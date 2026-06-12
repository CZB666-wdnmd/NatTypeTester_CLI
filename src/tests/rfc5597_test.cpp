#include "rfc5597_test.h"
#include "../utils/net_utils.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/errqueue.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#ifndef IPPROTO_DCCP
#define IPPROTO_DCCP 33
#endif

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace natcli {
namespace {

// ---- Constants ----

constexpr std::chrono::milliseconds kDefaultTimeout{3000};
constexpr std::chrono::milliseconds kDccpRecvTimeout{2000};
constexpr std::chrono::milliseconds kShortTimeout{1500};
constexpr std::uint32_t kServiceCodeA = 123456u;
constexpr std::uint32_t kServiceCodeB = 654321u;
constexpr std::uint32_t kServiceCodeSimOpen = 888888u;
constexpr std::uint32_t kServiceCodeFilterProbe = 999999u;
constexpr std::uint32_t kServiceCodeIcmpProbe = 777777u;
constexpr std::uint32_t kServiceCodeHairpin = 111111u;

// ---- Test wrapper helpers ----

std::string require_option(const std::map<std::string, std::string>& options, const std::string& name) {
    auto it = options.find(name);
    if (it == options.end()) {
        throw std::runtime_error("Missing required option: " + name);
    }
    return it->second;
}

std::optional<std::string> find_option(const std::map<std::string, std::string>& options, const std::string& name) {
    auto it = options.find(name);
    if (it == options.end()) {
        return std::nullopt;
    }
    return it->second;
}

Rfc5597TestType parse_rfc5597_test_type(const std::map<std::string, std::string>& options) {
    std::string value = find_option(options, "--test-type").value_or("all");
    if (value == "all") return Rfc5597TestType::All;
    if (value == "service-code") return Rfc5597TestType::ServiceCode;
    if (value == "mapping") return Rfc5597TestType::Mapping;
    if (value == "filtering") return Rfc5597TestType::Filtering;
    if (value == "simultaneous-open") return Rfc5597TestType::SimultaneousOpen;
    if (value == "unexpected-sync") return Rfc5597TestType::UnexpectedSync;
    if (value == "port-overloading") return Rfc5597TestType::PortOverloading;
    if (value == "hairpinning") return Rfc5597TestType::Hairpinning;
    if (value == "icmp") return Rfc5597TestType::Icmp;
    throw std::runtime_error("Unsupported RFC5597 test type: " + value);
}

std::optional<IpEndpoint> parse_local_bind(const std::map<std::string, std::string>& options, int family, int socket_type) {
    std::optional<std::string> local = find_option(options, "--local");
    if (!local.has_value()) return std::nullopt;
    auto [host, port] = split_host_port(*local, 0);
    return resolve_endpoint(host, port, socket_type, family);
}

void print_row(const std::string& key, const std::string& value) {
    std::cout << key << ": " << value << '\n';
}

std::string endpoint_or_dash(const std::optional<IpEndpoint>& endpoint) {
    return endpoint.has_value() ? to_string(*endpoint) : "-";
}

// ---- DCCP raw socket helpers ----

/// Compute IPv4 pseudo-header checksum for DCCP.
std::uint16_t compute_dccp_checksum(const iphdr& ip_header,
                                     const std::uint8_t* dccp_data,
                                     std::size_t dccp_len,
                                     std::uint8_t cscov) {
    // Build pseudo header
    struct PseudoHeader {
        std::uint32_t saddr;
        std::uint32_t daddr;
        std::uint8_t  zero;
        std::uint8_t  protocol;
        std::uint16_t length;
    } __attribute__((packed)) ph;

    std::memcpy(&ph.saddr, &ip_header.saddr, 4);
    std::memcpy(&ph.daddr, &ip_header.daddr, 4);
    ph.zero = 0;
    ph.protocol = IPPROTO_DCCP;
    ph.length = htons(static_cast<std::uint16_t>(dccp_len));

    std::uint32_t sum = 0;
    auto add_buf = [&](const void* buf, std::size_t len) {
        const std::uint8_t* ptr = static_cast<const std::uint8_t*>(buf);
        while (len >= 2) {
            sum += (static_cast<std::uint32_t>(ptr[0]) << 8) | ptr[1];
            ptr += 2;
            len -= 2;
        }
        if (len == 1) {
            sum += static_cast<std::uint32_t>(ptr[0]) << 8;
        }
    };

    add_buf(&ph, sizeof(ph));

    // Data Offset is stored as full byte (32-bit word count) — consistent with server impl
    std::uint8_t data_offset = dccp_data[4];
    if (data_offset == 0) data_offset = static_cast<std::uint8_t>(dccp_len / 4);

    std::size_t cov_len = dccp_len;
    if (cscov > 0) {
        std::size_t req_cov = static_cast<std::size_t>(data_offset) * 4 + static_cast<std::size_t>(cscov - 1) * 4;
        if (req_cov < dccp_len) cov_len = req_cov;
    }
    add_buf(dccp_data, cov_len);

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<std::uint16_t>(~sum);
}

/// Build and send a raw DCCP-Request packet.
/// Returns the actual local bind address/port used.
/// On error, throws std::runtime_error.
IpEndpoint send_dccp_request(const IpEndpoint& src_bind,
                              const IpEndpoint& dst,
                              std::uint32_t service_code,
                              std::uint8_t cscov,
                              const std::string& iface_name = "") {
    if (dst.family != AF_INET) {
        throw std::runtime_error("DCCP only supported for IPv4");
    }

    // Create raw socket with IP_HDRINCL so we craft the full IP header
    int raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_fd < 0) {
        throw system_error("socket(AF_INET, SOCK_RAW, IPPROTO_RAW) failed");
    }

    try {
        int enable = 1;
        if (setsockopt(raw_fd, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)) < 0) {
            throw system_error("setsockopt(IP_HDRINCL) failed");
        }

        // DCCP-Request: generic header (16 bytes) + Service Code (4 bytes) = 20 bytes
        constexpr std::size_t dccp_hdr_len = 20; // 16 + 4 service code
        constexpr std::size_t ip_hdr_len = sizeof(iphdr);
        std::vector<std::uint8_t> packet(ip_hdr_len + dccp_hdr_len, 0);

        // -- IP header --
        auto* ip = reinterpret_cast<iphdr*>(packet.data());
        ip->ihl = 5;
        ip->version = 4;
        ip->tos = 0;
        ip->tot_len = htons(static_cast<std::uint16_t>(packet.size()));
        ip->id = htons(0xDC00);
        ip->frag_off = 0;
        ip->ttl = 64;
        ip->protocol = IPPROTO_DCCP;
        ip->check = 0;

        // Determine source address: if bind addr is wildcard, use a local address
        IpEndpoint actual_src = src_bind;
        if (is_wildcard_endpoint_address(src_bind)) {
            // Connect to trigger local address resolution, but we use IP_HDRINCL
            // so we need to resolve the local interface address
            IpEndpoint resolved = infer_local_source_for_remote(dst);
            actual_src.address = resolved.address;
            actual_src.address_length = resolved.address_length;
            actual_src.family = resolved.family;
        }
        std::memcpy(&ip->saddr, actual_src.address.data(), 4);
        std::memcpy(&ip->daddr, dst.address.data(), 4);
        ip->check = calculate_checksum(ip, sizeof(iphdr));

        // -- DCCP header --
        std::uint8_t* dccp = packet.data() + ip_hdr_len;
        // Source port (2 bytes)
        std::uint16_t sport_n = htons(actual_src.port);
        std::memcpy(dccp, &sport_n, 2);
        // Destination port (2 bytes)
        std::uint16_t dport_n = htons(dst.port);
        std::memcpy(dccp + 2, &dport_n, 2);
        // Data Offset (upper 4 bits of byte 4): 20 bytes = 5 x 32-bit words
        dccp[4] = 5; // (20 / 4) = 5
        // CCVal (4 bits) + CsCov (4 bits) in byte 5
        dccp[5] = cscov & 0x0F;
        // Checksum (bytes 6-7): computed later
        dccp[6] = 0;
        dccp[7] = 0;
        // Res (3 bits) + Type (4 bits) + X (1 bit) in byte 8
        // Type 0 = DCCP-Request, X = 1 (extended sequence numbers)
        dccp[8] = (0 << 1) | 0x01; // Type=0, X=1
        // Reserved (bytes 9-11)
        dccp[9] = 0;
        dccp[10] = 0;
        dccp[11] = 0;
        // Sequence Number (bytes 12-15): set to 1 as initial value
        dccp[12] = 0;
        dccp[13] = 0;
        dccp[14] = 0;
        dccp[15] = 1; // Sequence number = 1

        // Service Code (bytes 16-19): network byte order
        std::uint32_t sc_n = htonl(service_code);
        std::memcpy(dccp + 16, &sc_n, 4);

        // Compute DCCP checksum
        std::uint16_t dccp_csum = compute_dccp_checksum(*ip, dccp, dccp_hdr_len, cscov);
        std::uint16_t csum_n = htons(dccp_csum);
        std::memcpy(dccp + 6, &csum_n, 2);

        // Send
        sockaddr_in dest{};
        dest.sin_family = AF_INET;
        std::memcpy(&dest.sin_addr, dst.address.data(), 4);

        ssize_t sent = sendto(raw_fd, packet.data(), packet.size(), 0,
                              reinterpret_cast<sockaddr*>(&dest), sizeof(dest));
        if (sent != static_cast<ssize_t>(packet.size())) {
            throw system_error("sendto DCCP-Request failed");
        }

        close(raw_fd);

        // Return the actual source endpoint we used
        return actual_src;
    } catch (...) {
        close(raw_fd);
        throw;
    }
}

/// Open a raw DCCP listener socket on a specific local port.
/// Returns the socket fd. Caller must close().
int open_dccp_listener(std::uint16_t local_port, std::chrono::milliseconds timeout) {
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_DCCP);
    if (fd < 0) {
        throw system_error("socket(AF_INET, SOCK_RAW, IPPROTO_DCCP) failed");
    }

    // Bind to the local port
    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(local_port);
    bind_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(fd, reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr)) < 0) {
        close(fd);
        throw system_error("bind DCCP listener failed");
    }

    // Set receive timeout
    timeval tv{};
    tv.tv_sec = static_cast<long>(timeout.count() / 1000);
    tv.tv_usec = static_cast<long>((timeout.count() % 1000) * 1000);
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    return fd;
}

/// Try to receive a DCCP packet on the given raw socket.
/// Returns true and fills peer info if a DCCP packet was received.
/// Returns false on timeout or non-DCCP packets.
struct DccpRecvResult {
    bool received{false};
    IpEndpoint peer;
    std::uint8_t type{0};
    std::uint8_t cscov{0};
    std::uint32_t service_code{0};
    bool valid_csum{false};
};

DccpRecvResult recv_dccp_packet(int raw_fd, std::chrono::milliseconds timeout) {
    DccpRecvResult result;

    pollfd pfd{raw_fd, POLLIN, 0};
    int rc = poll(&pfd, 1, static_cast<int>(timeout.count()));
    if (rc <= 0) {
        return result; // timeout or error
    }

    std::array<std::uint8_t, 4096> buffer{};
    sockaddr_storage peer{};
    socklen_t peer_len = sizeof(peer);

    ssize_t received = recvfrom(raw_fd, buffer.data(), buffer.size(), 0,
                                reinterpret_cast<sockaddr*>(&peer), &peer_len);
    if (received < static_cast<ssize_t>(sizeof(iphdr) + 12)) {
        return result;
    }

    const auto* ip_hdr = reinterpret_cast<const iphdr*>(buffer.data());
    if (ip_hdr->version != 4 || ip_hdr->protocol != IPPROTO_DCCP) {
        return result;
    }

    std::size_t ip_hdr_len = static_cast<std::size_t>(ip_hdr->ihl) * 4;
    if (received < static_cast<ssize_t>(ip_hdr_len + 12)) {
        return result;
    }

    const std::uint8_t* dccp = buffer.data() + ip_hdr_len;
    std::size_t dccp_len = static_cast<std::size_t>(received) - ip_hdr_len;

    std::uint16_t sport = (static_cast<std::uint16_t>(dccp[0]) << 8) | dccp[1];
    std::uint8_t type_val = (dccp[8] >> 1) & 0x0F;
    std::uint8_t cscov_val = dccp[5] & 0x0F;

    // Validate checksum
    std::uint32_t sum = 0;
    auto add_buf = [&](const void* buf, std::size_t len) {
        const std::uint8_t* ptr = static_cast<const std::uint8_t*>(buf);
        while (len >= 2) {
            sum += (static_cast<std::uint32_t>(ptr[0]) << 8) | ptr[1];
            ptr += 2;
            len -= 2;
        }
        if (len == 1) {
            sum += static_cast<std::uint32_t>(ptr[0]) << 8;
        }
    };

    // Pseudo-header
    struct PseudoHdr {
        std::uint32_t saddr, daddr;
        std::uint8_t zero, protocol;
        std::uint16_t length;
    } __attribute__((packed)) ph;
    std::memcpy(&ph.saddr, &ip_hdr->saddr, 4);
    std::memcpy(&ph.daddr, &ip_hdr->daddr, 4);
    ph.zero = 0;
    ph.protocol = IPPROTO_DCCP;
    ph.length = htons(static_cast<std::uint16_t>(dccp_len));
    add_buf(&ph, sizeof(ph));

    // Data Offset stored as full byte — consistent with server impl
    std::uint8_t data_offset_val = dccp[4];
    if (data_offset_val == 0) data_offset_val = static_cast<std::uint8_t>(dccp_len / 4);

    std::size_t cov_len = dccp_len;
    if (cscov_val > 0) {
        std::size_t req_cov = static_cast<std::size_t>(data_offset_val) * 4 + static_cast<std::size_t>(cscov_val - 1) * 4;
        if (req_cov < dccp_len) cov_len = req_cov;
    }
    add_buf(dccp, cov_len);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);

    result.valid_csum = (static_cast<std::uint16_t>(~sum) == 0);
    result.received = true;
    result.peer = from_sockaddr(reinterpret_cast<const sockaddr*>(&peer), peer_len);
    result.peer.port = sport;
    result.type = type_val;
    result.cscov = cscov_val;

    // Extract service code if type 0 (Request) with X=1 and enough data
    bool x_flag = (dccp[8] & 0x01) != 0;
    if (type_val == 0 && x_flag && dccp_len >= 20) {
        std::uint32_t sc;
        std::memcpy(&sc, dccp + 16, 4);
        result.service_code = ntohl(sc);
    }

    return result;
}

/// Try to receive an ICMP Port Unreachable message with embedded DCCP header.
/// Returns true if such an ICMP error was received on the socket.
bool recv_icmp_dccp_error(int raw_fd, std::chrono::milliseconds timeout) {
    pollfd pfd{raw_fd, POLLIN, 0};
    int rc = poll(&pfd, 1, static_cast<int>(timeout.count()));
    if (rc <= 0) {
        return false;
    }

    std::array<std::uint8_t, 4096> buffer{};
    sockaddr_storage peer{};
    socklen_t peer_len = sizeof(peer);

    ssize_t received = recvfrom(raw_fd, buffer.data(), buffer.size(), 0,
                                reinterpret_cast<sockaddr*>(&peer), &peer_len);
    if (received < static_cast<ssize_t>(sizeof(iphdr) + sizeof(icmphdr))) {
        return false;
    }

    const auto* ip_hdr = reinterpret_cast<const iphdr*>(buffer.data());
    if (ip_hdr->version != 4 || ip_hdr->protocol != IPPROTO_ICMP) {
        return false;
    }

    std::size_t ip_hdr_len = static_cast<std::size_t>(ip_hdr->ihl) * 4;
    const auto* icmp_hdr = reinterpret_cast<const icmphdr*>(buffer.data() + ip_hdr_len);

    if (icmp_hdr->type == ICMP_DEST_UNREACH && icmp_hdr->code == ICMP_PORT_UNREACH) {
        // Check if the embedded packet is DCCP
        const auto* inner_ip = reinterpret_cast<const iphdr*>(buffer.data() + ip_hdr_len + sizeof(icmphdr));
        if (inner_ip->version == 4 && inner_ip->protocol == IPPROTO_DCCP) {
            return true;
        }
    }

    return false;
}

// ---- TCP control channel helpers ----

/// Open a TCP connection to the server, send a command, and return the response line.
std::string send_server_command(const IpEndpoint& server,
                                std::string_view command,
                                std::chrono::milliseconds timeout = kDefaultTimeout) {
    int fd = socket(server.family, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        throw system_error("socket(TCP) failed");
    }
    try {
        set_reuse_options(fd);

        linger sl{1, 0};
        setsockopt(fd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));

        connect_with_timeout(fd, server, timeout);
        send_all(fd, command);
        std::string response = recv_line(fd, timeout);
        close(fd);
        return response;
    } catch (...) {
        close(fd);
        throw;
    }
}

/// Parse "DCCP_REQ <ip> <port> <cscov> <valid_csum>" response.
/// Returns {found, endpoint, cscov, valid_csum}.
struct DccpReqResponse {
    bool found{false};
    IpEndpoint endpoint{};
    std::uint8_t cscov{0};
    bool valid_csum{false};
};

DccpReqResponse parse_dccp_req_response(const std::string& line) {
    DccpReqResponse result;
    if (line.rfind("DCCP_REQ NONE", 0) == 0) {
        result.found = false;
        return result;
    }
    if (line.rfind("DCCP_REQ ", 0) != 0) {
        throw std::runtime_error("Unexpected DCCP_GET_REQ response: " + line);
    }
    std::istringstream stream(line);
    std::string cmd, ip_str;
    int port = 0, cscov_int = 0, valid_int = 0;
    if (!(stream >> cmd >> ip_str >> port >> cscov_int >> valid_int)) {
        throw std::runtime_error("Malformed DCCP_REQ response: " + line);
    }
    result.found = true;
    result.endpoint = parse_endpoint_literal(ip_str + ":" + std::to_string(port), 0);
    result.cscov = static_cast<std::uint8_t>(cscov_int);
    result.valid_csum = (valid_int != 0);
    return result;
}

/// Generate a random 32-bit service code.
std::uint32_t random_service_code() {
    static std::mt19937 rng(static_cast<unsigned>(
        std::chrono::steady_clock::now().time_since_epoch().count()));
    static std::uniform_int_distribution<std::uint32_t> dist(1, 0xFFFFFFFEu);
    return dist(rng);
}

// ====================================================================
// Test section implementations
// ====================================================================

// ---- Test 1: REQ-11/12/13 - Service Code & Checksum Integrity ----

DccpIntegrityResult run_dccp_integrity_test(const RequestOptions& options,
                                            const IpEndpoint& primary_server,
                                            const std::optional<IpEndpoint>& local_bind) {
    DccpIntegrityResult result;
    auto timeout = options.timeout;

    try {
        IpEndpoint bind_ep = local_bind.value_or(wildcard_endpoint(AF_INET, 0));

        // Send DCCP-Request with Service Code = 123456, CsCov = 5
        send_dccp_request(bind_ep, primary_server, kServiceCodeA, 5);
    } catch (const std::exception& e) {
        result.reachable = ProbeStatus::Fail;
        return result;
    }

    // Small delay for the server to process the packet
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // Query the server via TCP
    try {
        std::string response = send_server_command(
            primary_server,
            "DCCP_GET_REQ 123456\n",
            timeout);

        auto parsed = parse_dccp_req_response(response);
        if (!parsed.found) {
            // DCCP blocked or unsupported
            result.reachable = ProbeStatus::Fail;
            return result;
        }

        result.reachable = ProbeStatus::Pass;  // REQ-13: Service Code preserved
        result.mapped_endpoint = parsed.endpoint;
        result.returned_cscov = parsed.cscov;
        result.returned_valid_csum = parsed.valid_csum;

        // REQ-12: CsCov preserved (we sent 5)
        result.cscov_preserved = (parsed.cscov == 5) ? ProbeStatus::Pass : ProbeStatus::Fail;

        // REQ-11: Checksum valid
        result.checksum_valid = parsed.valid_csum ? ProbeStatus::Pass : ProbeStatus::Fail;

    } catch (const std::exception& e) {
        result.reachable = ProbeStatus::Inconclusive;
    }

    return result;
}

// ---- Test 2: Mapping Behavior (EIM / ADM) ----

DccpMappingFilteringResult run_dccp_mapping_filtering_test(const RequestOptions& options,
                                                           const IpEndpoint& primary_server,
                                                           const IpEndpoint& secondary_server,
                                                           const std::optional<IpEndpoint>& local_bind) {
    DccpMappingFilteringResult result;
    auto timeout = options.timeout;

    // Determine local port
    IpEndpoint bind_ep = local_bind.value_or(wildcard_endpoint(AF_INET, 0));

    // Step 1: Send to Primary with SC_A
    try {
        send_dccp_request(bind_ep, primary_server, kServiceCodeA, 0);
    } catch (const std::exception&) {
        result.mapping_behavior = MappingBehavior::Fail;
        return result;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // Query Primary mapping
    try {
        std::string r1 = send_server_command(primary_server, "DCCP_GET_REQ 123456\n", timeout);
        auto p1 = parse_dccp_req_response(r1);
        if (!p1.found) {
            result.mapping_behavior = MappingBehavior::Fail;
            return result;
        }
        result.primary_mapped = p1.endpoint;
    } catch (const std::exception&) {
        result.mapping_behavior = MappingBehavior::Fail;
        return result;
    }

    // Step 2: Send from SAME local port to Secondary with SC_B
    try {
        send_dccp_request(bind_ep, secondary_server, kServiceCodeB, 0);
    } catch (const std::exception&) {
        result.mapping_behavior = MappingBehavior::AddressAndPortDependent;
        return result;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // Query Secondary mapping
    try {
        std::string r2 = send_server_command(secondary_server, "DCCP_GET_REQ 654321\n", timeout);
        auto p2 = parse_dccp_req_response(r2);
        if (!p2.found) {
            result.mapping_behavior = MappingBehavior::AddressAndPortDependent;
            return result;
        }
        result.secondary_mapped = p2.endpoint;

        // Compare mapped ports
        if (result.primary_mapped.has_value() && result.secondary_mapped.has_value()) {
            if (result.primary_mapped->port == result.secondary_mapped->port &&
                same_address(*result.primary_mapped, *result.secondary_mapped)) {
                result.mapping_behavior = MappingBehavior::EndpointIndependent;
            } else {
                result.mapping_behavior = MappingBehavior::AddressAndPortDependent;
            }
        }
    } catch (const std::exception&) {
        result.mapping_behavior = MappingBehavior::Fail;
    }

    return result;
}

// ---- Test 3: Filtering Behavior (EIF / ADF) ----
// NOTE: This function also embeds filtering testing, see run_dccp_filtering_test

ProbeStatus run_dccp_filtering_test_inner(const RequestOptions& options,
                                          const IpEndpoint& secondary_server,
                                          const IpEndpoint& mapped_endpoint,
                                          std::uint16_t local_port,
                                          std::chrono::milliseconds timeout) {
    // Open a DCCP listener on the local port
    int listen_fd = -1;
    try {
        listen_fd = open_dccp_listener(local_port, kDccpRecvTimeout);
    } catch (const std::exception&) {
        return ProbeStatus::Inconclusive;
    }

    try {
        // Ask server to send DCCP-Request from Secondary to our mapped address
        std::string cmd = "DCCP_SEND S " + to_string(mapped_endpoint) +
                          " 0 999999 0\n";
        send_server_command(secondary_server, cmd, timeout);

        // Wait a bit for the packet to arrive
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        // Try to receive
        auto recv = recv_dccp_packet(listen_fd, kDccpRecvTimeout);
        close(listen_fd);

        if (recv.received && recv.service_code == kServiceCodeFilterProbe) {
            return ProbeStatus::Pass; // EIF: packet from any remote reaches us
        }
        return ProbeStatus::Fail; // ADF: only packets from known destination
    } catch (...) {
        if (listen_fd >= 0) close(listen_fd);
        return ProbeStatus::Inconclusive;
    }
}

// ---- Test 4: Simultaneous Open ----

DccpSimOpenResult run_dccp_simultaneous_open_test(const RequestOptions& options,
                                                  const IpEndpoint& primary_server,
                                                  const IpEndpoint& mapped_endpoint,
                                                  const std::optional<IpEndpoint>& local_bind) {
    DccpSimOpenResult result;
    auto timeout = options.timeout;

    IpEndpoint bind_ep = local_bind.value_or(wildcard_endpoint(AF_INET, 0));
    std::uint16_t local_port = bind_ep.port;

    // Open DCCP listener
    int listen_fd = -1;
    try {
        listen_fd = open_dccp_listener(local_port, kDccpRecvTimeout);
    } catch (const std::exception&) {
        result.received = ProbeStatus::Inconclusive;
        return result;
    }

    try {
        // First send our DCCP-Request to Primary
        send_dccp_request(bind_ep, primary_server, kServiceCodeA, 0);

        // Immediately (near-simultaneously) ask server to send DCCP-Request back
        std::string cmd = "DCCP_SEND P " + to_string(mapped_endpoint) +
                          " 0 888888 0\n";
        send_server_command(primary_server, cmd, timeout);

        // Try to receive
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        auto recv = recv_dccp_packet(listen_fd, kDccpRecvTimeout);
        close(listen_fd);

        if (recv.received && recv.service_code == kServiceCodeSimOpen) {
            result.received = ProbeStatus::Pass;
        } else {
            result.received = ProbeStatus::Fail;
        }
    } catch (...) {
        if (listen_fd >= 0) close(listen_fd);
        result.received = ProbeStatus::Inconclusive;
    }

    return result;
}

// ---- Test 5: Unexpected DCCP-Sync (Type 8) ----

DccpUnexpectedSyncResult run_dccp_unexpected_sync_test(const RequestOptions& options,
                                                       const IpEndpoint& primary_server,
                                                       const IpEndpoint& mapped_endpoint,
                                                       const std::optional<IpEndpoint>& local_bind) {
    DccpUnexpectedSyncResult result;
    auto timeout = options.timeout;

    IpEndpoint bind_ep = local_bind.value_or(wildcard_endpoint(AF_INET, 0));
    std::uint16_t local_port = bind_ep.port;

    // Open DCCP listener and ICMP-aware raw socket
    int listen_fd = -1;
    try {
        listen_fd = open_dccp_listener(local_port, kDccpRecvTimeout);
    } catch (const std::exception&) {
        result.blocked = ProbeStatus::Inconclusive;
        return result;
    }

    try {
        // Ask server to send isolated DCCP-Sync (Type 8, no Service Code)
        std::string cmd = "DCCP_SEND P " + to_string(mapped_endpoint) +
                          " 8 0 0\n";
        send_server_command(primary_server, cmd, timeout);

        // Try to receive DCCP-Sync
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        auto recv = recv_dccp_packet(listen_fd, kDccpRecvTimeout);

        if (recv.received && recv.type == 8) {
            // NAT forwarded the unexpected Sync packet — potentially dangerous
            result.blocked = ProbeStatus::Fail;
        } else {
            // NAT dropped/blocked the unexpected packet — safer behavior
            result.blocked = ProbeStatus::Pass;
        }
    } catch (...) {
        result.blocked = ProbeStatus::Inconclusive;
    }

    if (listen_fd >= 0) close(listen_fd);
    return result;
}

// ---- Test 6: Port Overloading ----

DccpPortOverloadingResult run_dccp_port_overloading_test(const RequestOptions& options,
                                                         const IpEndpoint& primary_server,
                                                         const std::optional<IpEndpoint>& local_bind) {
    DccpPortOverloadingResult result;
    auto timeout = options.timeout;

    // Use two distinct local ports
    IpEndpoint bind_x = local_bind.value_or(wildcard_endpoint(AF_INET, 0));
    IpEndpoint bind_y = bind_x;
    bind_y.port = 0; // different port, let OS assign

    std::uint32_t sc_x = random_service_code();
    std::uint32_t sc_y = random_service_code();

    // Send from port X
    try {
        send_dccp_request(bind_x, primary_server, sc_x, 0);
    } catch (const std::exception&) {
        result.overloaded = ProbeStatus::Inconclusive;
        return result;
    }

    // Send from port Y (different local port)
    try {
        send_dccp_request(bind_y, primary_server, sc_y, 0);
    } catch (const std::exception&) {
        result.overloaded = ProbeStatus::Inconclusive;
        return result;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // Query both
    try {
        std::string r1 = send_server_command(primary_server,
            "DCCP_GET_REQ " + std::to_string(sc_x) + "\n", timeout);
        auto p1 = parse_dccp_req_response(r1);
        if (p1.found) result.mapped_x = p1.endpoint;

        std::string r2 = send_server_command(primary_server,
            "DCCP_GET_REQ " + std::to_string(sc_y) + "\n", timeout);
        auto p2 = parse_dccp_req_response(r2);
        if (p2.found) result.mapped_y = p2.endpoint;

        if (result.mapped_x.has_value() && result.mapped_y.has_value()) {
            if (result.mapped_x->port == result.mapped_y->port) {
                // NAT assigned same public port → Port Overloading defect
                result.overloaded = ProbeStatus::Fail;
            } else {
                result.overloaded = ProbeStatus::Pass;
            }
        } else {
            result.overloaded = ProbeStatus::Inconclusive;
        }
    } catch (const std::exception&) {
        result.overloaded = ProbeStatus::Inconclusive;
    }

    return result;
}

// ---- Test 7: Hairpinning ----

DccpHairpinningResult run_dccp_hairpinning_test(const RequestOptions& options,
                                                const IpEndpoint& primary_server,
                                                const IpEndpoint& mapped_endpoint,
                                                const std::optional<IpEndpoint>& local_bind) {
    DccpHairpinningResult result;
    auto timeout = options.timeout;

    IpEndpoint bind_a = local_bind.value_or(wildcard_endpoint(AF_INET, 0));
    std::uint16_t port_a = bind_a.port;

    // Process A: open DCCP listener on PORT_A
    int listen_a = -1;
    try {
        listen_a = open_dccp_listener(port_a, kDccpRecvTimeout + std::chrono::milliseconds(500));
    } catch (const std::exception&) {
        result.hairpinning = ProbeStatus::Inconclusive;
        return result;
    }

    try {
        // Send DCCP-Request from port A to create mapping
        send_dccp_request(bind_a, primary_server, kServiceCodeA, 0);
    } catch (const std::exception&) {
        close(listen_a);
        result.hairpinning = ProbeStatus::Inconclusive;
        return result;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // Process B: from a DIFFERENT local port, send DCCP-Request to our own mapped address
    IpEndpoint bind_b = wildcard_endpoint(AF_INET, 0);
    try {
        send_dccp_request(bind_b, mapped_endpoint, kServiceCodeHairpin, 0);
    } catch (const std::exception&) {
        close(listen_a);
        result.hairpinning = ProbeStatus::Inconclusive;
        return result;
    }

    // Check if Process A received the hairpin packet
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    auto recv = recv_dccp_packet(listen_a, kDccpRecvTimeout);
    close(listen_a);

    if (recv.received) {
        result.hairpinning = ProbeStatus::Pass;
    } else {
        result.hairpinning = ProbeStatus::Fail;
    }

    return result;
}

// ---- Test 8: ICMP Error Forwarding & Mapping Persistence ----

DccpIcmpResult run_dccp_icmp_test(const RequestOptions& options,
                                  const IpEndpoint& primary_server,
                                  const IpEndpoint& mapped_endpoint,
                                  const std::optional<IpEndpoint>& local_bind) {
    DccpIcmpResult result;
    auto timeout = options.timeout;

    IpEndpoint bind_ep = local_bind.value_or(wildcard_endpoint(AF_INET, 0));
    std::uint16_t local_port = bind_ep.port;

    // Open raw socket for ICMP reception
    int icmp_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (icmp_fd < 0) {
        result.icmp_forwarded = ProbeStatus::Inconclusive;
        result.mapping_survives = ProbeStatus::Inconclusive;
        return result;
    }

    // Set timeout
    timeval tv{};
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(icmp_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    try {
        // Step 1: Ask server to send ICMP Port Unreachable with DCCP inner header
        send_server_command(primary_server, "DCCP_I\n", timeout);
    } catch (const std::exception&) {
        close(icmp_fd);
        result.icmp_forwarded = ProbeStatus::Inconclusive;
        result.mapping_survives = ProbeStatus::Inconclusive;
        return result;
    }

    // Step 2: Check if we received the ICMP Port Unreachable
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    bool icmp_received = recv_icmp_dccp_error(icmp_fd, kShortTimeout);

    if (icmp_received) {
        result.icmp_forwarded = ProbeStatus::Pass;
    } else {
        result.icmp_forwarded = ProbeStatus::Fail;
    }

    // Step 3: Verify mapping survived — ask server to send a normal DCCP-Request
    try {
        std::string cmd = "DCCP_SEND P " + to_string(mapped_endpoint) +
                          " 0 777777 0\n";
        send_server_command(primary_server, cmd, timeout);
    } catch (const std::exception&) {
        close(icmp_fd);
        result.mapping_survives = ProbeStatus::Inconclusive;
        return result;
    }

    // Try to receive on DCCP listener
    int dccp_fd = -1;
    try {
        dccp_fd = open_dccp_listener(local_port, kDccpRecvTimeout);
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        auto recv = recv_dccp_packet(dccp_fd, kDccpRecvTimeout);
        close(dccp_fd);
        close(icmp_fd);

        if (recv.received && recv.service_code == kServiceCodeIcmpProbe) {
            result.mapping_survives = ProbeStatus::Pass;
        } else {
            result.mapping_survives = ProbeStatus::Fail;
        }
    } catch (...) {
        if (dccp_fd >= 0) close(dccp_fd);
        close(icmp_fd);
        result.mapping_survives = ProbeStatus::Inconclusive;
    }

    return result;
}

// ---- Full test runner ----

Rfc5597Result run_rfc5597_tests(const RequestOptions& options,
                                const IpEndpoint& primary_server,
                                const IpEndpoint& secondary_server,
                                const std::optional<IpEndpoint>& local_bind) {
    Rfc5597Result full_result;

    // 1. Integrity test (REQ-11/12/13)
    full_result.integrity = run_dccp_integrity_test(options, primary_server, local_bind);

    if (full_result.integrity.reachable != ProbeStatus::Pass ||
        !full_result.integrity.mapped_endpoint.has_value()) {
        // Cannot proceed with remaining tests
        return full_result;
    }

    IpEndpoint mapped_ep = *full_result.integrity.mapped_endpoint;

    // 2. Mapping + Filtering test
    full_result.map_filter = run_dccp_mapping_filtering_test(
        options, primary_server, secondary_server, local_bind);

    // 3. Filtering test
    if (full_result.integrity.mapped_endpoint.has_value()) {
        IpEndpoint bind_ep = local_bind.value_or(wildcard_endpoint(AF_INET, 0));
        ProbeStatus fs = run_dccp_filtering_test_inner(
            options, secondary_server, mapped_ep, bind_ep.port, options.timeout);
        if (fs == ProbeStatus::Pass) {
            full_result.map_filter.filtering_behavior = FilteringBehavior::EndpointIndependent;
        } else if (fs == ProbeStatus::Fail) {
            full_result.map_filter.filtering_behavior = FilteringBehavior::AddressAndPortDependent;
        }
    }

    // 4. Simultaneous Open
    full_result.sim_open = run_dccp_simultaneous_open_test(
        options, primary_server, mapped_ep, local_bind);

    // 5. Unexpected Sync
    full_result.unexpected_sync = run_dccp_unexpected_sync_test(
        options, primary_server, mapped_ep, local_bind);

    // 6. Port Overloading
    full_result.port_overloading = run_dccp_port_overloading_test(
        options, primary_server, local_bind);

    // 7. Hairpinning
    full_result.hairpinning = run_dccp_hairpinning_test(
        options, primary_server, mapped_ep, local_bind);

    // 8. ICMP
    full_result.icmp = run_dccp_icmp_test(
        options, primary_server, mapped_ep, local_bind);

    return full_result;
}

// ====================================================================
// Test filtering — run only selected test types
// ====================================================================

} // namespace

// ---- Rfc5597Test class methods ----

void Rfc5597Test::parseArgs(const std::map<std::string, std::string>& options) {
    constexpr std::uint16_t default_port = 3478;
    json_mode_ = options.contains("--json");

    auto [stun_host, stun_port] = split_host_port(require_option(options, "--stun_server"), default_port);
    stun_server_ = resolve_endpoint(stun_host, stun_port, SOCK_DGRAM);
    options_.server_name = stun_host;

    std::optional<std::string> primary_opt = find_option(options, "--primary_server");
    std::optional<std::string> secondary_opt = find_option(options, "--secondary_server");

    if (primary_opt.has_value() && secondary_opt.has_value()) {
        auto [primary_host, primary_port] = split_host_port(*primary_opt, default_port);
        auto [secondary_host, secondary_port] = split_host_port(*secondary_opt, default_port);
        primary_server_ = resolve_endpoint(primary_host, primary_port, SOCK_DGRAM);
        secondary_server_ = resolve_endpoint(secondary_host, secondary_port, SOCK_DGRAM);
    }

    test_type_ = parse_rfc5597_test_type(options);

    local_bind_ = parse_local_bind(options, stun_server_.family, SOCK_DGRAM);
}

int Rfc5597Test::runTest() {
    const std::string& tt = (test_type_ == Rfc5597TestType::All) ? std::string("all") : std::string("");

    // Resolve servers if not manually specified
    if (primary_server_.port == 0) {
        auto cfg = discover_custom_servers(stun_server_, stun_server_.family);
        primary_server_ = cfg.primary;
        secondary_server_ = cfg.secondary;
    }

    Rfc5597Result result;

    bool run_all = (test_type_ == Rfc5597TestType::All);

    // Always run integrity first to get the mapped endpoint,
    // unless it was already set to ServiceCode-specific only
    bool need_mapping = run_all ||
        test_type_ == Rfc5597TestType::ServiceCode ||
        test_type_ == Rfc5597TestType::Mapping ||
        test_type_ == Rfc5597TestType::Filtering ||
        test_type_ == Rfc5597TestType::SimultaneousOpen ||
        test_type_ == Rfc5597TestType::UnexpectedSync ||
        test_type_ == Rfc5597TestType::PortOverloading ||
        test_type_ == Rfc5597TestType::Hairpinning ||
        test_type_ == Rfc5597TestType::Icmp;

    if (need_mapping) {
        result.integrity = run_dccp_integrity_test(options_, primary_server_, local_bind_);
        if (result.integrity.reachable != ProbeStatus::Pass && run_all) {
            // DCCP not reachable — cannot run remaining tests
        }
    }

    // Extract mapped endpoint for downstream tests
    IpEndpoint mapped_ep;
    bool have_mapped = false;
    if (result.integrity.mapped_endpoint.has_value()) {
        mapped_ep = *result.integrity.mapped_endpoint;
        have_mapped = true;
    }

    if (have_mapped) {

        if (mapped_ep.port != 0) {
            if (run_all || test_type_ == Rfc5597TestType::Mapping) {
                result.map_filter = run_dccp_mapping_filtering_test(
                    options_, primary_server_, secondary_server_, local_bind_);
            }

            if (run_all || test_type_ == Rfc5597TestType::Filtering) {
                IpEndpoint bind_ep = local_bind_.value_or(wildcard_endpoint(AF_INET, 0));
                ProbeStatus fs = run_dccp_filtering_test_inner(
                    options_, secondary_server_, mapped_ep, bind_ep.port, options_.timeout);
                if (fs == ProbeStatus::Pass) {
                    result.map_filter.filtering_behavior = FilteringBehavior::EndpointIndependent;
                } else if (fs == ProbeStatus::Fail) {
                    result.map_filter.filtering_behavior = FilteringBehavior::AddressAndPortDependent;
                }
            }

            if (run_all || test_type_ == Rfc5597TestType::SimultaneousOpen) {
                result.sim_open = run_dccp_simultaneous_open_test(
                    options_, primary_server_, mapped_ep, local_bind_);
            }

            if (run_all || test_type_ == Rfc5597TestType::UnexpectedSync) {
                result.unexpected_sync = run_dccp_unexpected_sync_test(
                    options_, primary_server_, mapped_ep, local_bind_);
            }

            if (run_all || test_type_ == Rfc5597TestType::PortOverloading) {
                result.port_overloading = run_dccp_port_overloading_test(
                    options_, primary_server_, local_bind_);
            }

            if (run_all || test_type_ == Rfc5597TestType::Hairpinning) {
                result.hairpinning = run_dccp_hairpinning_test(
                    options_, primary_server_, mapped_ep, local_bind_);
            }

            if (run_all || test_type_ == Rfc5597TestType::Icmp) {
                result.icmp = run_dccp_icmp_test(
                    options_, primary_server_, mapped_ep, local_bind_);
            }
        }
    }

    // ---- Output ----
    if (json_mode_) {
        std::ostringstream json;
        json << "{\"rfc\":\"rfc5597\"";
        auto add = [&](const std::string& key, const std::string& val) {
            json << "," << json_kv_result(key, val);
        };
        auto add_str = [&](const std::string& key, const std::string& val) {
            json << "," << json_kv_str(key, val);
        };

        // Integrity
        add("REQ13_ServiceCode_Preserved", to_string(result.integrity.reachable));
        add("REQ12_CsCov_Preserved", to_string(result.integrity.cscov_preserved));
        add("REQ11_Checksum_Valid", to_string(result.integrity.checksum_valid));
        if (result.integrity.mapped_endpoint.has_value()) {
            add_str("MappedEndpoint", to_string(*result.integrity.mapped_endpoint));
        }

        // Mapping
        add("MappingBehavior", to_string(result.map_filter.mapping_behavior));

        // Filtering
        add("FilteringBehavior", to_string(result.map_filter.filtering_behavior));

        // Simultaneous Open
        add("SimultaneousOpen", to_string(result.sim_open.received));

        // Unexpected Sync
        add("UnexpectedSync_Blocked", to_string(result.unexpected_sync.blocked));

        // Port Overloading
        add("PortOverloading", to_string(result.port_overloading.overloaded));

        // Hairpinning
        add("Hairpinning", to_string(result.hairpinning.hairpinning));

        // ICMP
        add("ICMP_Forwarded", to_string(result.icmp.icmp_forwarded));
        add("ICMP_MappingSurvives", to_string(result.icmp.mapping_survives));

        json << "}";
        std::cout << json.str() << std::endl;
    } else {
        // Text output
        std::cout << "=== RFC 5597 DCCP NAT Traversal Test Results ===\n";

        // REQ-11/12/13
        std::cout << "\n-- Service Code & Checksum Integrity (REQ-11/12/13) --\n";
        print_row("  REQ-13 ServiceCode Preserved", to_string(result.integrity.reachable));
        print_row("  REQ-12 CsCov Preserved", to_string(result.integrity.cscov_preserved));
        print_row("  REQ-11 Checksum Valid", to_string(result.integrity.checksum_valid));
        if (result.integrity.mapped_endpoint.has_value()) {
            print_row("  Mapped Endpoint", to_string(*result.integrity.mapped_endpoint));
        }

        // Mapping
        std::cout << "\n-- Mapping Behavior --\n";
        print_row("  Mapping Behavior", to_string(result.map_filter.mapping_behavior));
        if (result.map_filter.primary_mapped.has_value()) {
            print_row("  Primary Mapped", to_string(*result.map_filter.primary_mapped));
        }
        if (result.map_filter.secondary_mapped.has_value()) {
            print_row("  Secondary Mapped", to_string(*result.map_filter.secondary_mapped));
        }

        // Filtering
        std::cout << "\n-- Filtering Behavior --\n";
        print_row("  Filtering Behavior", to_string(result.map_filter.filtering_behavior));

        // Simultaneous Open
        std::cout << "\n-- Simultaneous Open --\n";
        print_row("  Simultaneous Open", to_string(result.sim_open.received));

        // Unexpected Sync
        std::cout << "\n-- Unexpected DCCP-Sync (Type 8) --\n";
        print_row("  Sync Blocked", to_string(result.unexpected_sync.blocked));

        // Port Overloading
        std::cout << "\n-- Port Overloading --\n";
        print_row("  Port Overloading", to_string(result.port_overloading.overloaded));
        if (result.port_overloading.mapped_x.has_value()) {
            print_row("  Mapped Port X", std::to_string(result.port_overloading.mapped_x->port));
        }
        if (result.port_overloading.mapped_y.has_value()) {
            print_row("  Mapped Port Y", std::to_string(result.port_overloading.mapped_y->port));
        }

        // Hairpinning
        std::cout << "\n-- Hairpinning --\n";
        print_row("  DCCP Hairpinning", to_string(result.hairpinning.hairpinning));

        // ICMP
        std::cout << "\n-- ICMP Error Handling --\n";
        print_row("  ICMP Forwarded", to_string(result.icmp.icmp_forwarded));
        print_row("  Mapping Survives ICMP", to_string(result.icmp.mapping_survives));

        std::cout << std::endl;
    }

    return 0;
}

void Rfc5597Test::printHelp() const {
    std::cout
        << "  rfc5597   DCCP NAT traversal tests (RFC 5597)\n"
        << "    Options:\n"
        << "      --stun_server <host:port>    STUN server address (required)\n"
        << "      --primary_server <host:port> Primary server address (optional)\n"
        << "      --secondary_server <host:port> Secondary server address (optional)\n"
        << "      --test-type <type>           Test type: all, service-code, mapping,\n"
        << "                                   filtering, simultaneous-open, unexpected-sync,\n"
        << "                                   port-overloading, hairpinning, icmp\n"
        << "      --local <host:port>          Local bind address (optional)\n"
        << "      --json                       Output results in JSON format\n"
        << "\n"
        << "    Description:\n"
        << "      Tests DCCP (Datagram Congestion Control Protocol) NAT traversal\n"
        << "      behavior per RFC 5597, including Service Code preservation,\n"
        << "      checksum validity, mapping/filtering classification,\n"
        << "      simultaneous open, hairpinning, and ICMP error handling.\n"
        << "\n"
        << "    Test sections:\n"
        << "      REQ-11: DCCP checksum remains valid after NAT traversal\n"
        << "      REQ-12: CsCov (checksum coverage) value is not modified\n"
        << "      REQ-13: Service Code (32-bit transaction ID) is preserved\n"
        << "      Mapping: Endpoint-Independent vs Address-Dependent mapping\n"
        << "      Filtering: Endpoint-Independent vs Address-Dependent filtering\n"
        << "      Simultaneous Open: Support for DCCP simultaneous open\n"
        << "      Unexpected Sync: Behavior for orphan DCCP-Sync packets\n"
        << "      Port Overloading: Whether NAT shares mapped ports across sockets\n"
        << "      Hairpinning: Loopback routing of DCCP to own mapped address\n"
        << "      ICMP: ICMP Port Unreachable forwarding + mapping persistence\n"
        << std::endl;
}

} // namespace natcli
