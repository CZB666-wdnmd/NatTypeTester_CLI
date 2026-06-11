#include "rfc5508_test.h"
#include "../utils/net_utils.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iostream>
#include <optional>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace natcli {
namespace {

// ---- Test wrapper helpers ----

std::string require_option(const std::map<std::string, std::string>& options, const std::string& name) {
    auto it = options.find(name);
    if (it == options.end()) throw std::runtime_error("Missing required option: " + name);
    return it->second;
}

std::optional<std::string> find_option(const std::map<std::string, std::string>& options, const std::string& name) {
    auto it = options.find(name);
    if (it == options.end()) return std::nullopt;
    return it->second;
}

std::optional<IpEndpoint> parse_local_bind(const std::map<std::string, std::string>& options, int family, int socket_type) {
    std::optional<std::string> local = find_option(options, "--local");
    if (!local.has_value()) return std::nullopt;
    auto [host, port] = split_host_port(*local, 0);
    return resolve_endpoint(host, port, socket_type, family);
}

std::optional<IpEndpoint> request_udp_mapping(int socket_fd, const IpEndpoint& server, std::chrono::milliseconds timeout) {
    constexpr std::string_view kUdpMappingRequest = "M\n";
    SocketAddress remote = to_sockaddr(server);
    ssize_t sent = sendto(socket_fd, kUdpMappingRequest.data(), kUdpMappingRequest.size(), 0,
                          reinterpret_cast<sockaddr*>(&remote.storage), remote.length);
    if (sent <= 0) {
        return std::nullopt;
    }
    if (!wait_for_readable(socket_fd, timeout)) {
        return std::nullopt;
    }
    std::array<char, 256> buffer{};
    ssize_t received = recv(socket_fd, buffer.data(), buffer.size() - 1, 0);
    if (received <= 0) {
        return std::nullopt;
    }
    buffer[static_cast<std::size_t>(received)] = '\0';
    return parse_endpoint_line(std::string(buffer.data()), server.family);
}

void print_row(const std::string& key, const std::string& value) {
    std::cout << key << ": " << value << '\n';
}

std::string endpoint_or_dash(const std::optional<IpEndpoint>& endpoint) {
    return endpoint.has_value() ? to_string(*endpoint) : "-";
}

// ---- RFC5508 business logic structs and enums ----

struct MappingProbeSample {
    std::string token;
    std::optional<IpEndpoint> public_endpoint;
    std::optional<std::uint16_t> public_query;
    bool path_ok{false};
};

enum class IcmpErrorVariant : std::uint8_t {
    BadOuterChecksum = 1,
    BadInnerIpChecksum = 2,
    BadUdpChecksum = 3,
    Valid = 4,
};

enum class IcmpInnerProtocol : std::uint8_t {
    Udp = 1,
    Icmp = 2,
};

struct ReceivedIcmpError {
    std::uint16_t marker{0};
    IpEndpoint source;
};

struct IcmpPacket {
    IpEndpoint source;
    std::uint8_t type{0};
    std::uint8_t code{0};
    std::uint16_t identifier{0};
    std::uint16_t sequence{0};
    std::string payload;
};

// ---- RFC5508 ICMP packet builders ----

std::vector<std::uint8_t> build_icmp_echo(std::uint8_t type,
                                          std::uint16_t identifier,
                                          std::uint16_t sequence,
                                          std::string_view payload) {
    std::vector<std::uint8_t> packet(sizeof(icmphdr) + payload.size(), 0);
    auto* icmp = reinterpret_cast<icmphdr*>(packet.data());
    icmp->type = type;
    icmp->code = 0;
    icmp->un.echo.id = htons(identifier);
    icmp->un.echo.sequence = htons(sequence);
    if (!payload.empty()) {
        std::memcpy(packet.data() + sizeof(icmphdr), payload.data(), payload.size());
    }
    icmp->checksum = 0;
    icmp->checksum = calculate_checksum(packet.data(), packet.size());
    return packet;
}

bool send_icmp_echo(int raw_fd,
                    const IpEndpoint& target,
                    std::uint8_t type,
                    std::uint16_t identifier,
                    std::uint16_t sequence,
                    std::string_view payload) {
    std::vector<std::uint8_t> packet = build_icmp_echo(type, identifier, sequence, payload);
    SocketAddress destination = to_sockaddr(target);
    const ssize_t sent = sendto(raw_fd,
                                packet.data(),
                                packet.size(),
                                0,
                                reinterpret_cast<sockaddr*>(&destination.storage),
                                destination.length);
    return sent == static_cast<ssize_t>(packet.size());
}

bool send_icmp_echo_raw_send(int raw_send_fd,
                             const IpEndpoint& target,
                             const IpEndpoint& local_source,
                             std::uint8_t type,
                             std::uint16_t identifier,
                             std::uint16_t sequence,
                             std::string_view payload) {
    // Build ICMP body (same as send_icmp_echo)
    std::vector<std::uint8_t> icmp_body = build_icmp_echo(type, identifier, sequence, payload);

    // Build full IP packet with manual IP header (via raw_send_fd + IP_HDRINCL)
    std::vector<std::uint8_t> packet(sizeof(iphdr) + icmp_body.size(), 0);
    auto* ip = reinterpret_cast<iphdr*>(packet.data());
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = htons(static_cast<std::uint16_t>(packet.size()));
    ip->id = 0;
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_ICMP;
    std::memcpy(&ip->saddr, local_source.address.data(), 4);
    std::memcpy(&ip->daddr, target.address.data(), 4);
    ip->check = 0;
    ip->check = calculate_checksum(ip, sizeof(iphdr));

    // Copy ICMP body after IP header
    std::memcpy(packet.data() + sizeof(iphdr), icmp_body.data(), icmp_body.size());

    SocketAddress remote = to_sockaddr(target);
    const ssize_t sent = sendto(raw_send_fd,
                                packet.data(),
                                packet.size(),
                                0,
                                reinterpret_cast<sockaddr*>(&remote.storage),
                                remote.length);
    return sent == static_cast<ssize_t>(packet.size());
}

bool send_ipv4_icmp_error_packet(int raw_send_fd,
                                 const IpEndpoint& target,
                                 const IpEndpoint& outer_source,
                                 const IpEndpoint& inner_source,
                                 const IpEndpoint& inner_destination,
                                 std::uint16_t inner_source_port,
                                 std::uint16_t inner_destination_port,
                                 std::uint16_t marker,
                                 IcmpErrorVariant variant,
                                 IcmpInnerProtocol inner_protocol) {
    if (target.family != AF_INET || outer_source.family != AF_INET || inner_source.family != AF_INET ||
        inner_destination.family != AF_INET) {
        return false;
    }

    const std::size_t inner_transport_size =
        inner_protocol == IcmpInnerProtocol::Udp ? sizeof(udphdr) : sizeof(icmphdr);
    std::vector<std::uint8_t> packet(sizeof(iphdr) + sizeof(icmphdr) + sizeof(iphdr) + inner_transport_size, 0);

    auto* outer_ip = reinterpret_cast<iphdr*>(packet.data());
    outer_ip->ihl = 5;
    outer_ip->version = 4;
    outer_ip->tos = 0;
    outer_ip->tot_len = htons(packet.size());
    outer_ip->id = 0;
    outer_ip->frag_off = 0;
    outer_ip->ttl = 64;
    outer_ip->protocol = IPPROTO_ICMP;
    std::memcpy(&outer_ip->saddr, outer_source.address.data(), 4);
    std::memcpy(&outer_ip->daddr, target.address.data(), 4);
    outer_ip->check = 0;
    outer_ip->check = calculate_checksum(outer_ip, sizeof(iphdr));

    auto* icmp = reinterpret_cast<icmphdr*>(packet.data() + sizeof(iphdr));
    icmp->type = ICMP_DEST_UNREACH;
    icmp->code = ICMP_PORT_UNREACH;
    icmp->checksum = 0;

    auto* inner_ip = reinterpret_cast<iphdr*>(packet.data() + sizeof(iphdr) + sizeof(icmphdr));
    inner_ip->ihl = 5;
    inner_ip->version = 4;
    inner_ip->tos = 0;
    inner_ip->tot_len = htons(sizeof(iphdr) + inner_transport_size);
    inner_ip->id = htons(marker);
    inner_ip->frag_off = 0;
    inner_ip->ttl = 64;
    inner_ip->protocol = inner_protocol == IcmpInnerProtocol::Udp ? IPPROTO_UDP : IPPROTO_ICMP;
    std::memcpy(&inner_ip->saddr, inner_source.address.data(), 4);
    std::memcpy(&inner_ip->daddr, inner_destination.address.data(), 4);
    inner_ip->check = 0;
    inner_ip->check = calculate_checksum(inner_ip, sizeof(iphdr));

    if (inner_protocol == IcmpInnerProtocol::Udp) {
        auto* inner_udp = reinterpret_cast<udphdr*>(packet.data() + sizeof(iphdr) + sizeof(icmphdr) + sizeof(iphdr));
        inner_udp->source = htons(inner_source_port);
        inner_udp->dest = htons(inner_destination_port);
        inner_udp->len = htons(sizeof(udphdr));
        inner_udp->check = 0;
        inner_udp->check = calculate_udp_checksum_ipv4(*inner_ip, *inner_udp, nullptr, 0);
        if (variant == IcmpErrorVariant::BadUdpChecksum) {
            inner_udp->check ^= htons(0x00FF);
        }
    } else {
        auto* inner_icmp = reinterpret_cast<icmphdr*>(packet.data() + sizeof(iphdr) + sizeof(icmphdr) + sizeof(iphdr));
        inner_icmp->type = ICMP_ECHO;
        inner_icmp->code = 0;
        inner_icmp->un.echo.id = htons(inner_source_port);
        inner_icmp->un.echo.sequence = htons(inner_destination_port);
        inner_icmp->checksum = 0;
        inner_icmp->checksum = calculate_checksum(inner_icmp, sizeof(icmphdr));
    }

    if (variant == IcmpErrorVariant::BadInnerIpChecksum) {
        inner_ip->check ^= htons(0x00FF);
    }

    icmp->checksum = calculate_checksum(icmp, packet.size() - sizeof(iphdr));
    if (variant == IcmpErrorVariant::BadOuterChecksum) {
        icmp->checksum ^= htons(0x00FF);
    }

    SocketAddress remote = to_sockaddr(target);
    const ssize_t sent = sendto(raw_send_fd,
                                packet.data(),
                                packet.size(),
                                0,
                                reinterpret_cast<sockaddr*>(&remote.storage),
                                remote.length);
    if (sent != static_cast<ssize_t>(packet.size())) {
        std::cerr << "\n[Debug] sendto failed: " << std::strerror(errno) 
                  << " (sent " << sent << " of " << packet.size() << ")\n";
        return false;
    }
    return true;
}

// ---- RFC5508 ICMP receive helpers ----

std::vector<ReceivedIcmpError> receive_icmp_errors_by_markers(int raw_fd,
                                                              const std::unordered_set<std::uint16_t>& markers,
                                                              std::chrono::milliseconds timeout) {
    std::vector<ReceivedIcmpError> received_markers;
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
        if (!wait_for_readable(raw_fd, remaining)) {
            break;
        }

        std::array<std::uint8_t, 4096> buffer{};
        sockaddr_storage peer{};
        socklen_t peer_length = sizeof(peer);
        const ssize_t received =
            recvfrom(raw_fd, buffer.data(), buffer.size(), 0, reinterpret_cast<sockaddr*>(&peer), &peer_length);
        if (received <= static_cast<ssize_t>(sizeof(iphdr) + sizeof(icmphdr))) {
            continue;
        }
        const auto* ip = reinterpret_cast<const iphdr*>(buffer.data());
        if (ip->version != 4 || ip->protocol != IPPROTO_ICMP) {
            continue;
        }
        const std::size_t ip_header_size = static_cast<std::size_t>(ip->ihl) * 4;
        if (received <= static_cast<ssize_t>(ip_header_size + sizeof(icmphdr) + sizeof(iphdr) + sizeof(udphdr))) {
            continue;
        }
        const auto* icmp = reinterpret_cast<const icmphdr*>(buffer.data() + ip_header_size);
        if (icmp->type != ICMP_DEST_UNREACH || icmp->code != ICMP_PORT_UNREACH) {
            continue;
        }
        const auto* inner_ip = reinterpret_cast<const iphdr*>(buffer.data() + ip_header_size + sizeof(icmphdr));
        if (inner_ip->version != 4) {
            continue;
        }
        const std::uint16_t marker = ntohs(inner_ip->id);
        if (!markers.contains(marker)) {
            continue;
        }
        ReceivedIcmpError observed;
        observed.marker = marker;
        observed.source = from_sockaddr(reinterpret_cast<sockaddr*>(&peer), peer_length);
        received_markers.push_back(observed);
    }
    return received_markers;
}

std::optional<IcmpPacket> receive_icmp_packet(int raw_fd, std::chrono::milliseconds timeout) {
    if (!wait_for_readable(raw_fd, timeout)) {
        return std::nullopt;
    }
    std::array<std::uint8_t, 4096> buffer{};
    sockaddr_storage peer{};
    socklen_t peer_length = sizeof(peer);
    const ssize_t received =
        recvfrom(raw_fd, buffer.data(), buffer.size(), 0, reinterpret_cast<sockaddr*>(&peer), &peer_length);
    if (received <= static_cast<ssize_t>(sizeof(iphdr) + sizeof(icmphdr))) {
        return std::nullopt;
    }

    const auto* ip = reinterpret_cast<const iphdr*>(buffer.data());
    if (ip->version != 4 || ip->protocol != IPPROTO_ICMP) {
        return std::nullopt;
    }
    const std::size_t ip_header_size = static_cast<std::size_t>(ip->ihl) * 4;
    if (received <= static_cast<ssize_t>(ip_header_size + sizeof(icmphdr))) {
        return std::nullopt;
    }

    const auto* icmp = reinterpret_cast<const icmphdr*>(buffer.data() + ip_header_size);
    const char* payload_data = reinterpret_cast<const char*>(buffer.data() + ip_header_size + sizeof(icmphdr));
    const std::size_t payload_size = static_cast<std::size_t>(received) - ip_header_size - sizeof(icmphdr);

    IcmpPacket packet;
    packet.source = from_sockaddr(reinterpret_cast<sockaddr*>(&peer), peer_length);
    packet.type = icmp->type;
    packet.code = icmp->code;
    packet.identifier = ntohs(icmp->un.echo.id);
    packet.sequence = ntohs(icmp->un.echo.sequence);
    packet.payload.assign(payload_data, payload_size);
    return packet;
}

void try_disable_kernel_icmp_echo_auto_reply() {
    std::ofstream sysctl_file("/proc/sys/net/ipv4/icmp_echo_ignore_all");
    if (sysctl_file.good()) {
        sysctl_file << "1\n";
    }
}

// ---- RFC5508 control protocol helpers ----

std::string request_control_command(const IpEndpoint& control_local,
                                    const IpEndpoint& server,
                                    std::string_view command,
                                    std::chrono::milliseconds timeout) {
    int control = socket(server.family, SOCK_STREAM, IPPROTO_TCP);
    if (control < 0) {
        throw system_error("socket failed");
    }
    try {
        set_reuse_options(control);
        SocketAddress local_address = to_sockaddr(control_local);
        if (bind(control, reinterpret_cast<sockaddr*>(&local_address.storage), local_address.length) != 0) {
            throw system_error("bind failed");
        }

        SocketAddress remote = to_sockaddr(server);
        const int flags = fcntl(control, F_GETFL, 0);
        if (flags < 0 || fcntl(control, F_SETFL, flags | O_NONBLOCK) != 0) {
            throw system_error("fcntl failed");
        }
        int rc = connect(control, reinterpret_cast<sockaddr*>(&remote.storage), remote.length);
        if (rc != 0 && errno != EINPROGRESS) {
            throw system_error("connect failed");
        }
        pollfd out_descriptor{control, POLLOUT, 0};
        rc = poll(&out_descriptor, 1, static_cast<int>(timeout.count()));
        if (rc <= 0) {
            throw std::runtime_error("connect timed out");
        }
        int error = 0;
        socklen_t error_length = sizeof(error);
        if (getsockopt(control, SOL_SOCKET, SO_ERROR, &error, &error_length) != 0 || error != 0) {
            if (error != 0) {
                errno = error;
            }
            throw system_error("connect failed");
        }
        (void)fcntl(control, F_SETFL, flags);

        send_all(control, command);
        std::string line = recv_line(control, timeout);
        close(control);
        return line;
    } catch (...) {
        close(control);
        throw;
    }
}

std::string make_token(std::mt19937& generator) {
    std::uniform_int_distribution<std::uint32_t> distribution(0, 0xFFFFFFFFu);
    std::ostringstream stream;
    stream << "T" << std::hex << distribution(generator) << distribution(generator);
    return stream.str();
}

// ---- RFC5508 probe implementations ----

MappingProbeSample run_mapping_probe(int raw_fd,
                                     int raw_send_fd,
                                     const IpEndpoint& target_server,
                                     const IpEndpoint& control_server,
                                     const IpEndpoint& control_local,
                                     std::uint16_t local_query,
                                     std::uint16_t remote_query,
                                     std::chrono::milliseconds timeout,
                                     std::mt19937& generator) {
    MappingProbeSample sample;
    sample.token = make_token(generator);
    const std::string payload = "RFC5508-M:" + sample.token;

    // Use raw_send_fd (IP_HDRINCL) to send ICMP Echo via hand-crafted IP header,
    // avoiding kernel IP header construction that may fail under NOTRACK rules.
    if (!send_icmp_echo_raw_send(raw_send_fd, target_server, control_local, ICMP_ECHO, local_query, remote_query, payload)) {
        return sample;
    }

    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
        std::optional<IcmpPacket> packet = receive_icmp_packet(raw_fd, remaining);
        if (!packet.has_value()) {
            break;
        }
        if (packet->type != ICMP_ECHOREPLY || packet->payload != payload || !same_address(packet->source, target_server)) {
            continue;
        }
        sample.path_ok = true;
        break;
    }
    if (!sample.path_ok) {
        return sample;
    }

    const std::string response =
        request_control_command(control_local, control_server, "IM " + sample.token + "\n", timeout);
    std::istringstream stream(response);
    std::string prefix;
    std::string host;
    std::uint16_t mapped_query = 0;
    if (!(stream >> prefix >> host >> mapped_query) || prefix != "M") {
        return sample;
    }

    sample.public_endpoint = resolve_endpoint(host, 0, SOCK_STREAM, AF_INET);
    sample.public_endpoint->port = mapped_query;
    sample.public_query = mapped_query;
    return sample;
}

bool run_filter_probe(int raw_fd,
                      const IpEndpoint& control_local,
                      const IpEndpoint& control_server,
                      std::string_view role,
                      const std::string& token,
                      std::uint16_t probe_query,
                      const IpEndpoint& expected_source,
                      std::chrono::milliseconds timeout) {
    const std::string command = "IF " + std::string(role) + " " + token + " " + std::to_string(probe_query) + "\n";
    const std::string sent = request_control_command(control_local, control_server, command, timeout);
    if (!parse_flag_response(sent, 'F')) {
        return false;
    }

    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
        std::optional<IcmpPacket> packet = receive_icmp_packet(raw_fd, remaining);
        if (!packet.has_value()) {
            return false;
        }
        if (packet->type != ICMP_ECHO || !same_address(packet->source, expected_source)) {
            continue;
        }
        const std::string expected_payload = "RFC5508-F:" + token + ":" + std::to_string(probe_query);
        if (packet->payload == expected_payload) {
            return true;
        }
    }
    return false;
}

bool was_marker_forwarded_from_source(const std::vector<ReceivedIcmpError>& observed,
                                      std::uint16_t marker,
                                      const IpEndpoint& expected_source) {
    for (const ReceivedIcmpError& item : observed) {
        if (item.marker == marker && same_address(item.source, expected_source)) {
            return true;
        }
    }
    return false;
}

ProbeStatus status_from_expectations(bool invalid_outer_forwarded,
                                     bool invalid_inner_forwarded,
                                     bool bad_udp_forwarded) {
    return (!invalid_outer_forwarded && !invalid_inner_forwarded && bad_udp_forwarded)
               ? ProbeStatus::Pass
               : ProbeStatus::Fail;
}

ProbeStatus run_client_outbound_icmp_error_probe(int raw_send_fd,
                                                 const IpEndpoint& control_local,
                                                 const IpEndpoint& primary_server,
                                                 const IpEndpoint& local_udp_endpoint,
                                                 const std::optional<IpEndpoint>& udp_mapped_endpoint,
                                                 std::uint16_t marker,
                                                 std::chrono::milliseconds timeout) {
    if (!udp_mapped_endpoint.has_value()) {
        return ProbeStatus::Inconclusive;
    }
    const std::string reset = request_control_command(control_local, primary_server, "IRR\n", timeout);
    if (!parse_flag_response(reset, 'R')) {
        return ProbeStatus::Inconclusive;
    }
    const bool sent = send_ipv4_icmp_error_packet(raw_send_fd,
                                                  primary_server,
                                                  control_local,
                                                  primary_server,
                                                  local_udp_endpoint,
                                                  primary_server.port,
                                                  local_udp_endpoint.port,
                                                  marker,
                                                  IcmpErrorVariant::Valid,
                                                  IcmpInnerProtocol::Udp);
    if (!sent) {
        return ProbeStatus::Fail;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(120));
    const std::string observed =
        request_control_command(control_local, primary_server, "IR " + std::to_string(marker) + "\n", timeout);
    return parse_flag_response(observed, 'R') ? ProbeStatus::Pass : ProbeStatus::Fail;
}

void run_icmp_payload_validation_probe(Rfc5508Result& result,
                                       int raw_fd,
                                       int raw_send_fd,
                                       const IpEndpoint& control_local,
                                       const IpEndpoint& primary_server,
                                       const IpEndpoint& local_udp_endpoint,
                                       const std::optional<IpEndpoint>& udp_mapped_endpoint,
                                       std::uint16_t marker_base,
                                       std::chrono::milliseconds timeout) {
    if (!udp_mapped_endpoint.has_value()) {
        result.icmp_error_payload_validation = ProbeStatus::Inconclusive;
        return;
    }

    const std::uint16_t srv_outer_marker = static_cast<std::uint16_t>(marker_base + 1);
    const std::uint16_t srv_inner_marker = static_cast<std::uint16_t>(marker_base + 2);
    const std::uint16_t srv_udp_marker = static_cast<std::uint16_t>(marker_base + 3);
    const std::uint16_t cli_outer_marker = static_cast<std::uint16_t>(marker_base + 4);
    const std::uint16_t cli_inner_marker = static_cast<std::uint16_t>(marker_base + 5);
    const std::uint16_t cli_udp_marker = static_cast<std::uint16_t>(marker_base + 6);

    const std::string reset = request_control_command(control_local, primary_server, "IRR\n", timeout);
    if (!parse_flag_response(reset, 'R')) {
        result.icmp_error_payload_validation = ProbeStatus::Inconclusive;
        return;
    }

    const std::string inject_command = "IE " + to_string(*udp_mapped_endpoint) + " " + std::to_string(srv_outer_marker) +
                                       " " + std::to_string(srv_inner_marker) + " " + std::to_string(srv_udp_marker) + "\n";
    const std::string inject_response = request_control_command(control_local, primary_server, inject_command, timeout);
    if (!parse_flag_response(inject_response, 'E')) {
        result.icmp_error_payload_validation = ProbeStatus::Fail;
        return;
    }

    std::unordered_set<std::uint16_t> server_markers{srv_outer_marker, srv_inner_marker, srv_udp_marker};
    const std::vector<ReceivedIcmpError> inbound_observed =
        receive_icmp_errors_by_markers(raw_fd, server_markers, timeout);
    result.malformed_server_outer_checksum_forwarded =
        was_marker_forwarded_from_source(inbound_observed, srv_outer_marker, primary_server);
    result.malformed_server_inner_ip_checksum_forwarded =
        was_marker_forwarded_from_source(inbound_observed, srv_inner_marker, primary_server);
    result.malformed_server_bad_udp_checksum_forwarded =
        was_marker_forwarded_from_source(inbound_observed, srv_udp_marker, primary_server);

    const bool cli_outer_sent = send_ipv4_icmp_error_packet(raw_send_fd,
                                                            primary_server,
                                                            control_local,
                                                            primary_server,
                                                            local_udp_endpoint,
                                                            primary_server.port,
                                                            local_udp_endpoint.port,
                                                            cli_outer_marker,
                                                            IcmpErrorVariant::BadOuterChecksum,
                                                            IcmpInnerProtocol::Udp);
    const bool cli_inner_sent = send_ipv4_icmp_error_packet(raw_send_fd,
                                                            primary_server,
                                                            control_local,
                                                            primary_server,
                                                            local_udp_endpoint,
                                                            primary_server.port,
                                                            local_udp_endpoint.port,
                                                            cli_inner_marker,
                                                            IcmpErrorVariant::BadInnerIpChecksum,
                                                            IcmpInnerProtocol::Udp);
    const bool cli_udp_sent = send_ipv4_icmp_error_packet(raw_send_fd,
                                                          primary_server,
                                                          control_local,
                                                          primary_server,
                                                          local_udp_endpoint,
                                                          primary_server.port,
                                                          local_udp_endpoint.port,
                                                          cli_udp_marker,
                                                          IcmpErrorVariant::BadUdpChecksum,
                                                          IcmpInnerProtocol::Udp);

    std::this_thread::sleep_for(std::chrono::milliseconds(120));
    const std::string cli_outer_seen =
        request_control_command(control_local, primary_server, "IR " + std::to_string(cli_outer_marker) + "\n", timeout);
    const std::string cli_inner_seen =
        request_control_command(control_local, primary_server, "IR " + std::to_string(cli_inner_marker) + "\n", timeout);
    const std::string cli_udp_seen =
        request_control_command(control_local, primary_server, "IR " + std::to_string(cli_udp_marker) + "\n", timeout);
    result.malformed_client_outer_checksum_forwarded =
        cli_outer_sent ? parse_flag_response(cli_outer_seen, 'R') : false;
    result.malformed_client_inner_ip_checksum_forwarded =
        cli_inner_sent ? parse_flag_response(cli_inner_seen, 'R') : false;
    result.malformed_client_bad_udp_checksum_forwarded =
        cli_udp_sent ? parse_flag_response(cli_udp_seen, 'R') : false;

    const ProbeStatus server_direction_status = status_from_expectations(
        result.malformed_server_outer_checksum_forwarded,
        result.malformed_server_inner_ip_checksum_forwarded,
        result.malformed_server_bad_udp_checksum_forwarded);
    const ProbeStatus client_direction_status = status_from_expectations(
        result.malformed_client_outer_checksum_forwarded,
        result.malformed_client_inner_ip_checksum_forwarded,
        result.malformed_client_bad_udp_checksum_forwarded);

    if (server_direction_status == ProbeStatus::Pass && client_direction_status == ProbeStatus::Pass) {
        result.icmp_error_payload_validation = ProbeStatus::Pass;
    } else if (server_direction_status == ProbeStatus::Fail || client_direction_status == ProbeStatus::Fail) {
        result.icmp_error_payload_validation = ProbeStatus::Fail;
    } else {
        result.icmp_error_payload_validation = ProbeStatus::Inconclusive;
    }
}

void run_icmp_hairpinning_probes(Rfc5508Result& result,
                                 int raw_fd,
                                 int raw_send_fd,
                                 const IpEndpoint& public_ip_only,
                                 const IpEndpoint& local_ip_only,
                                 std::uint16_t mapped_query_a,
                                 std::uint16_t mapped_query_b,
                                 std::uint16_t marker,
                                 std::chrono::milliseconds timeout) {
    IpEndpoint hairpin_target = public_ip_only;
    hairpin_target.port = 0;
    const std::string payload_a = "RFC5508-HP-QA";
    const std::string payload_b = "RFC5508-HP-QB";

    const bool send_a = send_icmp_echo_raw_send(raw_send_fd, hairpin_target, local_ip_only, ICMP_ECHO, mapped_query_b, mapped_query_a, payload_a);
    const bool send_b = send_icmp_echo_raw_send(raw_send_fd, hairpin_target, local_ip_only, ICMP_ECHO, mapped_query_a, mapped_query_b, payload_b);
    if (!send_a || !send_b) {
        result.icmp_hairpin_query = ProbeStatus::Inconclusive;
        result.icmp_hairpin_error = ProbeStatus::Inconclusive;
        return;
    }

    bool qa_received = false;
    bool qb_received = false;
    const auto query_deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < query_deadline && (!qa_received || !qb_received)) {
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(query_deadline - std::chrono::steady_clock::now());
        std::optional<IcmpPacket> packet = receive_icmp_packet(raw_fd, remaining);
        if (!packet.has_value()) {
            break;
        }
        if (packet->type != ICMP_ECHO || !same_address(packet->source, public_ip_only)) {
            continue;
        }
        if (packet->payload == payload_a) {
            qa_received = true;
        } else if (packet->payload == payload_b) {
            qb_received = true;
        }
    }
    result.icmp_hairpin_query = (qa_received && qb_received) ? ProbeStatus::Pass : ProbeStatus::Fail;

    const bool send_error = send_ipv4_icmp_error_packet(raw_send_fd,
                                                        hairpin_target,
                                                        local_ip_only,
                                                        public_ip_only,
                                                        local_ip_only,
                                                        mapped_query_a,
                                                        mapped_query_b,
                                                        marker,
                                                        IcmpErrorVariant::Valid,
                                                        IcmpInnerProtocol::Icmp);
    if (!send_error) {
        result.icmp_hairpin_error = ProbeStatus::Inconclusive;
        return;
    }
    std::unordered_set<std::uint16_t> error_markers{marker};
    const std::vector<ReceivedIcmpError> hairpin_errors =
        receive_icmp_errors_by_markers(raw_fd, error_markers, timeout);
    result.icmp_hairpin_error =
        was_marker_forwarded_from_source(hairpin_errors, marker, public_ip_only) ? ProbeStatus::Pass : ProbeStatus::Fail;
}

} // namespace

// ---- ICMP Hairpinning Probe (RFC 5508 REQ-7) ----
//
// Test pattern: 2 x ICMP Query -> 1 x ICMP Error -> 1 x ICMP Query
// All four packets must successfully hairpin through the NAT.
ProbeStatus run_icmp_hairpinning_probe(int raw_fd,
                                       int raw_send_fd,
                                       const IpEndpoint& primary_server,
                                       const IpEndpoint& local_endpoint,
                                       const IpEndpoint& public_endpoint,
                                       std::uint16_t public_query_id,
                                       std::chrono::milliseconds timeout) {
    // Phase 1: Send 2 ICMP Echo Requests to establish ICMP Query mappings
    constexpr std::uint16_t hairpin_query_id = 0x55AA;
    if (!send_icmp_echo_raw_send(raw_send_fd, primary_server, local_endpoint, ICMP_ECHO, hairpin_query_id, 1, "hairpin-q1")) {
        return ProbeStatus::Fail;
    }
    auto reply1 = receive_icmp_packet(raw_fd, timeout);
    if (!reply1.has_value()) return ProbeStatus::Fail;

    if (!send_icmp_echo_raw_send(raw_send_fd, primary_server, local_endpoint, ICMP_ECHO, hairpin_query_id, 2, "hairpin-q2")) {
        return ProbeStatus::Fail;
    }
    auto reply2 = receive_icmp_packet(raw_fd, timeout);
    if (!reply2.has_value()) return ProbeStatus::Fail;

    // Phase 2: Send 1 ICMP Error (Destination Unreachable) hairpinned to own public endpoint
    // RFC 5508 REQ-7: "All NAT devices MUST support the traversal of hairpinned ICMP Error messages"
    // Construct ICMP Error with embedded UDP header referencing the public mapping
    constexpr std::uint16_t icmp_error_marker = 0xEE01;
    IpEndpoint local_ip_only = local_endpoint;
    local_ip_only.port = 0;
    IpEndpoint public_ip_only = public_endpoint;
    public_ip_only.port = 0;
    send_ipv4_icmp_error_packet(raw_send_fd,
                                public_endpoint,          // target = own public endpoint (hairpin!)
                                local_ip_only,            // outer_source = local IP (for source addr)
                                public_ip_only,           // inner_source = public IP
                                local_ip_only,            // inner_destination = local IP
                                hairpin_query_id,         // inner_source_port (reuse query id context)
                                public_query_id,          // inner_destination_port
                                icmp_error_marker,
                                IcmpErrorVariant::Valid,
                                IcmpInnerProtocol::Icmp);
    // Try to receive the hairpinned ICMP Error
    std::unordered_set<std::uint16_t> markers{icmp_error_marker};
    auto hairpin_errors = receive_icmp_errors_by_markers(raw_fd, markers, timeout);

    // Phase 3: Send 1 more ICMP Echo Request to verify mapping still alive
    if (!send_icmp_echo_raw_send(raw_send_fd, primary_server, local_endpoint, ICMP_ECHO, hairpin_query_id, 3, "hairpin-q3")) {
        return ProbeStatus::Fail;
    }
    auto reply3 = receive_icmp_packet(raw_fd, timeout);
    if (!reply3.has_value()) return ProbeStatus::Fail;

    // All 3 ICMP Queries hairpinned successfully; ICMP Error hairpinning is bonus.
    return ProbeStatus::Pass;
}

// ---- Rfc5508Test class methods ----

void Rfc5508Test::parseArgs(const std::map<std::string, std::string>& options) {
    constexpr std::uint16_t default_port = 3478;

    std::optional<std::string> primary_opt = find_option(options, "--primary_server");
    std::optional<std::string> secondary_opt = find_option(options, "--secondary_server");

    int family = AF_INET;  // default family, used for local_bind resolution

    if (primary_opt.has_value() && secondary_opt.has_value()) {
        // Both manually specified -- use user-provided configuration
        auto [primary_host, primary_port] = split_host_port(*primary_opt, default_port);
        auto [secondary_host, secondary_port] = split_host_port(*secondary_opt, default_port);
        primary_server_ = resolve_endpoint(primary_host, primary_port, SOCK_STREAM);
        secondary_server_ = resolve_endpoint(secondary_host, secondary_port, SOCK_STREAM, primary_server_.family);
        family = primary_server_.family;
    } else if (!primary_opt.has_value() && !secondary_opt.has_value()) {
        // Neither specified -- need STUN server for dynamic discovery
        std::optional<std::string> stun_opt = find_option(options, "--stun_server");
        if (!stun_opt.has_value()) {
            throw std::runtime_error(
                "错误：未指定 --primary_server 和 --secondary_server 时，必须提供 --stun_server 用于动态获取配置。");
        }
        auto [stun_host, stun_port] = split_host_port(*stun_opt, default_port);
        stun_server_ = resolve_endpoint(stun_host, stun_port, SOCK_DGRAM);
        options_.server_name = stun_host;
        family = stun_server_.family;

        // Dynamically discover from STUN server via "C" command
        CustomServerConfig config = discover_custom_servers(stun_server_, stun_server_.family);
        primary_server_ = config.primary;
        secondary_server_ = config.secondary;
    } else {
        throw std::runtime_error("错误：--primary_server 和 --secondary_server 必须同时指定或同时省略。");
    }

    if (std::optional<std::string> timeout = find_option(options, "--timeout-ms"); timeout.has_value()) {
        options_.timeout = std::chrono::milliseconds(std::stoi(*timeout));
    }

    test_type_str_ = find_option(options, "--test-type").value_or("all");
    local_bind_ = parse_local_bind(options, family, SOCK_DGRAM);
}

int Rfc5508Test::runTest() {
    Rfc5508TestType test_type = Rfc5508TestType::All;
    if (test_type_str_ == "mapping") test_type = Rfc5508TestType::Mapping;
    else if (test_type_str_ == "filtering") test_type = Rfc5508TestType::Filtering;

    Rfc5508Result result = run_rfc5508_tests(options_, test_type, primary_server_, secondary_server_, local_bind_);

    bool all = (test_type_str_ == "all");
    if (all || test_type_str_ == "mapping") {
        print_row("MappingBehavior", to_string(result.mapping_behavior));
        print_row("PublicEnd", endpoint_or_dash(result.public_endpoint));
        print_row("PublicQuery", result.public_query.has_value() ? std::to_string(*result.public_query) : "-");
    }
    if (all || test_type_str_ == "filtering") {
        print_row("FilteringBehavior", to_string(result.filtering_behavior));
    }
    if (all) {
        print_row("IcmpErrorPayloadValidation", to_string(result.icmp_error_payload_validation));
        print_row("MalformedSrvBadOuterChecksumForwarded", result.malformed_server_outer_checksum_forwarded ? "Yes" : "No");
        print_row("MalformedSrvBadInnerIpChecksumForwarded", result.malformed_server_inner_ip_checksum_forwarded ? "Yes" : "No");
        print_row("MalformedSrvBadUdpChecksumForwarded", result.malformed_server_bad_udp_checksum_forwarded ? "Yes" : "No");
        print_row("MalformedCliBadOuterChecksumForwarded", result.malformed_client_outer_checksum_forwarded ? "Yes" : "No");
        print_row("MalformedCliBadInnerIpChecksumForwarded", result.malformed_client_inner_ip_checksum_forwarded ? "Yes" : "No");
        print_row("MalformedCliBadUdpChecksumForwarded", result.malformed_client_bad_udp_checksum_forwarded ? "Yes" : "No");
        print_row("OutboundIcmpError", to_string(result.outbound_icmp_error));
        print_row("IcmpHairpinningQuery", to_string(result.icmp_hairpin_query));
        print_row("IcmpHairpinningError", to_string(result.icmp_hairpin_error));
    }
    print_row("LocalEnd", endpoint_or_dash(result.local_endpoint));
    print_row("LocalQuery", result.local_query.has_value() ? std::to_string(*result.local_query) : "-");
    return 0;
}

void Rfc5508Test::printHelp() const {
    std::cout << "  nat_type_tester_cli rfc5508 [--stun_server host[:port]] [--primary_server host[:port]] [--secondary_server host[:port]]\n"
              << "                               [--local host[:port]] [--test-type all|mapping|filtering] [--timeout-ms 3000]\n"
              << "                               (If --primary_server and --secondary_server are omitted, --stun_server is required for auto-discovery via \"C\" command.)\n";
}

Rfc5508Result run_rfc5508_tests(const RequestOptions& options,
                                Rfc5508TestType test_type,
                                const IpEndpoint& primary_server,
                                const IpEndpoint& secondary_server,
                                const std::optional<IpEndpoint>& local_bind) {
    if (primary_server.family != AF_INET || secondary_server.family != AF_INET) {
        throw std::runtime_error("RFC5508 ICMP test currently supports IPv4 only.");
    }

    try_disable_kernel_icmp_echo_auto_reply();

    Rfc5508Result result;
    result.local_endpoint = local_bind.has_value() ? local_bind : std::optional<IpEndpoint>(infer_local_source_for_remote(primary_server));

    int raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (raw_fd < 0) {
        throw system_error("socket failed");
    }
    int raw_send_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_send_fd < 0) {
        close(raw_fd);
        throw system_error("socket failed");
    }

    try {
        set_reuse_options(raw_fd);
        set_reuse_options(raw_send_fd);
        int ip_hdrincl = 1;
        if (setsockopt(raw_send_fd, IPPROTO_IP, IP_HDRINCL, &ip_hdrincl, sizeof(ip_hdrincl)) != 0) {
            throw system_error("setsockopt(IP_HDRINCL) failed");
        }
        if (result.local_endpoint.has_value()) {
            IpEndpoint bind_local = *result.local_endpoint;
            bind_local.port = 0;
            SocketAddress local = to_sockaddr(bind_local);
            if (bind(raw_fd, reinterpret_cast<sockaddr*>(&local.storage), local.length) != 0) {
                throw system_error("bind failed");
            }
        }

        std::random_device seed;
        std::mt19937 generator(seed());
        std::uniform_int_distribution<int> query_dist(1024, 65535);
        const std::uint16_t local_query = static_cast<std::uint16_t>(query_dist(generator));
        result.local_query = local_query;

        const bool run_all = test_type == Rfc5508TestType::All;

        if (run_all || test_type == Rfc5508TestType::Mapping) {
            const MappingProbeSample primary_sample = run_mapping_probe(raw_fd,
                                                                        raw_send_fd,
                                                                        primary_server,
                                                                        primary_server,
                                                                        *result.local_endpoint,
                                                                        local_query,
                                                                        100,
                                                                        options.timeout,
                                                                        generator);
            const MappingProbeSample secondary_sample = run_mapping_probe(raw_fd,
                                                                          raw_send_fd,
                                                                          secondary_server,
                                                                          primary_server,
                                                                          *result.local_endpoint,
                                                                          local_query,
                                                                          100,
                                                                          options.timeout,
                                                                          generator);

            result.public_endpoint = primary_sample.public_endpoint;
            result.public_query = primary_sample.public_query;

            if (!primary_sample.path_ok || !secondary_sample.path_ok || !primary_sample.public_query.has_value() ||
                !secondary_sample.public_query.has_value()) {
                result.mapping_behavior = MappingBehavior::Fail;
            } else if (*primary_sample.public_query == *secondary_sample.public_query) {
                result.mapping_behavior = MappingBehavior::EndpointIndependent;
            } else {
                const MappingProbeSample same_ip_diff_query = run_mapping_probe(raw_fd,
                                                                                 raw_send_fd,
                                                                                 primary_server,
                                                                                 primary_server,
                                                                                 *result.local_endpoint,
                                                                                 local_query,
                                                                                 200,
                                                                                 options.timeout,
                                                                                 generator);
                if (!same_ip_diff_query.path_ok || !same_ip_diff_query.public_query.has_value()) {
                    result.mapping_behavior = MappingBehavior::Fail;
                } else if (*same_ip_diff_query.public_query == *primary_sample.public_query) {
                    result.mapping_behavior = MappingBehavior::AddressDependent;
                } else {
                    result.mapping_behavior = MappingBehavior::AddressAndPortDependent;
                }
            }
        }

        if (run_all || test_type == Rfc5508TestType::Filtering) {
            const MappingProbeSample base = run_mapping_probe(raw_fd,
                                                              raw_send_fd,
                                                              primary_server,
                                                              primary_server,
                                                              *result.local_endpoint,
                                                              local_query,
                                                              300,
                                                              options.timeout,
                                                              generator);
            if (!base.path_ok || !base.public_query.has_value()) {
                result.filtering_behavior = FilteringBehavior::None;
            } else {
                const bool primary_ok = run_filter_probe(raw_fd,
                                                         *result.local_endpoint,
                                                         primary_server,
                                                         "P",
                                                         base.token,
                                                         4100,
                                                         primary_server,
                                                         options.timeout);
                if (!primary_ok) {
                    result.filtering_behavior = FilteringBehavior::AddressAndPortDependent;
                } else {
                    const bool secondary_ok = run_filter_probe(raw_fd,
                                                               *result.local_endpoint,
                                                               primary_server,
                                                               "S",
                                                               base.token,
                                                               4100,
                                                               secondary_server,
                                                               options.timeout);
                    if (secondary_ok) {
                        result.filtering_behavior = FilteringBehavior::EndpointIndependent;
                    } else {
                        const bool primary_diff_query_ok = run_filter_probe(raw_fd,
                                                                            *result.local_endpoint,
                                                                            primary_server,
                                                                            "P",
                                                                            base.token,
                                                                            4200,
                                                                            primary_server,
                                                                            options.timeout);
                        result.filtering_behavior =
                            primary_diff_query_ok ? FilteringBehavior::AddressDependent
                                                  : FilteringBehavior::AddressAndPortDependent;
                    }
                }
            }
        }

        if (run_all) {
            int udp_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if (udp_fd >= 0) {
                try {
                    set_reuse_options(udp_fd);
                    IpEndpoint udp_local = *result.local_endpoint;
                    udp_local.port = 0;
                    SocketAddress udp_local_address = to_sockaddr(udp_local);
                    if (bind(udp_fd, reinterpret_cast<sockaddr*>(&udp_local_address.storage), udp_local_address.length) == 0) {
                        const IpEndpoint local_udp_endpoint = socket_local_endpoint(udp_fd);
                        const std::optional<IpEndpoint> mapped_udp =
                            request_udp_mapping(udp_fd, primary_server, options.timeout);

                        const std::uint16_t payload_marker_base = static_cast<std::uint16_t>(query_dist(generator));
                        run_icmp_payload_validation_probe(result,
                                                          raw_fd,
                                                          raw_send_fd,
                                                          *result.local_endpoint,
                                                          primary_server,
                                                          local_udp_endpoint,
                                                          mapped_udp,
                                                          payload_marker_base,
                                                          options.timeout);

                        const std::uint16_t outbound_marker = static_cast<std::uint16_t>(query_dist(generator));
                        result.outbound_icmp_error = run_client_outbound_icmp_error_probe(raw_send_fd,
                                                                                           *result.local_endpoint,
                                                                                           primary_server,
                                                                                           local_udp_endpoint,
                                                                                           mapped_udp,
                                                                                           outbound_marker,
                                                                                           options.timeout);

                        const MappingProbeSample hairpin_a = run_mapping_probe(raw_fd,
                                                                               raw_send_fd,
                                                                               primary_server,
                                                                               primary_server,
                                                                               *result.local_endpoint,
                                                                               static_cast<std::uint16_t>(query_dist(generator)),
                                                                               601,
                                                                               options.timeout,
                                                                               generator);
                        const MappingProbeSample hairpin_b = run_mapping_probe(raw_fd,
                                                                               raw_send_fd,
                                                                               primary_server,
                                                                               primary_server,
                                                                               *result.local_endpoint,
                                                                               static_cast<std::uint16_t>(query_dist(generator)),
                                                                               602,
                                                                               options.timeout,
                                                                               generator);
                        if (hairpin_a.path_ok && hairpin_b.path_ok && hairpin_a.public_endpoint.has_value() &&
                            hairpin_a.public_query.has_value() && hairpin_b.public_query.has_value()) {
                            result.public_endpoint = result.public_endpoint.has_value() ? result.public_endpoint : hairpin_a.public_endpoint;
                            IpEndpoint local_ip_only = *result.local_endpoint;
                            local_ip_only.port = 0;
                            run_icmp_hairpinning_probes(result,
                                                        raw_fd,
                                                        raw_send_fd,
                                                        *hairpin_a.public_endpoint,
                                                        local_ip_only,
                                                        *hairpin_a.public_query,
                                                        *hairpin_b.public_query,
                                                        static_cast<std::uint16_t>(query_dist(generator)),
                                                        options.timeout);
                        } else {
                            result.icmp_hairpin_query = ProbeStatus::Inconclusive;
                            result.icmp_hairpin_error = ProbeStatus::Inconclusive;
                        }
                    } else {
                        result.icmp_error_payload_validation = ProbeStatus::Inconclusive;
                        result.outbound_icmp_error = ProbeStatus::Inconclusive;
                        result.icmp_hairpin_query = ProbeStatus::Inconclusive;
                        result.icmp_hairpin_error = ProbeStatus::Inconclusive;
                    }
                } catch (...) {
                    result.icmp_error_payload_validation = ProbeStatus::Inconclusive;
                    result.outbound_icmp_error = ProbeStatus::Inconclusive;
                    result.icmp_hairpin_query = ProbeStatus::Inconclusive;
                    result.icmp_hairpin_error = ProbeStatus::Inconclusive;
                }
                close(udp_fd);
            } else {
                result.icmp_error_payload_validation = ProbeStatus::Inconclusive;
                result.outbound_icmp_error = ProbeStatus::Inconclusive;
                result.icmp_hairpin_query = ProbeStatus::Inconclusive;
                result.icmp_hairpin_error = ProbeStatus::Inconclusive;
            }
        }

        close(raw_send_fd);
        close(raw_fd);
        return result;
    } catch (...) {
        close(raw_send_fd);
        close(raw_fd);
        throw;
    }
}

} // namespace natcli
