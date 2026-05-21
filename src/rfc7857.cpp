#include "rfc7857.hpp"

#include "discovery.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace natcli {

std::string analyze_port_allocation_behavior(const std::vector<std::uint16_t>& local_ports,
                                             const std::vector<std::uint16_t>& public_ports);

namespace {

struct SocketAddress {
    sockaddr_storage storage{};
    socklen_t length{};
};

struct PortRandomizationProbeResult {
    ProbeStatus status{ProbeStatus::Unknown};
    std::vector<std::uint16_t> public_ports;
    std::vector<std::uint16_t> local_ports;
    std::string allocation_behavior;
};

std::runtime_error system_error(const std::string& message) {
    return std::runtime_error(message + ": " + std::strerror(errno));
}

SocketAddress to_sockaddr(const IpEndpoint& endpoint) {
    SocketAddress result;
    result.length = endpoint.family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
    if (endpoint.family == AF_INET) {
        auto* address = reinterpret_cast<sockaddr_in*>(&result.storage);
        address->sin_family = AF_INET;
        address->sin_port = htons(endpoint.port);
        std::memcpy(&address->sin_addr, endpoint.address.data(), 4);
        return result;
    }
    auto* address = reinterpret_cast<sockaddr_in6*>(&result.storage);
    address->sin6_family = AF_INET6;
    address->sin6_port = htons(endpoint.port);
    std::memcpy(&address->sin6_addr, endpoint.address.data(), 16);
    return result;
}

IpEndpoint from_sockaddr(const sockaddr* address, socklen_t length) {
    (void)length;
    IpEndpoint result;
    if (address->sa_family == AF_INET) {
        const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(address);
        result.family = AF_INET;
        result.address_length = 4;
        result.port = ntohs(ipv4->sin_port);
        std::memcpy(result.address.data(), &ipv4->sin_addr, 4);
        return result;
    }
    if (address->sa_family == AF_INET6) {
        const auto* ipv6 = reinterpret_cast<const sockaddr_in6*>(address);
        result.family = AF_INET6;
        result.address_length = 16;
        result.port = ntohs(ipv6->sin6_port);
        std::memcpy(result.address.data(), &ipv6->sin6_addr, 16);
        return result;
    }
    throw std::runtime_error("Unsupported sockaddr family");
}

void set_reuse_options(int socket_fd) {
    int reuse = 1;
    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#ifdef SO_REUSEPORT
    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
#endif
}

bool wait_for_readable(int socket_fd, std::chrono::milliseconds timeout) {
    pollfd descriptor{socket_fd, POLLIN, 0};
    int rc = poll(&descriptor, 1, static_cast<int>(timeout.count()));
    return rc > 0 && (descriptor.revents & POLLIN) != 0;
}

void send_all(int socket_fd, std::string_view payload) {
    std::size_t offset = 0;
    while (offset < payload.size()) {
        ssize_t written = send(socket_fd, payload.data() + offset, payload.size() - offset, 0);
        if (written <= 0) {
            throw system_error("send failed");
        }
        offset += static_cast<std::size_t>(written);
    }
}

std::string recv_line(int socket_fd, std::chrono::milliseconds timeout) {
    std::string line;
    std::array<char, 256> buffer{};
    while (line.find('\n') == std::string::npos) {
        if (!wait_for_readable(socket_fd, timeout)) {
            throw std::runtime_error("recv timed out");
        }
        ssize_t received = recv(socket_fd, buffer.data(), buffer.size(), 0);
        if (received <= 0) {
            throw std::runtime_error("peer closed connection");
        }
        line.append(buffer.data(), static_cast<std::size_t>(received));
        if (line.size() > 4096) {
            throw std::runtime_error("protocol line too long");
        }
    }
    return line.substr(0, line.find('\n'));
}

std::optional<IpEndpoint> parse_endpoint_line(const std::string& line, int family) {
    std::istringstream stream(line);
    std::string host;
    std::uint16_t port = 0;
    if (!(stream >> host >> port)) {
        return std::nullopt;
    }
    return resolve_endpoint(host, port, SOCK_STREAM, family);
}

std::string join_ports(const std::vector<std::uint16_t>& ports) {
    if (ports.empty()) {
        return "-";
    }
    std::ostringstream stream;
    for (std::size_t index = 0; index < ports.size(); ++index) {
        if (index > 0) {
            stream << ",";
        }
        stream << ports[index];
    }
    return stream.str();
}

std::optional<IpEndpoint> request_udp_mapping_with_local(const IpEndpoint& server,
                                                         const IpEndpoint& local_bind,
                                                         std::chrono::milliseconds timeout) {
    int socket_fd = socket(server.family, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd < 0) {
        return std::nullopt;
    }
    try {
        set_reuse_options(socket_fd);
        SocketAddress local = to_sockaddr(local_bind);
        if (bind(socket_fd, reinterpret_cast<sockaddr*>(&local.storage), local.length) != 0) {
            close(socket_fd);
            return std::nullopt;
        }
        SocketAddress remote = to_sockaddr(server);
        constexpr std::string_view kMappingRequest = "M\n";
        const ssize_t sent =
            sendto(socket_fd, kMappingRequest.data(), kMappingRequest.size(), 0,
                   reinterpret_cast<sockaddr*>(&remote.storage), remote.length);
        if (sent != static_cast<ssize_t>(kMappingRequest.size())) {
            close(socket_fd);
            return std::nullopt;
        }
        if (!wait_for_readable(socket_fd, timeout)) {
            close(socket_fd);
            return std::nullopt;
        }
        std::array<char, 256> buffer{};
        ssize_t received = recv(socket_fd, buffer.data(), buffer.size() - 1, 0);
        close(socket_fd);
        if (received <= 0) {
            return std::nullopt;
        }
        buffer[static_cast<std::size_t>(received)] = '\0';
        return parse_endpoint_line(std::string(buffer.data()), server.family);
    } catch (...) {
        close(socket_fd);
        return std::nullopt;
    }
}

PortRandomizationProbeResult run_section9_port_randomization_probe(const IpEndpoint& primary_server,
                                                                   int family,
                                                                   std::chrono::milliseconds timeout) {
    constexpr int kSamples = 20;
    constexpr int kRetryBudget = 200;
    std::random_device seed;
    std::mt19937 generator(seed());
    std::uniform_int_distribution<int> port_distribution(1024, 65535);

    PortRandomizationProbeResult result;
    int retries = 0;
    while (static_cast<int>(result.public_ports.size()) < kSamples && retries < kRetryBudget) {
        ++retries;
        IpEndpoint local = wildcard_endpoint(family);
        local.port = static_cast<std::uint16_t>(port_distribution(generator));
        std::optional<IpEndpoint> mapped = request_udp_mapping_with_local(primary_server, local, timeout);
        if (!mapped.has_value()) {
            continue;
        }
        result.public_ports.push_back(mapped->port);
        result.local_ports.push_back(local.port);
    }

    result.status = classify_rfc7857_port_randomization(result.public_ports);
    result.allocation_behavior = analyze_port_allocation_behavior(result.local_ports, result.public_ports);
    return result;
}

ProbeStatus merge_probe_status(ProbeStatus left, ProbeStatus right) {
    if (left == ProbeStatus::Fail || right == ProbeStatus::Fail) {
        return ProbeStatus::Fail;
    }
    if (left == ProbeStatus::Pass && right == ProbeStatus::Pass) {
        return ProbeStatus::Pass;
    }
    if (left == ProbeStatus::Unknown || right == ProbeStatus::Unknown) {
        return ProbeStatus::Unknown;
    }
    return ProbeStatus::Inconclusive;
}

std::uint16_t calculate_checksum(const void* data, std::size_t len) {
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    std::uint32_t sum = 0;
    while (len >= 2) {
        sum += static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[0]) << 8) | bytes[1]);
        bytes += 2;
        len -= 2;
    }
    if (len == 1) {
        sum += static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[0]) << 8);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<std::uint16_t>(~sum);
}

std::uint16_t calculate_udp_checksum_ipv4(const iphdr& ip_header,
                                          const udphdr& udp_header,
                                          const std::uint8_t* payload,
                                          std::size_t payload_len) {
    std::uint32_t sum = 0;

    auto add_buffer = [&](const void* data, std::size_t len) {
        const auto* bytes = static_cast<const std::uint8_t*>(data);
        while (len >= 2) {
            sum += static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[0]) << 8) | bytes[1]);
            bytes += 2;
            len -= 2;
        }
        if (len == 1) {
            sum += static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[0]) << 8);
        }
    };

    add_buffer(&ip_header.saddr, 4);
    add_buffer(&ip_header.daddr, 4);
    std::uint16_t protocol_word = htons(IPPROTO_UDP);
    add_buffer(&protocol_word, 2);
    add_buffer(&udp_header.len, 2);
    add_buffer(&udp_header, sizeof(udphdr));
    add_buffer(payload, payload_len);

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<std::uint16_t>(~sum);
}

std::optional<std::array<std::uint8_t, 4>> resolve_local_ipv4_for_server(const IpEndpoint& server) {
    if (server.family != AF_INET) {
        return std::nullopt;
    }
    int socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd < 0) {
        return std::nullopt;
    }
    try {
        SocketAddress remote = to_sockaddr(server);
        if (connect(socket_fd, reinterpret_cast<sockaddr*>(&remote.storage), remote.length) != 0) {
            close(socket_fd);
            return std::nullopt;
        }
        sockaddr_storage local_storage{};
        socklen_t local_length = sizeof(local_storage);
        if (getsockname(socket_fd, reinterpret_cast<sockaddr*>(&local_storage), &local_length) != 0) {
            close(socket_fd);
            return std::nullopt;
        }
        close(socket_fd);
        IpEndpoint local = from_sockaddr(reinterpret_cast<sockaddr*>(&local_storage), local_length);
        if (local.family != AF_INET) {
            return std::nullopt;
        }
        return {std::array<std::uint8_t, 4>{local.address[0], local.address[1], local.address[2], local.address[3]}};
    } catch (...) {
        close(socket_fd);
        return std::nullopt;
    }
}

bool send_udp_packet_with_ipv4_id(const IpEndpoint& server,
                                  const std::array<std::uint8_t, 4>& source_ip,
                                  std::uint16_t source_port,
                                  std::uint16_t ip_id,
                                  std::string_view payload) {
    int raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_fd < 0) {
        return false;
    }
    int enable = 1;
    if (setsockopt(raw_fd, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)) != 0) {
        close(raw_fd);
        return false;
    }

    try {
        std::vector<std::uint8_t> packet(sizeof(iphdr) + sizeof(udphdr) + payload.size(), 0);
        auto* ip_header = reinterpret_cast<iphdr*>(packet.data());
        auto* udp_header = reinterpret_cast<udphdr*>(packet.data() + sizeof(iphdr));
        auto* udp_payload = packet.data() + sizeof(iphdr) + sizeof(udphdr);
        std::memcpy(udp_payload, payload.data(), payload.size());

        ip_header->ihl = 5;
        ip_header->version = 4;
        ip_header->tos = 0;
        ip_header->tot_len = htons(static_cast<std::uint16_t>(packet.size()));
        ip_header->id = htons(ip_id);
        ip_header->frag_off = 0;
        ip_header->ttl = 64;
        ip_header->protocol = IPPROTO_UDP;
        std::memcpy(&ip_header->saddr, source_ip.data(), 4);
        std::memcpy(&ip_header->daddr, server.address.data(), 4);
        ip_header->check = 0;
        ip_header->check = calculate_checksum(ip_header, sizeof(iphdr));

        udp_header->source = htons(source_port);
        udp_header->dest = htons(server.port);
        udp_header->len = htons(static_cast<std::uint16_t>(sizeof(udphdr) + payload.size()));
        udp_header->check = 0;
        udp_header->check = calculate_udp_checksum_ipv4(*ip_header, *udp_header, udp_payload, payload.size());
        if (udp_header->check == 0) {
            udp_header->check = 0xFFFF;
        }

        sockaddr_in destination{};
        destination.sin_family = AF_INET;
        destination.sin_port = htons(server.port);
        std::memcpy(&destination.sin_addr, server.address.data(), 4);
        const ssize_t sent =
            sendto(raw_fd, packet.data(), packet.size(), 0, reinterpret_cast<sockaddr*>(&destination), sizeof(destination));
        close(raw_fd);
        return sent == static_cast<ssize_t>(packet.size());
    } catch (...) {
        close(raw_fd);
        return false;
    }
}

ProbeStatus run_single_section10_probe(const IpEndpoint& server,
                                       const std::chrono::milliseconds timeout,
                                       const std::optional<IpEndpoint>& local_bind,
                                       std::mt19937& generator) {
    if (server.family != AF_INET) {
        return ProbeStatus::Inconclusive;
    }

    int control = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (control < 0) {
        return ProbeStatus::Inconclusive;
    }
    try {
        set_reuse_options(control);
        if (local_bind.has_value() && local_bind->family == AF_INET) {
            IpEndpoint tcp_local = *local_bind;
            tcp_local.port = 0;
            SocketAddress local = to_sockaddr(tcp_local);
            if (bind(control, reinterpret_cast<sockaddr*>(&local.storage), local.length) != 0) {
                close(control);
                return ProbeStatus::Inconclusive;
            }
        }
        SocketAddress remote = to_sockaddr(server);
        if (connect(control, reinterpret_cast<sockaddr*>(&remote.storage), remote.length) != 0) {
            close(control);
            return ProbeStatus::Inconclusive;
        }

        std::optional<std::array<std::uint8_t, 4>> source_ip = resolve_local_ipv4_for_server(server);
        if (!source_ip.has_value()) {
            close(control);
            return ProbeStatus::Inconclusive;
        }

        std::uniform_int_distribution<int> id_distribution(1, 65535);
        std::uniform_int_distribution<int> port_distribution(1024, 65535);
        const std::uint16_t ip_id = static_cast<std::uint16_t>(id_distribution(generator));
        const std::uint16_t src_port = static_cast<std::uint16_t>(port_distribution(generator));
        const std::string token = std::to_string(id_distribution(generator));

        send_all(control, "V " + token + "\n");
        const std::string payload = "VID:" + token + ":" + std::to_string(ip_id) + "\n";
        if (!send_udp_packet_with_ipv4_id(server, *source_ip, src_port, ip_id, payload)) {
            close(control);
            return ProbeStatus::Inconclusive;
        }

        const std::string response = recv_line(control, timeout);
        close(control);
        if (!response.starts_with("V=")) {
            return ProbeStatus::Fail;
        }
        const int observed_id = std::stoi(response.substr(2));
        if (observed_id < 0) {
            return ProbeStatus::Fail;
        }
        return static_cast<std::uint16_t>(observed_id) == ip_id ? ProbeStatus::Pass : ProbeStatus::Fail;
    } catch (...) {
        close(control);
        return ProbeStatus::Inconclusive;
    }
}

ProbeStatus run_section10_ipv4_id_preservation_probe(const IpEndpoint& primary_server,
                                                     const IpEndpoint& secondary_server,
                                                     std::chrono::milliseconds timeout,
                                                     const std::optional<IpEndpoint>& local_bind) {
    if (primary_server.family != AF_INET || secondary_server.family != AF_INET) {
        return ProbeStatus::Inconclusive;
    }
    std::random_device seed;
    std::mt19937 generator(seed());
    const ProbeStatus first = run_single_section10_probe(primary_server, timeout, local_bind, generator);
    const ProbeStatus second = run_single_section10_probe(secondary_server, timeout, local_bind, generator);
    return merge_probe_status(first, second);
}

ProbeStatus classify_port_parity(const std::optional<IpEndpoint>& local,
                                 const std::optional<IpEndpoint>& udp_public,
                                 const std::optional<IpEndpoint>& tcp_public) {
    if (!udp_public.has_value() || !tcp_public.has_value()) {
        return ProbeStatus::Inconclusive;
    }
    if (!local.has_value()) {
        return ProbeStatus::Inconclusive;
    }
    const bool local_parity = (local->port % 2) == 0;
    const bool udp_parity = (udp_public->port % 2) == 0;
    const bool tcp_parity = (tcp_public->port % 2) == 0;
    return (local_parity == udp_parity && local_parity == tcp_parity) ? ProbeStatus::Pass : ProbeStatus::Fail;
}

} // namespace

ProbeStatus classify_rfc7857_eim_protocol_independence(const std::optional<IpEndpoint>& udp_public,
                                                       const std::optional<IpEndpoint>& tcp_public) {
    if (!udp_public.has_value() || !tcp_public.has_value()) {
        return ProbeStatus::Inconclusive;
    }
    return *udp_public == *tcp_public ? ProbeStatus::Fail : ProbeStatus::Pass;
}

ProbeStatus classify_rfc7857_eif_protocol_independence(const std::optional<bool>& tcp_mapping_allows_udp,
                                                       const std::optional<bool>& udp_mapping_allows_tcp) {
    if (!tcp_mapping_allows_udp.has_value() || !udp_mapping_allows_tcp.has_value()) {
        return ProbeStatus::Inconclusive;
    }
    if (*tcp_mapping_allows_udp || *udp_mapping_allows_tcp) {
        return ProbeStatus::Fail;
    }
    return ProbeStatus::Pass;
}

ProbeStatus classify_rfc7857_port_randomization(const std::vector<std::uint16_t>& public_ports) {
    constexpr std::size_t kExpectedSamples = 20;
    if (public_ports.size() < kExpectedSamples) {
        return ProbeStatus::Inconclusive;
    }
    std::size_t small_increment_count = 0;
    for (std::size_t index = 1; index < public_ports.size(); ++index) {
        const std::uint16_t previous = public_ports[index - 1];
        const std::uint16_t current = public_ports[index];
        if (current > previous) {
            const std::uint16_t delta = static_cast<std::uint16_t>(current - previous);
            if (delta == 1 || delta == 2) {
                ++small_increment_count;
            }
        }
    }
    constexpr std::size_t kSequentialThreshold = 14;
    return small_increment_count >= kSequentialThreshold ? ProbeStatus::Fail : ProbeStatus::Pass;
}

std::string analyze_port_allocation_behavior(const std::vector<std::uint16_t>& local_ports,
                                             const std::vector<std::uint16_t>& public_ports) {
    if (public_ports.size() < 2 || local_ports.size() != public_ports.size()) {
        return "Unknown";
    }

    // 1. 检查 Preserved (端口保留：公网端口 == 本地端口)
    bool is_preserved = true;
    for (std::size_t i = 0; i < public_ports.size(); ++i) {
        if (public_ports[i] != local_ports[i]) {
            is_preserved = false;
            break;
        }
    }
    if (is_preserved) {
        return "Preserved (Delta = 0, Port = LocalPort)";
    }

    // 2. 计算 Delta (连续公网端口之间的差值)
    std::size_t sequential_count = 0;
    std::uint16_t min_port = public_ports[0];
    std::uint16_t max_port = public_ports[0];

    for (std::size_t i = 1; i < public_ports.size(); ++i) {
        min_port = std::min(min_port, public_ports[i]);
        max_port = std::max(max_port, public_ports[i]);

        if (public_ports[i] > public_ports[i - 1]) {
            std::uint16_t delta = public_ports[i] - public_ports[i - 1];
            if (delta == 1 || delta == 2) {
                sequential_count++;
            }
        } else if (public_ports[i - 1] > public_ports[i]) {
            std::uint16_t delta = public_ports[i - 1] - public_ports[i];
            if (delta == 1 || delta == 2) {
                sequential_count++;
            }
        }
    }

    // 如果 70% 以上的分配是递增 1 或 2，判定为 Sequential
    if (sequential_count >= (public_ports.size() - 1) * 0.7) {
        return "Sequential (Delta = +1 or +2)";
    }

    // 3. 检查 Contiguous Port Block (在一个紧凑的端口块内，比如 CGNAT 分配了 256 个端口的块)
    if ((max_port - min_port) < 100) {
        return "Contiguous Port Block (Narrow Range)";
    }

    // 4. 其余情况视为 Random
    return "Random";
}

Rfc7857Result run_rfc7857_tests(const RequestOptions& options,
                                const IpEndpoint& stun_server,
                                const IpEndpoint& primary_server,
                                const IpEndpoint& secondary_server,
                                const std::optional<IpEndpoint>& local_bind) {
    RequestOptions udp_options = options;
    udp_options.transport = TransportType::Udp;

    StunResult5389 udp_mapping = run_rfc5780_test(udp_options, StunTestType::Mapping, stun_server, local_bind);
    StunResult5389 udp_filtering = run_rfc5780_test(udp_options, StunTestType::Filtering, stun_server, local_bind);
    Rfc5382TcpResult tcp_result = run_rfc5382_tests(options, stun_server, primary_server, secondary_server, local_bind);

    Rfc7857Result result;
    result.udp_mapping_behavior = udp_mapping.mapping_behavior;
    result.udp_filtering_behavior = udp_filtering.filtering_behavior;
    result.tcp_filtering_behavior = tcp_result.filtering_behavior;
    result.local_endpoint = tcp_result.local_endpoint.has_value() ? tcp_result.local_endpoint : udp_mapping.local_endpoint;
    result.udp_public_endpoint = udp_mapping.public_endpoint;
    result.tcp_public_endpoint = tcp_result.tcp_public_endpoint;
    result.eim_protocol_independence =
        classify_rfc7857_eim_protocol_independence(result.udp_public_endpoint, result.tcp_public_endpoint);
    result.eif_protocol_independence = classify_rfc7857_eif_protocol_independence(
        tcp_result.tcp_mapping_allows_udp, tcp_result.udp_mapping_allows_tcp);
    result.port_parity_preservation =
        classify_port_parity(result.local_endpoint, result.udp_public_endpoint, result.tcp_public_endpoint);
    result.udp_hairpinning = run_udp_hairpinning_test(options, stun_server, local_bind);
    result.tcp_hairpinning = tcp_result.tcp_hairpinning;
    result.icmp_hairpinning = run_rfc7857_icmp_hairpinning_test(options, stun_server, primary_server, local_bind);

    PortRandomizationProbeResult section9 = run_section9_port_randomization_probe(primary_server, primary_server.family, options.timeout);
    result.section9_port_randomization = section9.status;
    result.section9_public_ports = join_ports(section9.public_ports);
    result.section9_allocation_behavior = section9.allocation_behavior;
    result.section10_ipv4_id_preservation =
        run_section10_ipv4_id_preservation_probe(primary_server, secondary_server, options.timeout, local_bind);

    return result;
}

} // namespace natcli
