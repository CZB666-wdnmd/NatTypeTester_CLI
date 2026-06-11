#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <ifaddrs.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace {

constexpr std::string_view kRfc7857UdpProbePayload = "RFC7857-UDP-PROBE\n";
constexpr std::string_view kRfc4787OutOfOrderFragmentPayload = "RFC4787-OOO-FRAGMENT\n";

struct IpEndpoint {
    int family{};
    std::array<std::uint8_t, 16> address{};
    std::size_t address_length{};
    std::uint16_t port{};
};

struct SocketAddress {
    sockaddr_storage storage{};
    socklen_t length{};
};

struct StunNode {
    int fd = -1;
    IpEndpoint bind_ep{};
    IpEndpoint pub_ep{};
    std::string iface_name{};
};

struct IcmpMappingRecord {
    std::string peer_host;
    std::uint16_t mapped_query{};
};

struct IcmpRawContext {
    int primary_socket{-1};
    int secondary_socket{-1};
    std::unordered_map<std::string, IcmpMappingRecord> mappings;
    std::mutex mappings_mutex;
    std::unordered_set<std::uint16_t> observed_error_markers;
    std::mutex observed_error_markers_mutex;
};

struct StunContext {
    StunNode nodes[4];
    IcmpRawContext icmp_ctx;
};

enum class IcmpErrorVariant : std::uint8_t {
    BadOuterChecksum = 1,
    BadInnerIpChecksum = 2,
    BadUdpChecksum = 3,
};

[[noreturn]] void fail(const std::string& message) {
    throw std::runtime_error(message);
}

std::runtime_error system_error(const std::string& message) {
    return std::runtime_error(message + ": " + std::strerror(errno));
}

bool run_shell_command(const std::string& command) {
    return std::system(command.c_str()) == 0;
}

bool command_exists(const std::string& command) {
    return run_shell_command("command -v " + command + " >/dev/null 2>&1");
}

bool ensure_iptables_icmp_notrack() {
    if (!command_exists("iptables")) return false;
    bool ok = true;
    if (!run_shell_command("iptables -t raw -C OUTPUT -p icmp -j CT --notrack >/dev/null 2>&1")) {
        if (!run_shell_command("iptables -t raw -I OUTPUT -p icmp -j CT --notrack >/dev/null 2>&1")) ok = false;
    }
    if (!run_shell_command("iptables -t raw -C PREROUTING -p icmp -j CT --notrack >/dev/null 2>&1")) {
        if (!run_shell_command("iptables -t raw -I PREROUTING -p icmp -j CT --notrack >/dev/null 2>&1")) ok = false;
    }
    return ok;
}

bool ensure_nftables_icmp_notrack() {
    if (!command_exists("nft")) return false;
    bool ok = true;
    if (!run_shell_command("nft list table inet raw >/dev/null 2>&1") &&
        !run_shell_command("nft add table inet raw >/dev/null 2>&1")) ok = false;
    if (!run_shell_command("nft list chain inet raw prerouting >/dev/null 2>&1") &&
        !run_shell_command("nft add chain inet raw prerouting '{ type filter hook prerouting priority raw; }' >/dev/null 2>&1")) ok = false;
    if (!run_shell_command("nft list chain inet raw output >/dev/null 2>&1") &&
        !run_shell_command("nft add chain inet raw output '{ type filter hook output priority raw; }' >/dev/null 2>&1")) ok = false;
    
    if (!run_shell_command("nft list chain inet raw output 2>/dev/null | grep -Eq 'meta l4proto \\{ icmp, ipv6-icmp \\} notrack'")) {
        run_shell_command("nft add rule inet raw output meta l4proto '{ icmp, ipv6-icmp }' notrack >/dev/null 2>&1");
    }
    if (!run_shell_command("nft list chain inet raw prerouting 2>/dev/null | grep -Eq 'meta l4proto \\{ icmp, ipv6-icmp \\} notrack'")) {
        run_shell_command("nft add rule inet raw prerouting meta l4proto '{ icmp, ipv6-icmp }' notrack >/dev/null 2>&1");
    }
    return ok;
}

void ensure_icmp_conntrack_bypass() {
    bool configured = ensure_iptables_icmp_notrack();
    if (!configured) configured = ensure_nftables_icmp_notrack();
    if (configured) std::cout << "Note: ICMP/ICMPv6 conntrack bypass (notrack) is active.\n";
    else std::cerr << "Warning: Failed to configure ICMP notrack rules via iptables/nft.\n";
}

void try_disable_kernel_icmp_echo_auto_reply() {
    FILE* f1 = fopen("/proc/sys/net/ipv4/icmp_echo_ignore_all", "w");
    if (f1) { fputs("1\n", f1); fclose(f1); }
}

bool is_unspecified(const IpEndpoint& ep) {
    for (std::size_t i = 0; i < ep.address_length; ++i) {
        if (ep.address[i] != 0) return false;
    }
    return true;
}

std::string get_interface_name(const IpEndpoint& endpoint) {
    if (is_unspecified(endpoint)) return "";
    ifaddrs* interfaces = nullptr;
    if (getifaddrs(&interfaces) != 0) return "";
    
    std::unique_ptr<ifaddrs, decltype(&freeifaddrs)> guard(interfaces, freeifaddrs);
    for (ifaddrs* ifa = interfaces; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        if (ifa->ifa_addr->sa_family != endpoint.family) continue;
        
        if (endpoint.family == AF_INET) {
            auto* ipv4 = reinterpret_cast<sockaddr_in*>(ifa->ifa_addr);
            if (std::memcmp(&ipv4->sin_addr, endpoint.address.data(), 4) == 0) {
                return ifa->ifa_name;
            }
        } else if (endpoint.family == AF_INET6) {
            auto* ipv6 = reinterpret_cast<sockaddr_in6*>(ifa->ifa_addr);
            if (std::memcmp(&ipv6->sin6_addr, endpoint.address.data(), 16) == 0) {
                return ifa->ifa_name;
            }
        }
    }
    return "";
}

void bind_socket_to_device(int fd, const std::string& iface) {
    if (!iface.empty()) {
        setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, iface.c_str(), iface.length() + 1);
    }
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
    if (endpoint.family == AF_INET6) {
        auto* address = reinterpret_cast<sockaddr_in6*>(&result.storage);
        address->sin6_family = AF_INET6;
        address->sin6_port = htons(endpoint.port);
        std::memcpy(&address->sin6_addr, endpoint.address.data(), 16);
        return result;
    }
    fail("Unsupported address family");
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
    fail("Unsupported sockaddr family");
}

std::pair<std::string, std::uint16_t> split_host_port(std::string_view input, std::uint16_t default_port) {
    if (input.empty()) fail("Endpoint cannot be empty");
    if (input.front() == '[') {
        std::size_t end = input.find(']');
        if (end == std::string_view::npos || end + 1 >= input.size() || input[end + 1] != ':') fail("Invalid IPv6 endpoint syntax");
        return {std::string(input.substr(1, end - 1)), static_cast<std::uint16_t>(std::stoul(std::string(input.substr(end + 2))))};
    }
    std::size_t last_colon = input.rfind(':');
    if (last_colon == std::string_view::npos || input.find(':') != last_colon) return {std::string(input), default_port};
    return {std::string(input.substr(0, last_colon)), static_cast<std::uint16_t>(std::stoul(std::string(input.substr(last_colon + 1))))};
}

IpEndpoint resolve_endpoint(const std::string& host, std::uint16_t port) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM; 
    addrinfo* result = nullptr;
    
    std::string port_str = std::to_string(port);
    int rc = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result);
    if (rc != 0) fail(std::string("getaddrinfo failed: ") + gai_strerror(rc));

    std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> guard(result, freeaddrinfo);
    for (addrinfo* current = result; current != nullptr; current = current->ai_next) {
        if (current->ai_family == AF_INET || current->ai_family == AF_INET6) {
            IpEndpoint ep = from_sockaddr(current->ai_addr, static_cast<socklen_t>(current->ai_addrlen));
            ep.port = port;
            return ep;
        }
    }
    fail("No supported address found");
}

void set_reuse_options(int socket_fd) {
    int reuse = 1;
    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#ifdef SO_REUSEPORT
    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
#endif
}

int create_tcp_listener(const IpEndpoint& endpoint) {
    int socket_fd = socket(endpoint.family, SOCK_STREAM, IPPROTO_TCP);
    if (socket_fd < 0) throw system_error("socket failed");
    set_reuse_options(socket_fd);
    SocketAddress address = to_sockaddr(endpoint);
    if (bind(socket_fd, reinterpret_cast<sockaddr*>(&address.storage), address.length) != 0) throw system_error("bind failed");
    if (listen(socket_fd, 32) != 0) throw system_error("listen failed");
    return socket_fd;
}

int create_udp_listener(const IpEndpoint& endpoint, const std::string& iface) {
    int socket_fd = socket(endpoint.family, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd < 0) throw system_error("socket failed");
    set_reuse_options(socket_fd);
    bind_socket_to_device(socket_fd, iface); 
    SocketAddress address = to_sockaddr(endpoint);
    if (bind(socket_fd, reinterpret_cast<sockaddr*>(&address.storage), address.length) != 0) {
        throw system_error("bind failed on UDP");
    }
    return socket_fd;
}

int create_icmp_raw_listener(const IpEndpoint& endpoint) {
    if (endpoint.family != AF_INET) return -1;
    int socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (socket_fd < 0) return -1;
    set_reuse_options(socket_fd);
    IpEndpoint bind_endpoint = endpoint;
    bind_endpoint.port = 0;
    SocketAddress address = to_sockaddr(bind_endpoint);
    if (bind(socket_fd, reinterpret_cast<sockaddr*>(&address.storage), address.length) != 0) {
        close(socket_fd);
        return -1;
    }
    return socket_fd;
}

std::string endpoint_host(const IpEndpoint& endpoint) {
    char buffer[INET6_ADDRSTRLEN]{};
    if (endpoint.family == AF_INET) inet_ntop(AF_INET, endpoint.address.data(), buffer, sizeof(buffer));
    else inet_ntop(AF_INET6, endpoint.address.data(), buffer, sizeof(buffer));
    std::string res(buffer);
    if (endpoint.family == AF_INET6) res = "[" + res + "]";
    return res;
}

std::string endpoint_line(const IpEndpoint& endpoint) {
    return endpoint_host(endpoint) + " " + std::to_string(endpoint.port) + "\n";
}

void send_all(int socket_fd, std::string_view payload) {
    std::size_t offset = 0;
    while (offset < payload.size()) {
        ssize_t written = send(socket_fd, payload.data() + offset, payload.size() - offset, 0);
        if (written <= 0) throw system_error("send failed");
        offset += static_cast<std::size_t>(written);
    }
}

std::string recv_line(int socket_fd, int timeout_ms) {
    std::string line;
    std::array<char, 256> buffer{};
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (line.find('\n') == std::string::npos) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) throw std::runtime_error("recv timed out");
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        pollfd descriptor{socket_fd, POLLIN, 0};
        const int rc = poll(&descriptor, 1, static_cast<int>(remaining.count()));
        if (rc <= 0 || (descriptor.revents & POLLIN) == 0) throw std::runtime_error("recv timed out");
        ssize_t received = recv(socket_fd, buffer.data(), buffer.size(), 0);
        if (received <= 0) break;
        line.append(buffer.data(), static_cast<std::size_t>(received));
        if (line.size() > 4096) fail("Protocol line too long");
    }
    return line.empty() ? "" : line.substr(0, line.find('\n'));
}

std::uint16_t calculate_checksum(const void* data, std::size_t len) {
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    std::uint32_t sum = 0;
    while (len >= 2) {
        sum += static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[0]) << 8) | bytes[1]);
        bytes += 2; len -= 2;
    }
    if (len == 1) sum += static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[0]) << 8);
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return static_cast<std::uint16_t>(~sum);
}

std::uint16_t calculate_icmp_checksum(const void* data, std::size_t len) {
    const auto* ptr = static_cast<const std::uint16_t*>(data);
    std::uint32_t sum = 0;
    while (len > 1) { sum += *ptr++; len -= 2; }
    if (len == 1) sum += *reinterpret_cast<const std::uint8_t*>(ptr);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<std::uint16_t>(~sum);
}

std::uint16_t calculate_udp_checksum_ipv4(const iphdr& ip_header, const udphdr& udp_header, const std::uint8_t* payload, std::size_t payload_len) {
    std::uint32_t sum = 0;
    auto add_buffer = [&](const void* data, std::size_t len) {
        const auto* bytes = static_cast<const std::uint8_t*>(data);
        while (len >= 2) { sum += static_cast<std::uint16_t>((bytes[0] << 8) | bytes[1]); bytes += 2; len -= 2; }
        if (len == 1) sum += static_cast<std::uint16_t>(bytes[0] << 8);
    };
    add_buffer(&ip_header.saddr, 4); add_buffer(&ip_header.daddr, 4);
    std::uint16_t protocol_word = htons(IPPROTO_UDP); 
    add_buffer(&protocol_word, 2); add_buffer(&udp_header.len, 2);
    add_buffer(&udp_header, sizeof(udphdr)); add_buffer(payload, payload_len);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<std::uint16_t>(~sum);
}

// ================= Custom TCP Helper Functions =================

bool try_connect_from_source(const IpEndpoint& source_bind, const IpEndpoint& target, int timeout_ms) {
    int socket_fd = socket(target.family, SOCK_STREAM, IPPROTO_TCP);
    if (socket_fd < 0) return false;
    bool success = false;
    try {
        set_reuse_options(socket_fd);
        SocketAddress source = to_sockaddr(source_bind);
        if (bind(socket_fd, reinterpret_cast<sockaddr*>(&source.storage), source.length) == 0) {
            int flags = fcntl(socket_fd, F_GETFL, 0);
            if (flags >= 0 && fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK) == 0) {
                SocketAddress destination = to_sockaddr(target);
                int rc = connect(socket_fd, reinterpret_cast<sockaddr*>(&destination.storage), destination.length);
                if (rc == 0) success = true;
                else if (errno == EINPROGRESS) {
                    pollfd descriptor{socket_fd, POLLOUT, 0};
                    if (poll(&descriptor, 1, timeout_ms) > 0) {
                        int error = 0; socklen_t err_len = sizeof(error);
                        if (getsockopt(socket_fd, SOL_SOCKET, SO_ERROR, &error, &err_len) == 0 && error == 0) success = true;
                    }
                }
            }
        }
    } catch (...) {}
    close(socket_fd);
    return success;
}

bool try_send_udp_from_source(const IpEndpoint& source_bind, const IpEndpoint& target, std::string_view payload) {
    int socket_fd = socket(target.family, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd < 0) return false;
    bool success = false;
    try {
        set_reuse_options(socket_fd);
        SocketAddress source = to_sockaddr(source_bind);
        bind(socket_fd, reinterpret_cast<sockaddr*>(&source.storage), source.length);
        SocketAddress destination = to_sockaddr(target);
        ssize_t sent = sendto(socket_fd, payload.data(), payload.size(), 0, reinterpret_cast<sockaddr*>(&destination.storage), destination.length);
        success = sent > 0;
    } catch (...) {}
    close(socket_fd);
    return success;
}

std::optional<std::uint16_t> parse_payload_id(std::string_view payload, std::string_view token) {
    const std::string prefix = "VID:" + std::string(token) + ":";
    if (!payload.starts_with(prefix)) return std::nullopt;
    std::string_view id_text = payload.substr(prefix.size());
    const std::size_t newline = id_text.find('\n');
    if (newline != std::string_view::npos) id_text = id_text.substr(0, newline);
    if (id_text.empty()) return std::nullopt;
    try { return static_cast<std::uint16_t>(std::stoi(std::string(id_text))); } catch (...) { return std::nullopt; }
}

std::optional<std::uint16_t> observe_udp_ipv4_id(const IpEndpoint& peer, const IpEndpoint& local, std::string_view token, int timeout_ms) {
    if (peer.family != AF_INET || local.family != AF_INET) return std::nullopt;
    int raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (raw_fd < 0) return std::nullopt;

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    try {
        while (std::chrono::steady_clock::now() < deadline) {
            const int remaining = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count());
            if (remaining <= 0) break;
            pollfd descriptor{raw_fd, POLLIN, 0};
            if (poll(&descriptor, 1, remaining) <= 0 || (descriptor.revents & POLLIN) == 0) continue;

            std::array<std::uint8_t, 2048> buffer{};
            const ssize_t received = recv(raw_fd, buffer.data(), buffer.size(), 0);
            if (received <= static_cast<ssize_t>(sizeof(iphdr) + sizeof(udphdr))) continue;

            const auto* ip_header = reinterpret_cast<const iphdr*>(buffer.data());
            if (ip_header->version != 4 || ip_header->protocol != IPPROTO_UDP) continue;
            const std::size_t ip_header_length = static_cast<std::size_t>(ip_header->ihl) * 4;
            if (ip_header_length < sizeof(iphdr) || received <= static_cast<ssize_t>(ip_header_length + sizeof(udphdr))) continue;
            
            const auto* udp_header = reinterpret_cast<const udphdr*>(buffer.data() + ip_header_length);
            if (ntohs(udp_header->dest) != local.port) continue;
            if (std::memcmp(&ip_header->saddr, peer.address.data(), 4) != 0 || std::memcmp(&ip_header->daddr, local.address.data(), 4) != 0) continue;

            const char* payload_data = reinterpret_cast<const char*>(buffer.data() + ip_header_length + sizeof(udphdr));
            const std::size_t payload_size = static_cast<std::size_t>(received) - ip_header_length - sizeof(udphdr);
            std::optional<std::uint16_t> payload_id = parse_payload_id(std::string_view(payload_data, payload_size), token);
            if (payload_id.has_value()) {
                close(raw_fd);
                return ntohs(ip_header->id);
            }
        }
    } catch (...) {}
    close(raw_fd);
    return std::nullopt;
}

// ================= Custom ICMP / RAW Helper Functions =================

bool send_icmp_echo(int raw_fd, const IpEndpoint& target, std::uint8_t type, std::uint16_t identifier, std::uint16_t sequence, std::string_view payload) {
    std::vector<std::uint8_t> packet(sizeof(icmphdr) + payload.size(), 0);
    auto* icmp = reinterpret_cast<icmphdr*>(packet.data());
    icmp->type = type; icmp->code = 0;
    icmp->un.echo.id = htons(identifier); icmp->un.echo.sequence = htons(sequence);
    if (!payload.empty()) std::memcpy(packet.data() + sizeof(icmphdr), payload.data(), payload.size());
    icmp->checksum = calculate_icmp_checksum(packet.data(), packet.size());
    SocketAddress destination = to_sockaddr(target);
    ssize_t sent = sendto(raw_fd, packet.data(), packet.size(), 0, reinterpret_cast<sockaddr*>(&destination.storage), destination.length);
    return sent == static_cast<ssize_t>(packet.size());
}

bool send_ipv4_icmp_error(const IpEndpoint& peer, const IpEndpoint& local, int protocol) {
    if (peer.family == AF_INET) {
        int raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (raw_fd < 0) return false;

        std::vector<std::uint8_t> packet(sizeof(icmphdr) + sizeof(iphdr) + 8, 0);
        auto* icmp = reinterpret_cast<icmphdr*>(packet.data());
        icmp->type = ICMP_DEST_UNREACH; icmp->code = ICMP_PORT_UNREACH; 

        auto* inner_ip = reinterpret_cast<iphdr*>(packet.data() + sizeof(icmphdr));
        inner_ip->ihl = 5; inner_ip->version = 4; inner_ip->tot_len = htons(sizeof(iphdr) + 8);
        inner_ip->id = htons(0x1234); inner_ip->ttl = 64; inner_ip->protocol = protocol; 
        std::memcpy(&inner_ip->saddr, peer.address.data(), 4);
        std::memcpy(&inner_ip->daddr, local.address.data(), 4);
        inner_ip->check = calculate_checksum(inner_ip, sizeof(iphdr));

        std::uint8_t* inner_l4 = packet.data() + sizeof(icmphdr) + sizeof(iphdr);
        std::uint16_t sport = htons(peer.port), dport = htons(local.port);
        std::memcpy(inner_l4, &sport, 2); std::memcpy(inner_l4 + 2, &dport, 2);
        icmp->checksum = calculate_checksum(packet.data(), packet.size());

        sockaddr_in dest{}; dest.sin_family = AF_INET;
        std::memcpy(&dest.sin_addr, peer.address.data(), 4);
        ssize_t sent = sendto(raw_fd, packet.data(), packet.size(), 0, reinterpret_cast<sockaddr*>(&dest), sizeof(dest));
        close(raw_fd);
        return sent == static_cast<ssize_t>(packet.size());
    }
    return false;
}

bool send_ipv4_icmp_error_variant(const IpEndpoint& peer, const IpEndpoint& outer_source,
                                  const IpEndpoint& inner_source, const IpEndpoint& inner_destination,
                                  std::uint16_t inner_source_port, std::uint16_t inner_destination_port,
                                  std::uint16_t marker, IcmpErrorVariant variant) {
    if (peer.family != AF_INET || outer_source.family != AF_INET) return false;
    int raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_fd < 0) return false;
    int enable = 1; setsockopt(raw_fd, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

    std::vector<std::uint8_t> packet(sizeof(iphdr) + sizeof(icmphdr) + sizeof(iphdr) + sizeof(udphdr), 0);
    auto* outer_ip = reinterpret_cast<iphdr*>(packet.data());
    outer_ip->ihl = 5; outer_ip->version = 4; outer_ip->tot_len = htons(packet.size());
    outer_ip->ttl = 64; outer_ip->protocol = IPPROTO_ICMP;
    std::memcpy(&outer_ip->saddr, outer_source.address.data(), 4);
    std::memcpy(&outer_ip->daddr, peer.address.data(), 4);
    outer_ip->check = calculate_checksum(outer_ip, sizeof(iphdr));

    auto* icmp = reinterpret_cast<icmphdr*>(packet.data() + sizeof(iphdr));
    icmp->type = ICMP_DEST_UNREACH; icmp->code = ICMP_PORT_UNREACH;

    auto* inner_ip = reinterpret_cast<iphdr*>(packet.data() + sizeof(iphdr) + sizeof(icmphdr));
    inner_ip->ihl = 5; inner_ip->version = 4; inner_ip->tot_len = htons(sizeof(iphdr) + sizeof(udphdr));
    inner_ip->id = htons(marker); inner_ip->ttl = 64; inner_ip->protocol = IPPROTO_UDP;
    std::memcpy(&inner_ip->saddr, inner_source.address.data(), 4);
    std::memcpy(&inner_ip->daddr, inner_destination.address.data(), 4);
    inner_ip->check = calculate_checksum(inner_ip, sizeof(iphdr));

    auto* inner_udp = reinterpret_cast<udphdr*>(packet.data() + sizeof(iphdr) + sizeof(icmphdr) + sizeof(iphdr));
    inner_udp->source = htons(inner_source_port); inner_udp->dest = htons(inner_destination_port);
    inner_udp->len = htons(sizeof(udphdr));
    inner_udp->check = calculate_udp_checksum_ipv4(*inner_ip, *inner_udp, nullptr, 0);
    if (inner_udp->check == 0) inner_udp->check = 0xFFFF;

    if (variant == IcmpErrorVariant::BadInnerIpChecksum) inner_ip->check ^= htons(0x00FF);
    else if (variant == IcmpErrorVariant::BadUdpChecksum) inner_udp->check ^= htons(0x00FF);

    icmp->checksum = calculate_checksum(icmp, packet.size() - sizeof(iphdr));
    if (variant == IcmpErrorVariant::BadOuterChecksum) icmp->checksum ^= htons(0x00FF);

    sockaddr_in dest{}; dest.sin_family = AF_INET;
    std::memcpy(&dest.sin_addr, peer.address.data(), 4);
    ssize_t sent = sendto(raw_fd, packet.data(), packet.size(), 0, reinterpret_cast<sockaddr*>(&dest), sizeof(dest));
    close(raw_fd);
    return sent == static_cast<ssize_t>(packet.size());
}

bool send_out_of_order_fragmented_udp(const IpEndpoint& peer, const IpEndpoint& local) {
    if (peer.family != AF_INET || local.family != AF_INET) return false;
    int raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_fd < 0) return false;
    int enable = 1; setsockopt(raw_fd, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

    constexpr std::size_t first_payload_size = 16;
    constexpr std::size_t second_payload_size = kRfc4787OutOfOrderFragmentPayload.size() - first_payload_size;
    
    iphdr ip_base{};
    ip_base.ihl = 5; ip_base.version = 4; ip_base.id = htons(0x4A87); ip_base.ttl = 64; ip_base.protocol = IPPROTO_UDP;
    std::memcpy(&ip_base.saddr, local.address.data(), 4); std::memcpy(&ip_base.daddr, peer.address.data(), 4);

    udphdr udp{};
    udp.source = htons(local.port); udp.dest = htons(peer.port);
    udp.len = htons(sizeof(udphdr) + kRfc4787OutOfOrderFragmentPayload.size());
    udp.check = calculate_udp_checksum_ipv4(ip_base, udp, reinterpret_cast<const std::uint8_t*>(kRfc4787OutOfOrderFragmentPayload.data()), kRfc4787OutOfOrderFragmentPayload.size());
    if (udp.check == 0) udp.check = 0xFFFF;

    std::vector<std::uint8_t> first_fragment(sizeof(iphdr) + sizeof(udphdr) + first_payload_size, 0);
    auto* first_ip = reinterpret_cast<iphdr*>(first_fragment.data());
    *first_ip = ip_base; first_ip->tot_len = htons(first_fragment.size());
    first_ip->frag_off = htons(IP_MF); first_ip->check = calculate_checksum(first_ip, sizeof(iphdr));
    std::memcpy(first_fragment.data() + sizeof(iphdr), &udp, sizeof(udphdr));
    std::memcpy(first_fragment.data() + sizeof(iphdr) + sizeof(udphdr), kRfc4787OutOfOrderFragmentPayload.data(), first_payload_size);

    std::vector<std::uint8_t> second_fragment(sizeof(iphdr) + second_payload_size, 0);
    auto* second_ip = reinterpret_cast<iphdr*>(second_fragment.data());
    *second_ip = ip_base; second_ip->tot_len = htons(second_fragment.size());
    second_ip->frag_off = htons(static_cast<std::uint16_t>((sizeof(udphdr) + first_payload_size) / 8));
    second_ip->check = calculate_checksum(second_ip, sizeof(iphdr));
    std::memcpy(second_fragment.data() + sizeof(iphdr), kRfc4787OutOfOrderFragmentPayload.data() + first_payload_size, second_payload_size);

    sockaddr_in dest{}; dest.sin_family = AF_INET;
    std::memcpy(&dest.sin_addr, peer.address.data(), 4);
    
    ssize_t second_sent = sendto(raw_fd, second_fragment.data(), second_fragment.size(), 0, reinterpret_cast<sockaddr*>(&dest), sizeof(dest));
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    ssize_t first_sent = sendto(raw_fd, first_fragment.data(), first_fragment.size(), 0, reinterpret_cast<sockaddr*>(&dest), sizeof(dest));
    close(raw_fd);
    return first_sent == static_cast<ssize_t>(first_fragment.size()) && second_sent == static_cast<ssize_t>(second_fragment.size());
}

// ================= Handler Functions =================

std::optional<std::string> parse_rfc5508_mapping_token(std::string_view payload) {
    constexpr std::string_view prefix = "RFC5508-M:";
    if (!payload.starts_with(prefix)) return std::nullopt;
    std::string token(payload.substr(prefix.size()));
    const std::size_t newline = token.find('\n');
    if (newline != std::string::npos) token = token.substr(0, newline);
    if (token.empty()) return std::nullopt;
    return token;
}

void handle_icmp_packet(int raw_fd, IcmpRawContext& icmp_ctx) {
    std::array<std::uint8_t, 4096> buffer{};
    sockaddr_storage peer{}; socklen_t peer_length = sizeof(peer);
    const ssize_t received = recvfrom(raw_fd, buffer.data(), buffer.size(), 0, reinterpret_cast<sockaddr*>(&peer), &peer_length);
    if (received <= static_cast<ssize_t>(sizeof(iphdr) + sizeof(icmphdr))) return;

    IpEndpoint peer_endpoint = from_sockaddr(reinterpret_cast<sockaddr*>(&peer), peer_length);
    const auto* ip_header = reinterpret_cast<const iphdr*>(buffer.data());
    if (ip_header->version != 4 || ip_header->protocol != IPPROTO_ICMP) return;
    
    const std::size_t ip_header_length = static_cast<std::size_t>(ip_header->ihl) * 4;
    if (received <= static_cast<ssize_t>(ip_header_length + sizeof(icmphdr))) return;

    const auto* icmp = reinterpret_cast<const icmphdr*>(buffer.data() + ip_header_length);
    if (icmp->type == ICMP_DEST_UNREACH && icmp->code == ICMP_PORT_UNREACH) {
        const std::size_t min_size = ip_header_length + sizeof(icmphdr) + sizeof(iphdr) + sizeof(udphdr);
        if (static_cast<std::size_t>(received) >= min_size) {
            const auto* inner_ip = reinterpret_cast<const iphdr*>(buffer.data() + ip_header_length + sizeof(icmphdr));
            if (inner_ip->version == 4 && inner_ip->protocol == IPPROTO_UDP) {
                uint16_t marker = ntohs(inner_ip->id);
                std::cout << "[ICMP-RAW] Port Unreach from " << endpoint_host(peer_endpoint) << " | Marker=" << marker << "\n";
                std::lock_guard<std::mutex> lock(icmp_ctx.observed_error_markers_mutex);
                icmp_ctx.observed_error_markers.insert(marker);
            }
        }
        return;
    }
    if (icmp->type != ICMP_ECHO || icmp->code != 0) return;

    const char* payload_data = reinterpret_cast<const char*>(buffer.data() + ip_header_length + sizeof(icmphdr));
    const std::size_t payload_size = static_cast<std::size_t>(received) - ip_header_length - sizeof(icmphdr);
    std::string_view payload(payload_data, payload_size);

    if (std::optional<std::string> token = parse_rfc5508_mapping_token(payload); token.has_value()) {
        std::cout << "[ICMP-RAW] Echo Req from " << endpoint_host(peer_endpoint) << " | Token=" << *token << " | MapQuery=" << ntohs(icmp->un.echo.id) << "\n";
        IcmpMappingRecord record;
        record.peer_host = endpoint_host(peer_endpoint);
        record.mapped_query = ntohs(icmp->un.echo.id);
        std::lock_guard<std::mutex> lock(icmp_ctx.mappings_mutex);
        icmp_ctx.mappings[*token] = record;
    }

    send_icmp_echo(raw_fd, peer_endpoint, ICMP_ECHOREPLY, ntohs(icmp->un.echo.id), ntohs(icmp->un.echo.sequence), std::string(payload));
}

void handle_tcp_client(int client_fd, const StunNode& primary, const StunNode& secondary, IcmpRawContext& icmp_ctx, int timeout_ms, int syn_delay_ms) {
    try {
        sockaddr_storage peer{}; socklen_t peer_length = sizeof(peer);
        if (getpeername(client_fd, reinterpret_cast<sockaddr*>(&peer), &peer_length) != 0) throw system_error("getpeername failed");
        IpEndpoint peer_endpoint = from_sockaddr(reinterpret_cast<sockaddr*>(&peer), peer_length);
        
        // 线程安全的打印助手
        auto log_tcp = [&](const std::string& cmd, const std::string& extra = "") {
            std::ostringstream oss;
            oss << "[TCP-CUST] Req from " << endpoint_host(peer_endpoint) << ":" << peer_endpoint.port << " | Cmd: " << cmd;
            if (!extra.empty()) oss << " | " << extra;
            oss << "\n";
            std::cout << oss.str();
        };

        log_tcp("NEW_CONNECTION");

        while (true) {
            std::string command = recv_line(client_fd, 30000);
            if (command.empty()) {
                log_tcp("DISCONNECT");
                return;
            }
            
            if (command == "M") {
                log_tcp("M (Mapping Test)");
                send_all(client_fd, endpoint_line(peer_endpoint)); 
                continue;
            }
            if (command == "F") {
                IpEndpoint p_src = primary.bind_ep; p_src.port = 0;
                IpEndpoint s_src = secondary.bind_ep; s_src.port = 0;
                bool p_ok = try_connect_from_source(p_src, peer_endpoint, timeout_ms);
                bool s_ok = try_connect_from_source(s_src, peer_endpoint, timeout_ms);
                std::string res = std::string("P=") + (p_ok ? "1" : "0") + " S=" + (s_ok ? "1" : "0");
                log_tcp("F (Filter Probe)", res);
                send_all(client_fd, res + "\n");
                continue;
            }
            if (command == "S") {
                IpEndpoint imm_src = secondary.bind_ep; imm_src.port = 0;
                IpEndpoint del_src = primary.bind_ep; del_src.port = 0;
                bool imm_ok = try_connect_from_source(imm_src, peer_endpoint, timeout_ms);
                std::this_thread::sleep_for(std::chrono::milliseconds(syn_delay_ms));
                bool del_ok = try_connect_from_source(del_src, peer_endpoint, timeout_ms);
                std::string res = std::string("I=") + (imm_ok ? "1" : "0") + " D=" + (del_ok ? "1" : "0");
                log_tcp("S (SYN Delay Test)", res);
                send_all(client_fd, res + "\n");
                continue;
            }
            if (command == "U") {
                IpEndpoint udp_src = primary.bind_ep; udp_src.port = 0;
                bool sent = try_send_udp_from_source(udp_src, peer_endpoint, kRfc7857UdpProbePayload);
                std::string res = std::string("R=") + (sent ? "1" : "0");
                log_tcp("U (UDP Probe)", res);
                send_all(client_fd, res + "\n");
                continue;
            }
            if (command.rfind("C ", 0) == 0) {
                const std::string ep_str = command.substr(2);
                auto [target_host, target_port] = split_host_port(ep_str, 0);
                IpEndpoint target = resolve_endpoint(target_host, target_port);
                IpEndpoint src = primary.bind_ep; src.port = 0;
                bool connected = try_connect_from_source(src, target, timeout_ms);
                std::string res = std::string("R=") + (connected ? "1" : "0");
                log_tcp("C (Connect Target)", target_host + ":" + std::to_string(target_port) + " -> " + res);
                send_all(client_fd, res + "\n");
                continue;
            }
            if (command == "I") {
                sockaddr_storage local_addr{}; socklen_t local_length = sizeof(local_addr);
                getsockname(client_fd, reinterpret_cast<sockaddr*>(&local_addr), &local_length);
                IpEndpoint local_endpoint = from_sockaddr(reinterpret_cast<sockaddr*>(&local_addr), local_length);
                bool icmp_sent = send_ipv4_icmp_error(peer_endpoint, local_endpoint, IPPROTO_TCP);
                std::string res = std::string("I=") + (icmp_sent ? "1" : "0");
                log_tcp("I (ICMP TCP Inject)", res);
                send_all(client_fd, res + "\n");
                continue;
            }
            if (command.rfind("V ", 0) == 0) {
                std::string token = command.substr(2);
                sockaddr_storage local_addr{}; socklen_t local_length = sizeof(local_addr);
                getsockname(client_fd, reinterpret_cast<sockaddr*>(&local_addr), &local_length);
                IpEndpoint local_endpoint = from_sockaddr(reinterpret_cast<sockaddr*>(&local_addr), local_length);

                std::optional<std::uint16_t> obs_id = observe_udp_ipv4_id(peer_endpoint, local_endpoint, token, timeout_ms);
                std::string res = obs_id.has_value() ? ("V=" + std::to_string(*obs_id)) : "V=-1";
                log_tcp("V (Verify ID)", "Token=" + token + " -> " + res);
                send_all(client_fd, res + "\n");
                continue;
            }
            if (command.rfind("IE ", 0) == 0) {
                std::istringstream stream(command);
                std::string op, target_literal;
                std::uint16_t m_out = 0, m_in = 0, m_udp = 0;
                if (!(stream >> op >> target_literal >> m_out >> m_in >> m_udp)) {
                    log_tcp("IE (ICMP Error Variants)", "Invalid Params");
                    send_all(client_fd, "E=0\n"); continue;
                }
                auto [target_host, target_port] = split_host_port(target_literal, 0);
                IpEndpoint target = resolve_endpoint(target_host, target_port);
                if (target.family != AF_INET || peer_endpoint.family != AF_INET) { 
                    log_tcp("IE (ICMP Error Variants)", "Family mismatch");
                    send_all(client_fd, "E=0\n"); continue; 
                }

                bool s_out = send_ipv4_icmp_error_variant(target, primary.bind_ep, peer_endpoint, primary.pub_ep, target.port, primary.pub_ep.port, m_out, IcmpErrorVariant::BadOuterChecksum);
                bool s_in = send_ipv4_icmp_error_variant(target, primary.bind_ep, peer_endpoint, primary.pub_ep, target.port, primary.pub_ep.port, m_in, IcmpErrorVariant::BadInnerIpChecksum);
                bool s_udp = send_ipv4_icmp_error_variant(target, primary.bind_ep, peer_endpoint, primary.pub_ep, target.port, primary.pub_ep.port, m_udp, IcmpErrorVariant::BadUdpChecksum);
                std::string res = std::string("E=") + ((s_out && s_in && s_udp) ? "1" : "0");
                log_tcp("IE (ICMP Error Variants)", res);
                send_all(client_fd, res + "\n");
                continue;
            }
            if (command == "IRR") {
                { std::lock_guard<std::mutex> lock(icmp_ctx.observed_error_markers_mutex); icmp_ctx.observed_error_markers.clear(); }
                log_tcp("IRR (ICMP Reset Markers)");
                send_all(client_fd, "R=1\n"); continue;
            }
            if (command.rfind("IR ", 0) == 0) {
                std::istringstream stream(command); std::string op; std::uint16_t marker = 0;
                if (!(stream >> op >> marker)) { 
                    log_tcp("IR (ICMP Check Marker)", "Invalid Params");
                    send_all(client_fd, "R=0\n"); continue; 
                }
                bool seen = false;
                { std::lock_guard<std::mutex> lock(icmp_ctx.observed_error_markers_mutex); seen = icmp_ctx.observed_error_markers.contains(marker); }
                std::string res = std::string("R=") + (seen ? "1" : "0");
                log_tcp("IR (ICMP Check Marker)", "Marker=" + std::to_string(marker) + " -> " + res);
                send_all(client_fd, res + "\n"); continue;
            }
            if (command.rfind("IM ", 0) == 0) {
                const std::string token = command.substr(3);
                std::optional<IcmpMappingRecord> record;
                {
                    std::lock_guard<std::mutex> lock(icmp_ctx.mappings_mutex);
                    auto it = icmp_ctx.mappings.find(token);
                    if (it != icmp_ctx.mappings.end()) record = it->second;
                }
                if (!record.has_value()) { 
                    log_tcp("IM (ICMP Get Mapping)", token + " -> Not Found");
                    send_all(client_fd, "ERR\n"); continue; 
                }
                log_tcp("IM (ICMP Get Mapping)", token + " -> Found");
                send_all(client_fd, "M " + record->peer_host + " " + std::to_string(record->mapped_query) + "\n");
                continue;
            }
            if (command.rfind("IF ", 0) == 0) {
                std::istringstream stream(command); std::string op, role, token; std::uint16_t probe_query = 0;
                if (!(stream >> op >> role >> token >> probe_query) || role.size() != 1) { 
                    log_tcp("IF (ICMP Fragment/Echo)", "Invalid Params");
                    send_all(client_fd, "F=0\n"); continue; 
                }
                std::optional<IcmpMappingRecord> record;
                {
                    std::lock_guard<std::mutex> lock(icmp_ctx.mappings_mutex);
                    auto it = icmp_ctx.mappings.find(token);
                    if (it != icmp_ctx.mappings.end()) record = it->second;
                }
                if (!record.has_value()) { 
                    log_tcp("IF (ICMP Fragment/Echo)", token + " -> No Mapping");
                    send_all(client_fd, "F=0\n"); continue; 
                }

                int raw_fd = (role[0] == 'P') ? icmp_ctx.primary_socket : ((role[0] == 'S') ? icmp_ctx.secondary_socket : -1);
                if (raw_fd < 0) { 
                    log_tcp("IF (ICMP Fragment/Echo)", "Invalid Socket");
                    send_all(client_fd, "F=0\n"); continue; 
                }
                IpEndpoint target = resolve_endpoint(record->peer_host, 0); target.port = 0;
                const std::string payload = "RFC5508-F:" + token + ":" + std::to_string(probe_query);
                bool sent = send_icmp_echo(raw_fd, target, ICMP_ECHO, record->mapped_query, probe_query, payload);
                std::string res = std::string("F=") + (sent ? "1" : "0");
                log_tcp("IF (ICMP Fragment/Echo)", "Token=" + token + " Role=" + role + " -> " + res);
                send_all(client_fd, res + "\n");
                continue;
            }
            
            log_tcp("UNKNOWN_CMD", command);
            send_all(client_fd, "ERR\n");
        }
    } catch (...) {}
}

void append_stun_address(std::vector<uint8_t>& out, uint16_t attr_type, const IpEndpoint& ep, const uint8_t* tx_id, bool xor_mapped) {
    out.push_back(attr_type >> 8); 
    out.push_back(attr_type & 0xFF);
    uint16_t len = (ep.family == AF_INET) ? 8 : 20;
    out.push_back(len >> 8); 
    out.push_back(len & 0xFF);
    
    out.push_back(0); 
    out.push_back((ep.family == AF_INET) ? 1 : 2); 

    uint16_t port = ep.port;
    if (xor_mapped && tx_id) {
        port ^= (static_cast<uint16_t>(tx_id[0]) << 8) | tx_id[1];
    }
    out.push_back(port >> 8); 
    out.push_back(port & 0xFF);

    if (ep.family == AF_INET) {
        for (int i = 0; i < 4; ++i) {
            uint8_t val = ep.address[i];
            if (xor_mapped && tx_id) val ^= tx_id[i]; 
            out.push_back(val);
        }
    } else {
        for (int i = 0; i < 16; ++i) {
            uint8_t val = ep.address[i];
            if (xor_mapped && tx_id) val ^= tx_id[i]; 
            out.push_back(val);
        }
    }
}

void handle_udp_packet(int rx_idx, const StunContext& ctx) {
    const StunNode& rx_node = ctx.nodes[rx_idx];
    int udp_fd = rx_node.fd;
    if (udp_fd < 0) return;

    sockaddr_storage peer{}; socklen_t peer_length = sizeof(peer);
    std::vector<char> buffer(4096);
    ssize_t received = recvfrom(udp_fd, buffer.data(), buffer.size(), 0, reinterpret_cast<sockaddr*>(&peer), &peer_length);
    if (received <= 0) return;

    IpEndpoint peer_endpoint = from_sockaddr(reinterpret_cast<sockaddr*>(&peer), peer_length);

    // 1. STUN 请求解析
    if (received >= 20 && (buffer[0] & 0xC0) == 0) {
        uint16_t msg_type = static_cast<uint16_t>((static_cast<uint8_t>(buffer[0]) << 8) | static_cast<uint8_t>(buffer[1]));
        uint16_t msg_length = static_cast<uint16_t>((static_cast<uint8_t>(buffer[2]) << 8) | static_cast<uint8_t>(buffer[3]));
        
        if (msg_type == 0x0001) { // Binding Request
            bool change_ip = false, change_port = false;
            size_t offset = 20;
            
            while (offset + 4 <= static_cast<size_t>(received) && offset + 4 <= 20U + msg_length) {
                uint16_t attr_type = static_cast<uint16_t>((static_cast<uint8_t>(buffer[offset]) << 8) | static_cast<uint8_t>(buffer[offset + 1]));
                uint16_t attr_len = static_cast<uint16_t>((static_cast<uint8_t>(buffer[offset + 2]) << 8) | static_cast<uint8_t>(buffer[offset + 3]));
                size_t next_offset = offset + 4 + ((attr_len + 3) & ~3);
                if (next_offset > static_cast<size_t>(received) || next_offset > 20U + msg_length) break;

                if (attr_type == 0x0003 && attr_len == 4) { // CHANGE-REQUEST
                    uint32_t change_flags = 0;
                    std::memcpy(&change_flags, buffer.data() + offset + 4, 4); 
                    change_flags = ntohl(change_flags);
                    change_ip = (change_flags & 0x0004); 
                    change_port = (change_flags & 0x0002); 
                }
                offset = next_offset;
            }

            int ip_bit = rx_idx & 2;     
            int port_bit = rx_idx & 1;   
            if (change_ip) ip_bit ^= 2;
            if (change_port) port_bit ^= 1;
            int reply_idx = ip_bit | port_bit;
            int other_idx = rx_idx ^ 3;

            const StunNode& reply_node = ctx.nodes[reply_idx];
            const StunNode& other_node = ctx.nodes[other_idx];

            std::vector<uint8_t> stun_resp(20, 0);
            stun_resp[0] = 0x01; stun_resp[1] = 0x01; 
            std::memcpy(&stun_resp[4], buffer.data() + 4, 16); 
            const uint8_t* tx_id = reinterpret_cast<const uint8_t*>(buffer.data() + 4); 
            
            bool is_rfc5389 = (tx_id[0] == 0x21 && tx_id[1] == 0x12 && tx_id[2] == 0xA4 && tx_id[3] == 0x42);

            std::cout << "[STUN] Req from " << endpoint_host(peer_endpoint) << ":" << peer_endpoint.port 
                      << " | Rx: " << rx_node.pub_ep.port << " (IP-" << (rx_idx & 2 ? "2" : "1") << ")"
                      << " | ChgIP=" << change_ip << " ChgPort=" << change_port 
                      << " | Reply: " << endpoint_host(reply_node.pub_ep) << ":" << reply_node.pub_ep.port 
                      << (reply_node.iface_name.empty() ? "" : (" via " + reply_node.iface_name)) << "\n";

            append_stun_address(stun_resp, 0x0001, peer_endpoint, tx_id, false); 
            append_stun_address(stun_resp, 0x0004, reply_node.pub_ep, tx_id, false);  
            append_stun_address(stun_resp, 0x0005, other_node.pub_ep, tx_id, false); 
            append_stun_address(stun_resp, 0x802b, reply_node.pub_ep, tx_id, false);  
            append_stun_address(stun_resp, 0x802c, other_node.pub_ep, tx_id, false); 

            if (is_rfc5389) {
                append_stun_address(stun_resp, 0x0020, peer_endpoint, tx_id, true);  
            }

            uint16_t total_attr_len = stun_resp.size() - 20;
            stun_resp[2] = total_attr_len >> 8; 
            stun_resp[3] = total_attr_len & 0xFF;

            sendto(reply_node.fd, stun_resp.data(), stun_resp.size(), 0, reinterpret_cast<sockaddr*>(&peer), peer_length);
            return;
        }
    }

    // 2. 映射地址测试
    if (received >= 1 && buffer[0] == 'M') {
        std::cout << "[UDP-CUST] Req from " << endpoint_host(peer_endpoint) << ":" << peer_endpoint.port << " | Cmd: M (Mapping Test)\n";
        std::string payload = endpoint_line(peer_endpoint);
        sendto(udp_fd, payload.data(), payload.size(), 0, reinterpret_cast<sockaddr*>(&peer), peer_length);
        return;
    }

    // 3. 配置拓扑下发指令 (Config): 强行返回 Node0 (IP1) 和 Node2 (IP2)，两者的 Port 完全一致，以便完美兼容老客户端
    if (received >= 1 && buffer[0] == 'C') {
        std::cout << "[UDP-CUST] Req from " << endpoint_host(peer_endpoint) << ":" << peer_endpoint.port << " | Cmd: C (Config Matrix Download)\n";
        std::string payload = 
            "PRIMARY " + endpoint_host(ctx.nodes[0].pub_ep) + " " + std::to_string(ctx.nodes[0].pub_ep.port) + "\n" +
            "SECONDARY " + endpoint_host(ctx.nodes[2].pub_ep) + " " + std::to_string(ctx.nodes[2].pub_ep.port) + "\n";
        
        sendto(udp_fd, payload.data(), payload.size(), 0, reinterpret_cast<sockaddr*>(&peer), peer_length);
        return;
    }

    // 4. ICMP 注入测试
    if (received >= 1 && buffer[0] == 'I') {
        bool sent = send_ipv4_icmp_error(peer_endpoint, rx_node.bind_ep, IPPROTO_UDP);
        std::cout << "[UDP-CUST] Req from " << endpoint_host(peer_endpoint) << ":" << peer_endpoint.port << " | Cmd: I (ICMP UDP Inject) | Sent=" << sent << "\n";
        std::string reply = std::string("I=") + (sent ? "1" : "0") + "\n";
        sendto(udp_fd, reply.data(), reply.size(), 0, reinterpret_cast<sockaddr*>(&peer), peer_length);
        return;
    }

    // 5. 乱序分片 UDP 测试
    if (received >= 1 && buffer[0] == 'O') {
        bool sent = send_out_of_order_fragmented_udp(peer_endpoint, rx_node.bind_ep);
        std::cout << "[UDP-CUST] Req from " << endpoint_host(peer_endpoint) << ":" << peer_endpoint.port << " | Cmd: O (Out-of-order Fragment) | Sent=" << sent << "\n";
        std::string reply = std::string("O=") + (sent ? "1" : "0") + "\n";
        sendto(udp_fd, reply.data(), reply.size(), 0, reinterpret_cast<sockaddr*>(&peer), peer_length);
        return;
    }
}

} // namespace

int main(int argc, char** argv) {
    try {
        std::string bind_ip1 = "0.0.0.0", pub_ip1 = "";
        std::string bind_ip2 = "0.0.0.0", pub_ip2 = "";
        uint16_t port1 = 3478, port2 = 3479;
        int probe_timeout_ms = 1200;
        int syn_delay_ms = 350;

        for (int index = 1; index < argc; ++index) {
            std::string token = argv[index];
            if (token == "--bind-ip1") bind_ip1 = argv[++index];
            else if (token == "--pub-ip1") pub_ip1 = argv[++index];
            else if (token == "--bind-ip2") bind_ip2 = argv[++index];
            else if (token == "--pub-ip2") pub_ip2 = argv[++index];
            else if (token == "--port1") port1 = std::stoi(argv[++index]);
            else if (token == "--port2") port2 = std::stoi(argv[++index]);
            else if (token == "--probe-timeout-ms") probe_timeout_ms = std::stoi(argv[++index]);
            else if (token == "--syn-delay-ms") syn_delay_ms = std::stoi(argv[++index]);
        }

        if (pub_ip1.empty() || pub_ip2.empty()) fail("Both --pub-ip1 and --pub-ip2 are required.");

        StunContext stun_ctx;
        stun_ctx.nodes[0].bind_ep = resolve_endpoint(bind_ip1, port1); stun_ctx.nodes[0].pub_ep = resolve_endpoint(pub_ip1, port1);
        stun_ctx.nodes[1].bind_ep = resolve_endpoint(bind_ip1, port2); stun_ctx.nodes[1].pub_ep = resolve_endpoint(pub_ip1, port2);
        stun_ctx.nodes[2].bind_ep = resolve_endpoint(bind_ip2, port1); stun_ctx.nodes[2].pub_ep = resolve_endpoint(pub_ip2, port1);
        stun_ctx.nodes[3].bind_ep = resolve_endpoint(bind_ip2, port2); stun_ctx.nodes[3].pub_ep = resolve_endpoint(pub_ip2, port2);

        ensure_icmp_conntrack_bypass();
        try_disable_kernel_icmp_echo_auto_reply();

        std::cout << "Starting STUN 4-Socket Matrix (UDP) and TCP/ICMP Endpoints...\n";
        for (int i = 0; i < 4; ++i) {
            stun_ctx.nodes[i].iface_name = get_interface_name(stun_ctx.nodes[i].bind_ep);
            stun_ctx.nodes[i].fd = create_udp_listener(stun_ctx.nodes[i].bind_ep, stun_ctx.nodes[i].iface_name);
            
            std::cout << "  Node " << i << ": Bind=" << endpoint_host(stun_ctx.nodes[i].bind_ep) << ":" << stun_ctx.nodes[i].bind_ep.port 
                      << "  Public=" << endpoint_host(stun_ctx.nodes[i].pub_ep) << ":" << stun_ctx.nodes[i].pub_ep.port;
            if (!stun_ctx.nodes[i].iface_name.empty()) std::cout << "  (Device: " << stun_ctx.nodes[i].iface_name << ")\n";
            else std::cout << "  (Device: Default)\n";
        }

        int primary_tcp_fd = create_tcp_listener(stun_ctx.nodes[0].bind_ep);
        int secondary_tcp_fd = create_tcp_listener(stun_ctx.nodes[2].bind_ep);

        if (stun_ctx.nodes[0].bind_ep.family == AF_INET) {
            stun_ctx.icmp_ctx.primary_socket = create_icmp_raw_listener(stun_ctx.nodes[0].bind_ep);
            stun_ctx.icmp_ctx.secondary_socket = create_icmp_raw_listener(stun_ctx.nodes[2].bind_ep);
        }

        std::cout << "\n>>> Server fully ready! Logs will appear below...\n";
        std::cout << "========================================================\n";

        while (true) {
            std::array<pollfd, 8> descriptors{{
                {primary_tcp_fd, POLLIN, 0},
                {secondary_tcp_fd, POLLIN, 0},
                {stun_ctx.nodes[0].fd, POLLIN, 0},
                {stun_ctx.nodes[1].fd, POLLIN, 0},
                {stun_ctx.nodes[2].fd, POLLIN, 0},
                {stun_ctx.nodes[3].fd, POLLIN, 0},
                {stun_ctx.icmp_ctx.primary_socket, POLLIN, 0},
                {stun_ctx.icmp_ctx.secondary_socket, POLLIN, 0}
            }};
            
            if (poll(descriptors.data(), descriptors.size(), -1) < 0) throw system_error("poll failed");

            // 1. 处理自定义 TCP 连接
            if (descriptors[0].revents & POLLIN) {
                sockaddr_storage client{}; socklen_t len = sizeof(client);
                int client_fd = accept(primary_tcp_fd, reinterpret_cast<sockaddr*>(&client), &len);
                if (client_fd >= 0) {
                    std::thread([client_fd, primary = stun_ctx.nodes[0], secondary = stun_ctx.nodes[2], &icmp_ctx = stun_ctx.icmp_ctx, probe_timeout_ms, syn_delay_ms]() {
                        handle_tcp_client(client_fd, primary, secondary, const_cast<IcmpRawContext&>(icmp_ctx), probe_timeout_ms, syn_delay_ms);
                        close(client_fd);
                    }).detach();
                }
            }
            if (descriptors[1].revents & POLLIN) {
                sockaddr_storage client{}; socklen_t len = sizeof(client);
                int client_fd = accept(secondary_tcp_fd, reinterpret_cast<sockaddr*>(&client), &len);
                if (client_fd >= 0) {
                    std::thread([client_fd, primary = stun_ctx.nodes[0], secondary = stun_ctx.nodes[2], &icmp_ctx = stun_ctx.icmp_ctx, probe_timeout_ms, syn_delay_ms]() {
                        handle_tcp_client(client_fd, primary, secondary, const_cast<IcmpRawContext&>(icmp_ctx), probe_timeout_ms, syn_delay_ms);
                        close(client_fd);
                    }).detach();
                }
            }

            // 2. 处理 STUN 及自定义 UDP
            for (int i = 0; i < 4; ++i) {
                if (descriptors[2 + i].revents & POLLIN) handle_udp_packet(i, stun_ctx);
            }

            // 3. 处理 ICMP 回显及映射
            if (stun_ctx.icmp_ctx.primary_socket >= 0 && (descriptors[6].revents & POLLIN)) {
                handle_icmp_packet(stun_ctx.icmp_ctx.primary_socket, stun_ctx.icmp_ctx);
            }
            if (stun_ctx.icmp_ctx.secondary_socket >= 0 && (descriptors[7].revents & POLLIN)) {
                handle_icmp_packet(stun_ctx.icmp_ctx.secondary_socket, stun_ctx.icmp_ctx);
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }
}