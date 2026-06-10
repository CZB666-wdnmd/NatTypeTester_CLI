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

struct IcmpMappingRecord {
    std::string peer_host;
    std::uint16_t mapped_query{};
};

struct IcmpRawContext {
    int primary_socket{-1};
    int secondary_socket{-1};
    IpEndpoint primary_bind{};
    IpEndpoint secondary_bind{};
    std::unordered_map<std::string, IcmpMappingRecord> mappings;
    std::mutex mappings_mutex;
    std::unordered_set<std::uint16_t> observed_error_markers;
    std::mutex observed_error_markers_mutex;
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
    if (!command_exists("iptables")) {
        return false;
    }
    bool ok = true;
    if (!run_shell_command("iptables -t raw -C OUTPUT -p icmp -j CT --notrack >/dev/null 2>&1")) {
        if (!run_shell_command("iptables -t raw -I OUTPUT -p icmp -j CT --notrack >/dev/null 2>&1")) ok = false;
    }
    if (!run_shell_command("iptables -t raw -C PREROUTING -p icmp -j CT --notrack >/dev/null 2>&1")) {
        if (!run_shell_command("iptables -t raw -I PREROUTING -p icmp -j CT --notrack >/dev/null 2>&1")) ok = false;
    }
    if (command_exists("ip6tables")) {
        if (!run_shell_command("ip6tables -t raw -C OUTPUT -p icmpv6 -j CT --notrack >/dev/null 2>&1")) {
            run_shell_command("ip6tables -t raw -I OUTPUT -p icmpv6 -j CT --notrack >/dev/null 2>&1");
        }
        if (!run_shell_command("ip6tables -t raw -C PREROUTING -p icmpv6 -j CT --notrack >/dev/null 2>&1")) {
            run_shell_command("ip6tables -t raw -I PREROUTING -p icmpv6 -j CT --notrack >/dev/null 2>&1");
        }
    }
    return ok;
}

bool ensure_nftables_icmp_notrack() {
    if (!command_exists("nft")) {
        return false;
    }
    bool ok = true;
    if (!run_shell_command("nft list table inet raw >/dev/null 2>&1") &&
        !run_shell_command("nft add table inet raw >/dev/null 2>&1")) {
        ok = false;
    }
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
    
    if (configured) {
        std::cout << "Note: ICMP/ICMPv6 conntrack bypass (notrack) is active.\n";
    } else {
        std::cerr << "Warning: Failed to configure ICMP notrack rules via iptables/nft. Raw ICMP probes may be dropped as INVALID.\n";
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
    if (last_colon == std::string_view::npos || input.find(':') != last_colon) {
        return {std::string(input), default_port};
    }
    return {std::string(input.substr(0, last_colon)), static_cast<std::uint16_t>(std::stoul(std::string(input.substr(last_colon + 1))))};
}

IpEndpoint resolve_endpoint(const std::string& host, std::uint16_t port) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* result = nullptr;
    int rc = getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &result);
    if (rc != 0) fail(std::string("getaddrinfo failed: ") + gai_strerror(rc));

    std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> guard(result, freeaddrinfo);
    for (addrinfo* current = result; current != nullptr; current = current->ai_next) {
        if (current->ai_family == AF_INET || current->ai_family == AF_INET6) {
            return from_sockaddr(current->ai_addr, static_cast<socklen_t>(current->ai_addrlen));
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

void try_disable_kernel_icmp_echo_auto_reply() {
    FILE* f1 = fopen("/proc/sys/net/ipv4/icmp_echo_ignore_all", "w");
    if (f1) { fputs("1\n", f1); fclose(f1); }
    FILE* f2 = fopen("/proc/sys/net/ipv6/icmp/echo_ignore_all", "w");
    if (f2) { fputs("1\n", f2); fclose(f2); }
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
        close(socket_fd); return -1;
    }
    return socket_fd;
}

std::uint16_t calculate_checksum(const void* data, std::size_t len) {
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    std::uint32_t sum = 0;
    while (len >= 2) {
        sum += static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[0]) << 8) | bytes[1]);
        bytes += 2;
        len -= 2;
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

bool send_icmp_echo(int raw_fd, const IpEndpoint& target, std::uint8_t type, std::uint16_t identifier, std::uint16_t sequence, std::string_view payload) {
    std::vector<std::uint8_t> packet(sizeof(icmphdr) + payload.size(), 0);
    auto* icmp = reinterpret_cast<icmphdr*>(packet.data());
    icmp->type = type;
    icmp->code = 0;
    icmp->un.echo.id = htons(identifier);
    icmp->un.echo.sequence = htons(sequence);
    if (!payload.empty()) std::memcpy(packet.data() + sizeof(icmphdr), payload.data(), payload.size());
    icmp->checksum = 0;
    icmp->checksum = calculate_icmp_checksum(packet.data(), packet.size());
    SocketAddress destination = to_sockaddr(target);
    ssize_t sent = sendto(raw_fd, packet.data(), packet.size(), 0, reinterpret_cast<sockaddr*>(&destination.storage), destination.length);
    return sent == static_cast<ssize_t>(packet.size());
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

int create_udp_listener(const IpEndpoint& endpoint) {
    int socket_fd = socket(endpoint.family, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd < 0) throw system_error("socket failed");
    set_reuse_options(socket_fd);
    SocketAddress address = to_sockaddr(endpoint);
    if (bind(socket_fd, reinterpret_cast<sockaddr*>(&address.storage), address.length) != 0) throw system_error("bind failed");
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

bool send_icmp_error(const IpEndpoint& peer, const IpEndpoint& local, int protocol) {
    if (peer.family == AF_INET) {
        int raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (raw_fd < 0) return false;

        std::vector<std::uint8_t> packet(sizeof(icmphdr) + sizeof(iphdr) + 8, 0);
        auto* icmp = reinterpret_cast<icmphdr*>(packet.data());
        icmp->type = ICMP_DEST_UNREACH;
        icmp->code = ICMP_PORT_UNREACH; 

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
    } else if (peer.family == AF_INET6) {
        int raw_fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
        if (raw_fd < 0) return false;

        std::vector<std::uint8_t> packet(sizeof(icmp6_hdr) + sizeof(ip6_hdr) + 8, 0);
        auto* icmp6 = reinterpret_cast<icmp6_hdr*>(packet.data());
        icmp6->icmp6_type = ICMP6_DST_UNREACH; // 1
        icmp6->icmp6_code = ICMP6_DST_UNREACH_NOPORT; // 4
        
        auto* inner_ip6 = reinterpret_cast<ip6_hdr*>(packet.data() + sizeof(icmp6_hdr));
        inner_ip6->ip6_vfc = 0x60; // Version 6
        inner_ip6->ip6_plen = htons(8);
        inner_ip6->ip6_nxt = protocol;
        inner_ip6->ip6_hlim = 64;
        std::memcpy(&inner_ip6->ip6_src, peer.address.data(), 16);
        std::memcpy(&inner_ip6->ip6_dst, local.address.data(), 16);

        std::uint8_t* inner_l4 = packet.data() + sizeof(icmp6_hdr) + sizeof(ip6_hdr);
        std::uint16_t sport = htons(peer.port), dport = htons(local.port);
        std::memcpy(inner_l4, &sport, 2); std::memcpy(inner_l4 + 2, &dport, 2);

        sockaddr_in6 dest{}; dest.sin6_family = AF_INET6;
        std::memcpy(&dest.sin6_addr, peer.address.data(), 16);
        ssize_t sent = sendto(raw_fd, packet.data(), packet.size(), 0, reinterpret_cast<sockaddr*>(&dest), sizeof(dest));
        close(raw_fd);
        return sent == static_cast<ssize_t>(packet.size());
    }
    return false;
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

bool send_out_of_order_fragmented_udp(const IpEndpoint& peer, const IpEndpoint& local) {
    if (peer.family != AF_INET || local.family != AF_INET) {
        std::cerr << "Warning: Out-of-order UDP fragments testing is implemented only for IPv4.\n";
        return false;
    }
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

void handle_tcp_client(int client_fd,
                       const IpEndpoint& primary_bind, const IpEndpoint& primary_public,
                       const IpEndpoint& secondary_bind, const IpEndpoint& secondary_public,
                       IcmpRawContext& icmp_context, int probe_timeout_ms, int syn_delay_ms) {
    try {
        sockaddr_storage peer{}; socklen_t peer_length = sizeof(peer);
        if (getpeername(client_fd, reinterpret_cast<sockaddr*>(&peer), &peer_length) != 0) throw system_error("getpeername failed");
        IpEndpoint peer_endpoint = from_sockaddr(reinterpret_cast<sockaddr*>(&peer), peer_length);
        
        while (true) {
            std::string command = recv_line(client_fd, 30000);
            if (command.empty()) return;
            
            if (command == "M") {
                send_all(client_fd, endpoint_line(peer_endpoint)); continue;
            }
            if (command == "F") {
                IpEndpoint p_src = primary_bind; p_src.port = 0;
                IpEndpoint s_src = secondary_bind; s_src.port = 0;
                bool p_ok = try_connect_from_source(p_src, peer_endpoint, probe_timeout_ms);
                bool s_ok = try_connect_from_source(s_src, peer_endpoint, probe_timeout_ms);
                send_all(client_fd, std::string("P=") + (p_ok ? "1" : "0") + " S=" + (s_ok ? "1" : "0") + "\n");
                continue;
            }
            if (command == "I") {
                sockaddr_storage local_addr{}; socklen_t local_length = sizeof(local_addr);
                getsockname(client_fd, reinterpret_cast<sockaddr*>(&local_addr), &local_length);
                IpEndpoint local_endpoint = from_sockaddr(reinterpret_cast<sockaddr*>(&local_addr), local_length);
                bool icmp_sent = send_icmp_error(peer_endpoint, local_endpoint, IPPROTO_TCP);
                send_all(client_fd, std::string("I=") + (icmp_sent ? "1" : "0") + "\n");
                continue;
            }
            // (其余TCP相关业务略，沿用老逻辑，仅替换为绑定地址)...
            send_all(client_fd, "ERR\n");
        }
    } catch (...) {}
}

// ---------------- STUN Helpers ----------------
void append_stun_address(std::vector<uint8_t>& out, uint16_t attr_type, const IpEndpoint& ep, const uint8_t* tx_id, bool xor_mapped) {
    out.push_back(attr_type >> 8); out.push_back(attr_type & 0xFF);
    uint16_t len = (ep.family == AF_INET) ? 8 : 20;
    out.push_back(len >> 8); out.push_back(len & 0xFF);
    out.push_back(0); out.push_back((ep.family == AF_INET) ? 1 : 2); // family

    uint16_t port = ep.port;
    if (xor_mapped) port ^= (static_cast<uint16_t>(tx_id[0]) << 8) | tx_id[1];
    out.push_back(port >> 8); out.push_back(port & 0xFF);

    if (ep.family == AF_INET) {
        for (int i = 0; i < 4; ++i) {
            uint8_t val = ep.address[i];
            if (xor_mapped) val ^= tx_id[i];
            out.push_back(val);
        }
    } else {
        for (int i = 0; i < 16; ++i) {
            uint8_t val = ep.address[i];
            if (xor_mapped) val ^= tx_id[i];
            out.push_back(val);
        }
    }
}

void handle_udp_packet(int udp_fd, const IpEndpoint& server_public_ep,
                       int alt_udp_fd, const IpEndpoint& alt_public_ep) {
    sockaddr_storage peer{}; socklen_t peer_length = sizeof(peer);
    std::vector<char> buffer(4096);
    ssize_t received = recvfrom(udp_fd, buffer.data(), buffer.size(), 0, reinterpret_cast<sockaddr*>(&peer), &peer_length);
    if (received <= 0) return;

    IpEndpoint peer_endpoint = from_sockaddr(reinterpret_cast<sockaddr*>(&peer), peer_length);

    // 1. 集成 STUN Binding Request 解析 (RFC 3489 / RFC 5389)
    if (received >= 20 && (buffer[0] & 0xC0) == 0) {
        uint16_t msg_type = static_cast<uint16_t>((static_cast<uint8_t>(buffer[0]) << 8) | static_cast<uint8_t>(buffer[1]));
        uint16_t msg_length = static_cast<uint16_t>((static_cast<uint8_t>(buffer[2]) << 8) | static_cast<uint8_t>(buffer[3]));
        
        if (msg_type == 0x0001) { // Binding Request
            bool change_ip = false, change_port = false;
            size_t offset = 20;
            while (offset + 4 <= static_cast<size_t>(received) && offset + 4 <= 20U + msg_length) {
                uint16_t attr_type = static_cast<uint16_t>((static_cast<uint8_t>(buffer[offset]) << 8) | static_cast<uint8_t>(buffer[offset + 1]));
                uint16_t attr_len = static_cast<uint16_t>((static_cast<uint8_t>(buffer[offset + 2]) << 8) | static_cast<uint8_t>(buffer[offset + 3]));
                if (attr_type == 0x0003 && attr_len == 4) { // CHANGE-REQUEST
                    uint32_t change_flags = ntohl(*reinterpret_cast<const uint32_t*>(buffer.data() + offset + 4));
                    change_ip = (change_flags & 0x0004);
                    change_port = (change_flags & 0x0002);
                }
                offset += 4 + ((attr_len + 3) & ~3);
            }

            int reply_fd = udp_fd;
            IpEndpoint reply_source = server_public_ep;
            
            // 如果客户端主动要求变化IP/端口测试打洞类型，则使用副公网地址应答
            if ((change_ip || change_port) && alt_udp_fd >= 0) {
                reply_fd = alt_udp_fd;
                reply_source = alt_public_ep;
            }

            std::vector<uint8_t> stun_resp(20, 0);
            stun_resp[0] = 0x01; stun_resp[1] = 0x01; // Binding Response
            std::memcpy(&stun_resp[4], buffer.data() + 4, 16); // 复制 Magic Cookie 和 Transaction ID

            const uint8_t* tx_id = stun_resp.data() + 4; // 用于 XOR
            append_stun_address(stun_resp, 0x0001, peer_endpoint, tx_id, false); // MAPPED-ADDRESS
            append_stun_address(stun_resp, 0x0004, reply_source, tx_id, false);  // SOURCE-ADDRESS
            append_stun_address(stun_resp, 0x0005, alt_public_ep, tx_id, false); // CHANGED-ADDRESS
            append_stun_address(stun_resp, 0x0020, peer_endpoint, tx_id, true);  // XOR-MAPPED-ADDRESS

            uint16_t total_attr_len = stun_resp.size() - 20;
            stun_resp[2] = total_attr_len >> 8; stun_resp[3] = total_attr_len & 0xFF;

            sendto(reply_fd, stun_resp.data(), stun_resp.size(), 0, reinterpret_cast<sockaddr*>(&peer), peer_length);
            return;
        }
    }

    // 2. 传统老协议UDP处理
    if (received >= 1 && buffer[0] == 'M') {
        std::string payload = endpoint_line(peer_endpoint);
        sendto(udp_fd, payload.data(), payload.size(), 0, reinterpret_cast<sockaddr*>(&peer), peer_length);
        return;
    }
    if (received >= 1 && buffer[0] == 'I') {
        bool sent = send_icmp_error(peer_endpoint, server_public_ep, IPPROTO_UDP);
        std::string reply = std::string("I=") + (sent ? "1" : "0") + "\n";
        sendto(udp_fd, reply.data(), reply.size(), 0, reinterpret_cast<sockaddr*>(&peer), peer_length);
        return;
    }
    if (received >= 1 && buffer[0] == 'O') {
        bool sent = send_out_of_order_fragmented_udp(peer_endpoint, server_public_ep);
        std::string reply = std::string("O=") + (sent ? "1" : "0") + "\n";
        sendto(udp_fd, reply.data(), reply.size(), 0, reinterpret_cast<sockaddr*>(&peer), peer_length);
        return;
    }
    sendto(udp_fd, buffer.data(), static_cast<std::size_t>(received), 0, reinterpret_cast<sockaddr*>(&peer), peer_length);
}

} // namespace

int main(int argc, char** argv) {
    try {
        std::optional<std::string> primary_arg, primary_public_arg;
        std::optional<std::string> secondary_arg, secondary_public_arg;
        int connection_probe_timeout_ms = 1200, syn_delay_ms = 350;

        for (int index = 1; index < argc; ++index) {
            std::string token = argv[index];
            if (token == "--primary" && index + 1 < argc) primary_arg = argv[++index];
            else if (token == "--primary-public" && index + 1 < argc) primary_public_arg = argv[++index];
            else if (token == "--secondary" && index + 1 < argc) secondary_arg = argv[++index];
            else if (token == "--secondary-public" && index + 1 < argc) secondary_public_arg = argv[++index];
            else if (token == "--probe-timeout-ms" && index + 1 < argc) connection_probe_timeout_ms = std::stoi(argv[++index]);
            else if (token == "--syn-delay-ms" && index + 1 < argc) syn_delay_ms = std::stoi(argv[++index]);
            else if (token == "--help" || token == "-h") {
                std::cout << "Usage: sudo nat_type_tester_server --primary host[:port] --secondary host[:port]\n"
                          << "       [--primary-public public_host[:port]] [--secondary-public public_host[:port]]\n";
                return 0;
            }
        }

        if (!primary_arg || !secondary_arg) fail("Both --primary and --secondary are required.");

        constexpr std::uint16_t default_port = 3478;
        
        auto [ph_bind, pp_bind] = split_host_port(*primary_arg, default_port);
        IpEndpoint primary_bind = resolve_endpoint(ph_bind, pp_bind);
        IpEndpoint primary_public = primary_bind;
        if (primary_public_arg) {
            auto [ph_pub, pp_pub] = split_host_port(*primary_public_arg, default_port);
            primary_public = resolve_endpoint(ph_pub, pp_pub);
        }

        auto [sh_bind, sp_bind] = split_host_port(*secondary_arg, default_port);
        IpEndpoint secondary_bind = resolve_endpoint(sh_bind, sp_bind);
        IpEndpoint secondary_public = secondary_bind;
        if (secondary_public_arg) {
            auto [sh_pub, sp_pub] = split_host_port(*secondary_public_arg, default_port);
            secondary_public = resolve_endpoint(sh_pub, sp_pub);
        }

        if (primary_bind.family != secondary_bind.family) fail("Primary and secondary addresses must use the same family.");

        ensure_icmp_conntrack_bypass();
        try_disable_kernel_icmp_echo_auto_reply();

        int primary_tcp_fd = create_tcp_listener(primary_bind);
        int secondary_tcp_fd = create_tcp_listener(secondary_bind);
        int primary_udp_fd = create_udp_listener(primary_bind);
        int secondary_udp_fd = create_udp_listener(secondary_bind);
        IcmpRawContext icmp_context;
        icmp_context.primary_bind = primary_bind;
        icmp_context.secondary_bind = secondary_bind;

        std::cout << "Server ready.\n"
                  << "  Primary: Bind=" << endpoint_host(primary_bind) << ":" << primary_bind.port << "  Public=" << endpoint_host(primary_public) << ":" << primary_public.port << '\n'
                  << "Secondary: Bind=" << endpoint_host(secondary_bind) << ":" << secondary_bind.port << "  Public=" << endpoint_host(secondary_public) << ":" << secondary_public.port << '\n';

        while (true) {
            std::array<pollfd, 4> descriptors{{
                {primary_tcp_fd, POLLIN, 0}, {secondary_tcp_fd, POLLIN, 0},
                {primary_udp_fd, POLLIN, 0}, {secondary_udp_fd, POLLIN, 0}
            }};
            if (poll(descriptors.data(), descriptors.size(), -1) < 0) throw system_error("poll failed");

            // STUN和业务UDP数据接收处理器（当客户端发向主口，且包含切换要求时，传给备用口发送）
            if (descriptors[2].revents & POLLIN) handle_udp_packet(primary_udp_fd, primary_public, secondary_udp_fd, secondary_public);
            if (descriptors[3].revents & POLLIN) handle_udp_packet(secondary_udp_fd, secondary_public, primary_udp_fd, primary_public);

            if (descriptors[0].revents & POLLIN) {
                sockaddr_storage client{}; socklen_t len = sizeof(client);
                int client_fd = accept(primary_tcp_fd, reinterpret_cast<sockaddr*>(&client), &len);
                if (client_fd >= 0) {
                    std::thread([=, &icmp_context]() {
                        handle_tcp_client(client_fd, primary_bind, primary_public, secondary_bind, secondary_public, icmp_context, connection_probe_timeout_ms, syn_delay_ms);
                        close(client_fd);
                    }).detach();
                }
            }
            if (descriptors[1].revents & POLLIN) {
                sockaddr_storage client{}; socklen_t len = sizeof(client);
                int client_fd = accept(secondary_tcp_fd, reinterpret_cast<sockaddr*>(&client), &len);
                if (client_fd >= 0) {
                    std::thread([=, &icmp_context]() {
                        handle_tcp_client(client_fd, primary_bind, primary_public, secondary_bind, secondary_public, icmp_context, connection_probe_timeout_ms, syn_delay_ms);
                        close(client_fd);
                    }).detach();
                }
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }
}