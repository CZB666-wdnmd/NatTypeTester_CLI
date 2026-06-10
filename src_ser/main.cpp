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
    if (!command_exists("iptables")) return false;
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

bool is_unspecified(const IpEndpoint& ep) {
    for (std::size_t i = 0; i < ep.address_length; ++i) {
        if (ep.address[i] != 0) return false;
    }
    return true;
}

// ---------------- STUN Implementation ----------------

void append_stun_address(std::vector<uint8_t>& out, uint16_t attr_type, const IpEndpoint& ep, const uint8_t* tx_id, bool xor_mapped) {
    out.push_back(attr_type >> 8); 
    out.push_back(attr_type & 0xFF);
    
    uint16_t len = (ep.family == AF_INET) ? 8 : 20;
    out.push_back(len >> 8); 
    out.push_back(len & 0xFF);
    
    out.push_back(0); // Unused
    out.push_back((ep.family == AF_INET) ? 1 : 2); // IPv4 = 0x01, IPv6 = 0x02

    uint16_t port = ep.port;
    if (xor_mapped && tx_id) {
        port ^= (static_cast<uint16_t>(tx_id[0]) << 8) | tx_id[1];
    }
    out.push_back(port >> 8); 
    out.push_back(port & 0xFF);

    if (ep.family == AF_INET) {
        for (int i = 0; i < 4; ++i) {
            uint8_t val = ep.address[i];
            if (xor_mapped && tx_id) val ^= tx_id[i]; // IPv4 仅异或 Magic Cookie 的前4字节
            out.push_back(val);
        }
    } else {
        for (int i = 0; i < 16; ++i) {
            uint8_t val = ep.address[i];
            if (xor_mapped && tx_id) val ^= tx_id[i]; // IPv6 异或所有 16 字节
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

    // 1. STUN Binding Request 分析 (RFC 3489 / RFC 5389 / RFC 5780)
    if (received >= 20 && (buffer[0] & 0xC0) == 0) {
        uint16_t msg_type = static_cast<uint16_t>((static_cast<uint8_t>(buffer[0]) << 8) | static_cast<uint8_t>(buffer[1]));
        uint16_t msg_length = static_cast<uint16_t>((static_cast<uint8_t>(buffer[2]) << 8) | static_cast<uint8_t>(buffer[3]));
        
        if (msg_type == 0x0001) { // Binding Request
            bool change_ip = false, change_port = false;
            size_t offset = 20;
            
            // 安全读取并解析 Attributes
            while (offset + 4 <= static_cast<size_t>(received) && offset + 4 <= 20U + msg_length) {
                uint16_t attr_type = static_cast<uint16_t>((static_cast<uint8_t>(buffer[offset]) << 8) | static_cast<uint8_t>(buffer[offset + 1]));
                uint16_t attr_len = static_cast<uint16_t>((static_cast<uint8_t>(buffer[offset + 2]) << 8) | static_cast<uint8_t>(buffer[offset + 3]));
                
                size_t next_offset = offset + 4 + ((attr_len + 3) & ~3);
                if (next_offset > static_cast<size_t>(received) || next_offset > 20U + msg_length) break;

                if (attr_type == 0x0003 && attr_len == 4) { // CHANGE-REQUEST
                    uint32_t change_flags = 0;
                    std::memcpy(&change_flags, buffer.data() + offset + 4, 4); 
                    change_flags = ntohl(change_flags);
                    change_ip = (change_flags & 0x0004); // A 位
                    change_port = (change_flags & 0x0002); // B 位
                }
                offset = next_offset;
            }

            int reply_fd = udp_fd;
            IpEndpoint reply_source = server_public_ep;
            
            // 处理 NAT 打洞发现，根据客户端要求用别的公网 IP/Port 响应
            if ((change_ip || change_port) && alt_udp_fd >= 0) {
                reply_fd = alt_udp_fd;
                reply_source = alt_public_ep;
            }

            std::vector<uint8_t> stun_resp(20, 0);
            stun_resp[0] = 0x01; stun_resp[1] = 0x01; // Success Binding Response
            std::memcpy(&stun_resp[4], buffer.data() + 4, 16); 

            const uint8_t* tx_id = reinterpret_cast<const uint8_t*>(buffer.data() + 4); 
            
            // 防御性解析 Magic Cookie，安全判断是否支持 RFC 5389
            bool is_rfc5389 = (tx_id[0] == 0x21 && tx_id[1] == 0x12 && tx_id[2] == 0xA4 && tx_id[3] == 0x42);

            std::cout << "[STUN] Req from " << endpoint_host(peer_endpoint) << ":" << peer_endpoint.port 
                      << " | Type: " << (is_rfc5389 ? "RFC5389/5780" : "RFC3489") 
                      << " | ChgIP=" << change_ip << " ChgPort=" << change_port 
                      << " | ReplySrc: " << endpoint_host(reply_source) << ":" << reply_source.port << "\n";

            // 无论是 3489 还是 5780，我们都提供最全面的 Attributes 供其解析
            append_stun_address(stun_resp, 0x0001, peer_endpoint, tx_id, false); // MAPPED-ADDRESS
            append_stun_address(stun_resp, 0x0004, reply_source, tx_id, false);  // SOURCE-ADDRESS
            append_stun_address(stun_resp, 0x0005, alt_public_ep, tx_id, false); // CHANGED-ADDRESS
            
            // RFC 5780 (NAT Behavior Discovery) 所必需的扩展字段（由于 > 0x7FFF，老旧客户端会自动忽略它们而不报错）
            append_stun_address(stun_resp, 0x802b, reply_source, tx_id, false);  // RESPONSE-ORIGIN
            append_stun_address(stun_resp, 0x802c, alt_public_ep, tx_id, false); // OTHER-ADDRESS

            if (is_rfc5389) {
                append_stun_address(stun_resp, 0x0020, peer_endpoint, tx_id, true);  // XOR-MAPPED-ADDRESS
            }

            uint16_t total_attr_len = stun_resp.size() - 20;
            stun_resp[2] = total_attr_len >> 8; 
            stun_resp[3] = total_attr_len & 0xFF;

            sendto(reply_fd, stun_resp.data(), stun_resp.size(), 0, reinterpret_cast<sockaddr*>(&peer), peer_length);
            return;
        }
    }

    if (received >= 1 && buffer[0] == 'M') {
        std::string payload = endpoint_line(peer_endpoint);
        sendto(udp_fd, payload.data(), payload.size(), 0, reinterpret_cast<sockaddr*>(&peer), peer_length);
        return;
    }
}

} // namespace

int main(int argc, char** argv) {
    try {
        std::optional<std::string> primary_arg, primary_public_arg;
        std::optional<std::string> secondary_arg, secondary_public_arg;

        for (int index = 1; index < argc; ++index) {
            std::string token = argv[index];
            if (token == "--primary" && index + 1 < argc) primary_arg = argv[++index];
            else if (token == "--primary-public" && index + 1 < argc) primary_public_arg = argv[++index];
            else if (token == "--secondary" && index + 1 < argc) secondary_arg = argv[++index];
            else if (token == "--secondary-public" && index + 1 < argc) secondary_public_arg = argv[++index];
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

        ensure_icmp_conntrack_bypass();
        try_disable_kernel_icmp_echo_auto_reply();

        int primary_udp_fd = create_udp_listener(primary_bind);
        int secondary_udp_fd = create_udp_listener(secondary_bind);

        std::cout << "Server ready.\n"
                  << "  Primary: Bind=" << endpoint_host(primary_bind) << ":" << primary_bind.port 
                  << "  Public=" << endpoint_host(primary_public) << ":" << primary_public.port << '\n'
                  << "Secondary: Bind=" << endpoint_host(secondary_bind) << ":" << secondary_bind.port 
                  << "  Public=" << endpoint_host(secondary_public) << ":" << secondary_public.port << "\n\n";

        if (primary_public.port == secondary_public.port) {
            std::cerr << "=================================================================================\n"
                      << "[FATAL WARNING] Primary and Secondary Public Ports are IDENTICAL (" << primary_public.port << ")\n"
                      << "Standard STUN clients (like NATTypeTester) strictly check that the alternate \n"
                      << "port differs from the primary. If they are the same, the STUN client will \n"
                      << "instantly reject the server with 'UnsupportedServer'!\n"
                      << "HOW TO FIX: Start the server using a DIFFERENT port for the secondary server:\n"
                      << "e.g., --secondary 8.163.60.58:3479\n"
                      << "=================================================================================\n\n";
        }

        while (true) {
            std::array<pollfd, 2> descriptors{{
                {primary_udp_fd, POLLIN, 0}, {secondary_udp_fd, POLLIN, 0}
            }};
            if (poll(descriptors.data(), descriptors.size(), -1) < 0) throw system_error("poll failed");

            if (descriptors[0].revents & POLLIN) handle_udp_packet(primary_udp_fd, primary_public, secondary_udp_fd, secondary_public);
            if (descriptors[1].revents & POLLIN) handle_udp_packet(secondary_udp_fd, secondary_public, primary_udp_fd, primary_public);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }
}