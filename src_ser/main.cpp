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

struct StunNode {
    int fd = -1;
    IpEndpoint bind_ep{};
    IpEndpoint pub_ep{};
};

struct StunContext {
    // 0: IP_A, Port_1
    // 1: IP_A, Port_2
    // 2: IP_B, Port_1
    // 3: IP_B, Port_2
    StunNode nodes[4];
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
    if (bind(socket_fd, reinterpret_cast<sockaddr*>(&address.storage), address.length) != 0) throw system_error("bind failed on UDP");
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

    // 1. STUN Binding Request
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

            // 完美的 4 端口矩阵路由逻辑 (0: A1, 1: A2, 2: B1, 3: B2)
            int reply_idx = rx_idx;
            int ip_bit = rx_idx & 2;     // 0 = IP A, 2 = IP B
            int port_bit = rx_idx & 1;   // 0 = Port 1, 1 = Port 2
            
            if (change_ip) ip_bit ^= 2;
            if (change_port) port_bit ^= 1;
            reply_idx = ip_bit | port_bit;

            // STUN 标准要求的 CHANGED-ADDRESS 是指向与接收端口"IP和Port均相反"的地址
            int other_idx = rx_idx ^ 3; // 直接异或 3 翻转两个 bit

            const StunNode& reply_node = ctx.nodes[reply_idx];
            const StunNode& other_node = ctx.nodes[other_idx];

            std::vector<uint8_t> stun_resp(20, 0);
            stun_resp[0] = 0x01; stun_resp[1] = 0x01; // Success Binding Response
            std::memcpy(&stun_resp[4], buffer.data() + 4, 16); 
            const uint8_t* tx_id = reinterpret_cast<const uint8_t*>(buffer.data() + 4); 
            
            bool is_rfc5389 = (tx_id[0] == 0x21 && tx_id[1] == 0x12 && tx_id[2] == 0xA4 && tx_id[3] == 0x42);

            std::cout << "[STUN] Req from " << endpoint_host(peer_endpoint) << ":" << peer_endpoint.port 
                      << " | Type: " << (is_rfc5389 ? "RFC5389/5780" : "RFC3489") 
                      << " | Rx: " << rx_node.pub_ep.port << " (IP-" << (rx_idx & 2 ? "B" : "A") << ")"
                      << " | ChgIP=" << change_ip << " ChgPort=" << change_port 
                      << " | ReplySrc: " << endpoint_host(reply_node.pub_ep) << ":" << reply_node.pub_ep.port << "\n";

            append_stun_address(stun_resp, 0x0001, peer_endpoint, tx_id, false); // MAPPED-ADDRESS
            append_stun_address(stun_resp, 0x0004, reply_node.pub_ep, tx_id, false);  // SOURCE-ADDRESS
            append_stun_address(stun_resp, 0x0005, other_node.pub_ep, tx_id, false); // CHANGED-ADDRESS
            
            append_stun_address(stun_resp, 0x802b, reply_node.pub_ep, tx_id, false);  // RESPONSE-ORIGIN
            append_stun_address(stun_resp, 0x802c, other_node.pub_ep, tx_id, false); // OTHER-ADDRESS

            if (is_rfc5389) {
                append_stun_address(stun_resp, 0x0020, peer_endpoint, tx_id, true);  // XOR-MAPPED-ADDRESS
            }

            uint16_t total_attr_len = stun_resp.size() - 20;
            stun_resp[2] = total_attr_len >> 8; 
            stun_resp[3] = total_attr_len & 0xFF;

            sendto(reply_node.fd, stun_resp.data(), stun_resp.size(), 0, reinterpret_cast<sockaddr*>(&peer), peer_length);
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
        
        // 解析传入的基础 Host 和 Port
        auto [ph_bind_host, p_bind_port] = split_host_port(*primary_arg, default_port);
        auto [ph_pub_host, p_pub_port] = primary_public_arg ? split_host_port(*primary_public_arg, default_port) : std::make_pair(ph_bind_host, p_bind_port);
        
        auto [sh_bind_host, s_bind_port] = split_host_port(*secondary_arg, default_port);
        auto [sh_pub_host, s_pub_port] = secondary_public_arg ? split_host_port(*secondary_public_arg, default_port) : std::make_pair(sh_bind_host, s_bind_port);

        uint16_t port_a = p_bind_port;
        uint16_t port_b = s_bind_port;
        
        // 如果用户只给了同一个端口，系统强制分配下一个端口形成矩阵
        if (port_a == port_b) {
            port_b = port_a + 1;
        }

        StunContext stun_ctx;
        
        // 节点 0: IP_A, Port_a
        stun_ctx.nodes[0].bind_ep = resolve_endpoint(ph_bind_host, port_a);
        stun_ctx.nodes[0].pub_ep = resolve_endpoint(ph_pub_host, port_a);
        // 节点 1: IP_A, Port_b
        stun_ctx.nodes[1].bind_ep = resolve_endpoint(ph_bind_host, port_b);
        stun_ctx.nodes[1].pub_ep = resolve_endpoint(ph_pub_host, port_b);
        // 节点 2: IP_B, Port_a
        stun_ctx.nodes[2].bind_ep = resolve_endpoint(sh_bind_host, port_a);
        stun_ctx.nodes[2].pub_ep = resolve_endpoint(sh_pub_host, port_a);
        // 节点 3: IP_B, Port_b
        stun_ctx.nodes[3].bind_ep = resolve_endpoint(sh_bind_host, port_b);
        stun_ctx.nodes[3].pub_ep = resolve_endpoint(sh_pub_host, port_b);

        ensure_icmp_conntrack_bypass();
        try_disable_kernel_icmp_echo_auto_reply();

        std::cout << "STUN 4-Socket Matrix Starting...\n";
        for (int i = 0; i < 4; ++i) {
            stun_ctx.nodes[i].fd = create_udp_listener(stun_ctx.nodes[i].bind_ep);
            std::cout << "  Node " << i << ": Bind=" << endpoint_host(stun_ctx.nodes[i].bind_ep) << ":" << stun_ctx.nodes[i].bind_ep.port 
                      << "  Public=" << endpoint_host(stun_ctx.nodes[i].pub_ep) << ":" << stun_ctx.nodes[i].pub_ep.port << '\n';
        }
        std::cout << "\n>>> Server ready for Full Cone / Restricted Cone discovery tests.\n";
        std::cout << ">>> NOTE: Make sure your Firewall/Security Group allows UDP on BOTH ports (" 
                  << port_a << " and " << port_b << ") for BOTH IPs.\n\n";

        // TCP Legacy Server Keep Alive (使用 Node0 和 Node3 的信息作为 Primary/Secondary)
        int primary_tcp_fd = create_tcp_listener(stun_ctx.nodes[0].bind_ep);
        int secondary_tcp_fd = create_tcp_listener(stun_ctx.nodes[3].bind_ep);

        while (true) {
            std::array<pollfd, 6> descriptors{{
                {primary_tcp_fd, POLLIN, 0},
                {secondary_tcp_fd, POLLIN, 0},
                {stun_ctx.nodes[0].fd, POLLIN, 0},
                {stun_ctx.nodes[1].fd, POLLIN, 0},
                {stun_ctx.nodes[2].fd, POLLIN, 0},
                {stun_ctx.nodes[3].fd, POLLIN, 0}
            }};
            
            if (poll(descriptors.data(), descriptors.size(), -1) < 0) throw system_error("poll failed");

            // 监听 4 个 UDP 端口
            for (int i = 0; i < 4; ++i) {
                if (descriptors[i + 2].revents & POLLIN) {
                    handle_udp_packet(i, stun_ctx);
                }
            }
            
            // 忽略 TCP Accept 逻辑占位（如果不需要 TCP 测试其实可以直接移除）
            if (descriptors[0].revents & POLLIN) {
                sockaddr_storage client{}; socklen_t len = sizeof(client);
                int client_fd = accept(primary_tcp_fd, reinterpret_cast<sockaddr*>(&client), &len);
                if (client_fd >= 0) close(client_fd);
            }
            if (descriptors[1].revents & POLLIN) {
                sockaddr_storage client{}; socklen_t len = sizeof(client);
                int client_fd = accept(secondary_tcp_fd, reinterpret_cast<sockaddr*>(&client), &len);
                if (client_fd >= 0) close(client_fd);
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }
}