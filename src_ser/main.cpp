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
#include <net/if.h>

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
    std::string device_name;
};

struct StunContext {
    StunNode nodes[4];
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

void try_disable_kernel_icmp_echo_auto_reply() {
    FILE* f1 = fopen("/proc/sys/net/ipv4/icmp_echo_ignore_all", "w");
    if (f1) { fputs("1\n", f1); fclose(f1); }
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

IpEndpoint resolve_endpoint(const std::string& host, std::uint16_t port) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_UDP;
    addrinfo* result = nullptr;
    int rc = getaddrinfo(host.c_str(), nullptr, &hints, &result);
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

std::string endpoint_host(const IpEndpoint& endpoint) {
    char buffer[INET6_ADDRSTRLEN]{};
    if (endpoint.family == AF_INET) inet_ntop(AF_INET, endpoint.address.data(), buffer, sizeof(buffer));
    else inet_ntop(AF_INET6, endpoint.address.data(), buffer, sizeof(buffer));
    std::string res(buffer);
    if (endpoint.family == AF_INET6) res = "[" + res + "]";
    return res;
}

bool is_unspecified(const IpEndpoint& ep) {
    for (std::size_t i = 0; i < ep.address_length; ++i) {
        if (ep.address[i] != 0) return false;
    }
    return true;
}

// 自动寻找 IP 对应的网络接口名称 (eth0, eth1, ens3 等)
std::optional<std::string> get_interface_name(const IpEndpoint& endpoint) {
    if (is_unspecified(endpoint)) return std::nullopt;

    ifaddrs* ifaddr_list = nullptr;
    if (getifaddrs(&ifaddr_list) == -1) return std::nullopt;

    std::optional<std::string> result;
    for (ifaddrs* ifa = ifaddr_list; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;

        if (ifa->ifa_addr->sa_family == endpoint.family) {
            if (endpoint.family == AF_INET) {
                auto* ipv4 = reinterpret_cast<sockaddr_in*>(ifa->ifa_addr);
                if (std::memcmp(&ipv4->sin_addr, endpoint.address.data(), 4) == 0) {
                    result = ifa->ifa_name;
                    break;
                }
            } else if (endpoint.family == AF_INET6) {
                auto* ipv6 = reinterpret_cast<sockaddr_in6*>(ifa->ifa_addr);
                if (std::memcmp(&ipv6->sin6_addr, endpoint.address.data(), 16) == 0) {
                    result = ifa->ifa_name;
                    break;
                }
            }
        }
    }
    freeifaddrs(ifaddr_list);
    return result;
}

void set_reuse_options(int socket_fd) {
    int reuse = 1;
    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#ifdef SO_REUSEPORT
    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
#endif
}

int create_udp_listener(StunNode& node) {
    int socket_fd = socket(node.bind_ep.family, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd < 0) throw system_error("socket failed");
    set_reuse_options(socket_fd);

    // 核心代码：硬件网卡强绑定，绕过内核主路由表
    auto iface = get_interface_name(node.bind_ep);
    if (iface) {
        node.device_name = *iface;
        if (setsockopt(socket_fd, SOL_SOCKET, SO_BINDTODEVICE, iface->c_str(), iface->length()) != 0) {
            std::cerr << "  [Warning] SO_BINDTODEVICE failed for " << *iface << " (Requires root privileges)\n";
        }
    } else {
        node.device_name = "N/A";
    }

    SocketAddress address = to_sockaddr(node.bind_ep);
    if (bind(socket_fd, reinterpret_cast<sockaddr*>(&address.storage), address.length) != 0) {
        throw system_error("bind failed on UDP");
    }
    return socket_fd;
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

            int ip_bit = rx_idx & 2;     // 0 = IP_1, 2 = IP_2
            int port_bit = rx_idx & 1;   // 0 = Port_1, 1 = Port_2
            
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

            std::cout << "[STUN] " << endpoint_host(peer_endpoint) << ":" << peer_endpoint.port 
                      << " | " << (is_rfc5389 ? "RFC5780" : "RFC3489") 
                      << " | Rx: " << rx_node.pub_ep.port << "(IP-" << (rx_idx & 2 ? "2" : "1") << ")"
                      << " | ChgIP=" << change_ip << " ChgPort=" << change_port 
                      << " | ReplyOut: " << endpoint_host(reply_node.pub_ep) << ":" << reply_node.pub_ep.port 
                      << " (" << reply_node.device_name << ")\n";

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

            ssize_t sent = sendto(reply_node.fd, stun_resp.data(), stun_resp.size(), 0, reinterpret_cast<sockaddr*>(&peer), peer_length);
            if (sent < 0) {
                std::cerr << "  -> [ERROR] sendto failed: " << std::strerror(errno);
                if (errno == ENETUNREACH) {
                    std::cerr << " (No default route found on interface " << reply_node.device_name << ". You may need to add a routing rule for this device!)";
                }
                std::cerr << "\n";
            }
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
        std::string bind_ip1 = "0.0.0.0", pub_ip1 = "";
        std::string bind_ip2 = "0.0.0.0", pub_ip2 = "";
        uint16_t port1 = 3478, port2 = 3479;

        for (int index = 1; index < argc; ++index) {
            std::string token = argv[index];
            if (token == "--bind-ip1") bind_ip1 = argv[++index];
            else if (token == "--pub-ip1") pub_ip1 = argv[++index];
            else if (token == "--bind-ip2") bind_ip2 = argv[++index];
            else if (token == "--pub-ip2") pub_ip2 = argv[++index];
            else if (token == "--port1") port1 = std::stoi(argv[++index]);
            else if (token == "--port2") port2 = std::stoi(argv[++index]);
        }

        if (pub_ip1.empty() || pub_ip2.empty()) fail("Both --pub-ip1 and --pub-ip2 are required.");

        StunContext stun_ctx;
        stun_ctx.nodes[0].bind_ep = resolve_endpoint(bind_ip1, port1); stun_ctx.nodes[0].pub_ep = resolve_endpoint(pub_ip1, port1);
        stun_ctx.nodes[1].bind_ep = resolve_endpoint(bind_ip1, port2); stun_ctx.nodes[1].pub_ep = resolve_endpoint(pub_ip1, port2);
        stun_ctx.nodes[2].bind_ep = resolve_endpoint(bind_ip2, port1); stun_ctx.nodes[2].pub_ep = resolve_endpoint(pub_ip2, port1);
        stun_ctx.nodes[3].bind_ep = resolve_endpoint(bind_ip2, port2); stun_ctx.nodes[3].pub_ep = resolve_endpoint(pub_ip2, port2);

        try_disable_kernel_icmp_echo_auto_reply();

        std::cout << "STUN 4-Socket Matrix Starting (with SO_BINDTODEVICE)...\n";
        for (int i = 0; i < 4; ++i) {
            stun_ctx.nodes[i].fd = create_udp_listener(stun_ctx.nodes[i]);
            std::cout << "  Node " << i << ": Bind=" << endpoint_host(stun_ctx.nodes[i].bind_ep) << ":" << stun_ctx.nodes[i].bind_ep.port 
                      << "  Public=" << endpoint_host(stun_ctx.nodes[i].pub_ep) << ":" << stun_ctx.nodes[i].pub_ep.port 
                      << "  [Device: " << stun_ctx.nodes[i].device_name << "]\n";
        }

        std::cout << "\n>>> Server ready. Asymmetric routing prevention active.\n";

        while (true) {
            std::array<pollfd, 4> descriptors{{
                {stun_ctx.nodes[0].fd, POLLIN, 0}, {stun_ctx.nodes[1].fd, POLLIN, 0},
                {stun_ctx.nodes[2].fd, POLLIN, 0}, {stun_ctx.nodes[3].fd, POLLIN, 0}
            }};
            
            if (poll(descriptors.data(), descriptors.size(), -1) < 0) throw system_error("poll failed");

            for (int i = 0; i < 4; ++i) {
                if (descriptors[i].revents & POLLIN) handle_udp_packet(i, stun_ctx);
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }
}