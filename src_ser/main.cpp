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

#include <array>
#include <cerrno>
#include <chrono>
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
    IpEndpoint primary_server{};
    IpEndpoint secondary_server{};
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
    if (input.empty()) {
        fail("Endpoint cannot be empty");
    }

    if (input.front() == '[') {
        std::size_t end = input.find(']');
        if (end == std::string_view::npos || end + 1 >= input.size() || input[end + 1] != ':') {
            fail("Invalid IPv6 endpoint syntax");
        }
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
    if (rc != 0) {
        fail(std::string("getaddrinfo failed: ") + gai_strerror(rc));
    }

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
    FILE* file = fopen("/proc/sys/net/ipv4/icmp_echo_ignore_all", "w");
    if (file == nullptr) {
        return;
    }
    fputs("1\n", file);
    fclose(file);
}

int create_icmp_raw_listener(const IpEndpoint& endpoint) {
    if (endpoint.family != AF_INET) {
        return -1;
    }
    int socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (socket_fd < 0) {
        throw system_error("socket failed");
    }
    try {
        set_reuse_options(socket_fd);
        IpEndpoint bind_endpoint = endpoint;
        bind_endpoint.port = 0;
        SocketAddress address = to_sockaddr(bind_endpoint);
        if (bind(socket_fd, reinterpret_cast<sockaddr*>(&address.storage), address.length) != 0) {
            throw system_error("bind failed");
        }
        return socket_fd;
    } catch (...) {
        close(socket_fd);
        throw;
    }
}

std::uint16_t calculate_icmp_checksum(const void* data, std::size_t len) {
    const auto* ptr = static_cast<const std::uint16_t*>(data);
    std::uint32_t sum = 0;
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len == 1) {
        sum += *reinterpret_cast<const std::uint8_t*>(ptr);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<std::uint16_t>(~sum);
}

bool send_icmp_echo(int raw_fd,
                    const IpEndpoint& target,
                    std::uint8_t type,
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
    icmp->checksum = calculate_icmp_checksum(packet.data(), packet.size());

    SocketAddress destination = to_sockaddr(target);
    const ssize_t sent = sendto(raw_fd,
                                packet.data(),
                                packet.size(),
                                0,
                                reinterpret_cast<sockaddr*>(&destination.storage),
                                destination.length);
    return sent == static_cast<ssize_t>(packet.size());
}

int create_tcp_listener(const IpEndpoint& endpoint) {
    int socket_fd = socket(endpoint.family, SOCK_STREAM, IPPROTO_TCP);
    if (socket_fd < 0) {
        throw system_error("socket failed");
    }

    try {
        set_reuse_options(socket_fd);
        SocketAddress address = to_sockaddr(endpoint);
        if (bind(socket_fd, reinterpret_cast<sockaddr*>(&address.storage), address.length) != 0) {
            throw system_error("bind failed");
        }
        if (listen(socket_fd, 32) != 0) {
            throw system_error("listen failed");
        }
        return socket_fd;
    } catch (...) {
        close(socket_fd);
        throw;
    }
}

int create_udp_listener(const IpEndpoint& endpoint) {
    int socket_fd = socket(endpoint.family, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd < 0) {
        throw system_error("socket failed");
    }

    try {
        set_reuse_options(socket_fd);
        SocketAddress address = to_sockaddr(endpoint);
        if (bind(socket_fd, reinterpret_cast<sockaddr*>(&address.storage), address.length) != 0) {
            throw system_error("bind failed");
        }
        return socket_fd;
    } catch (...) {
        close(socket_fd);
        throw;
    }
}

void bind_socket(int socket_fd, const IpEndpoint& endpoint) {
    SocketAddress address = to_sockaddr(endpoint);
    if (bind(socket_fd, reinterpret_cast<sockaddr*>(&address.storage), address.length) != 0) {
        throw system_error("bind failed");
    }
}

std::string endpoint_host(const IpEndpoint& endpoint) {
    char buffer[INET6_ADDRSTRLEN]{};
    if (endpoint.family == AF_INET) {
        inet_ntop(AF_INET, endpoint.address.data(), buffer, sizeof(buffer));
    } else {
        inet_ntop(AF_INET6, endpoint.address.data(), buffer, sizeof(buffer));
    }
    return std::string(buffer);
}

std::string endpoint_line(const IpEndpoint& endpoint) {
    return endpoint_host(endpoint) + " " + std::to_string(endpoint.port) + "\n";
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

std::string recv_line(int socket_fd, int timeout_ms) {
    std::string line;
    std::array<char, 256> buffer{};
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (line.find('\n') == std::string::npos) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            throw std::runtime_error("recv timed out");
        }
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        pollfd descriptor{socket_fd, POLLIN, 0};
        const int rc = poll(&descriptor, 1, static_cast<int>(remaining.count()));
        if (rc <= 0 || (descriptor.revents & POLLIN) == 0) {
            throw std::runtime_error("recv timed out");
        }
        ssize_t received = recv(socket_fd, buffer.data(), buffer.size(), 0);
        if (received <= 0) {
            break;
        }
        line.append(buffer.data(), static_cast<std::size_t>(received));
        if (line.size() > 4096) {
            fail("Protocol line too long");
        }
    }
    if (line.empty()) {
        return "";
    }
    return line.substr(0, line.find('\n'));
}

// ---------------------------------------------------------
// 新增: 构造并发送原生的 ICMP 错误包功能
// ---------------------------------------------------------
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
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return static_cast<std::uint16_t>(~sum);
}

bool send_ipv4_icmp_error(const IpEndpoint& peer, const IpEndpoint& local, int protocol) {
    if (peer.family != AF_INET) {
        // 出于复杂性考虑，目前仅实现了 IPv4 的 ICMP 注入
        std::cerr << "Warning: ICMP injection only implemented for IPv4.\n";
        return false;
    }

    // 创建原始套接字，这需要 ROOT 权限
    int raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (raw_fd < 0) {
        std::cerr << "Warning: Failed to create raw socket (Requires root). Error: " << std::strerror(errno) << '\n';
        return false;
    }

    // Payload = ICMP 报头(8) + 内层 IP 报头(20) + 内层 L4 报头(8)
    std::vector<std::uint8_t> packet(sizeof(icmphdr) + sizeof(iphdr) + 8, 0);

    // 1. 构造 ICMP 报头
    auto* icmp = reinterpret_cast<icmphdr*>(packet.data());
    icmp->type = ICMP_DEST_UNREACH;
    icmp->code = ICMP_PORT_UNREACH; // Code 3: 端口不可达
    icmp->checksum = 0;

    // 2. 构造内层的 IP 报头 (这代表的是 NAT发往服务器的那张包)
    auto* inner_ip = reinterpret_cast<iphdr*>(packet.data() + sizeof(icmphdr));
    inner_ip->ihl = 5;
    inner_ip->version = 4;
    inner_ip->tos = 0;
    inner_ip->tot_len = htons(sizeof(iphdr) + 8);
    inner_ip->id = htons(0x1234);
    inner_ip->frag_off = 0;
    inner_ip->ttl = 64;
    inner_ip->protocol = protocol; // IPPROTO_TCP 或 IPPROTO_UDP
    
    // 内层包：源 IP 是 NAT，目的 IP 是服务器
    std::memcpy(&inner_ip->saddr, peer.address.data(), 4);
    std::memcpy(&inner_ip->daddr, local.address.data(), 4);
    inner_ip->check = calculate_checksum(inner_ip, sizeof(iphdr));

    // 3. 构造内层 L4 报头 (只截取前 8 字节，包含源端口和目的端口)
    std::uint8_t* inner_l4 = packet.data() + sizeof(icmphdr) + sizeof(iphdr);
    std::uint16_t sport = htons(peer.port);  // NAT的端口
    std::uint16_t dport = htons(local.port); // 服务器的端口
    std::memcpy(inner_l4, &sport, 2);
    std::memcpy(inner_l4 + 2, &dport, 2);
    // 对于 TCP，这里之后的 4 字节原本是 Seq Number。我们保留为 0，因为绝大多数 NAT 是依据 5 元组来匹配映射的。

    // 计算外层 ICMP 的校验和
    icmp->checksum = calculate_checksum(packet.data(), packet.size());

    // 发送数据
    sockaddr_in dest{};
    dest.sin_family = AF_INET;
    std::memcpy(&dest.sin_addr, peer.address.data(), 4);

    ssize_t sent = sendto(raw_fd, packet.data(), packet.size(), 0, reinterpret_cast<sockaddr*>(&dest), sizeof(dest));
    close(raw_fd);
    
    return sent == static_cast<ssize_t>(packet.size());
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

bool send_ipv4_icmp_error_variant(const IpEndpoint& peer,
                                  const IpEndpoint& outer_source,
                                  const IpEndpoint& inner_source,
                                  const IpEndpoint& inner_destination,
                                  std::uint16_t inner_source_port,
                                  std::uint16_t inner_destination_port,
                                  std::uint16_t marker,
                                  IcmpErrorVariant variant) {
    if (peer.family != AF_INET || outer_source.family != AF_INET || inner_source.family != AF_INET ||
        inner_destination.family != AF_INET) {
        return false;
    }

    int raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_fd < 0) {
        return false;
    }
    int enable = 1;
    if (setsockopt(raw_fd, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)) != 0) {
        close(raw_fd);
        return false;
    }

    std::vector<std::uint8_t> packet(sizeof(iphdr) + sizeof(icmphdr) + sizeof(iphdr) + sizeof(udphdr), 0);
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
    std::memcpy(&outer_ip->daddr, peer.address.data(), 4);
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
    inner_ip->tot_len = htons(sizeof(iphdr) + sizeof(udphdr));
    inner_ip->id = htons(marker);
    inner_ip->frag_off = 0;
    inner_ip->ttl = 64;
    inner_ip->protocol = IPPROTO_UDP;
    std::memcpy(&inner_ip->saddr, inner_source.address.data(), 4);
    std::memcpy(&inner_ip->daddr, inner_destination.address.data(), 4);
    inner_ip->check = 0;
    inner_ip->check = calculate_checksum(inner_ip, sizeof(iphdr));

    auto* inner_udp = reinterpret_cast<udphdr*>(packet.data() + sizeof(iphdr) + sizeof(icmphdr) + sizeof(iphdr));
    inner_udp->source = htons(inner_source_port);
    inner_udp->dest = htons(inner_destination_port);
    inner_udp->len = htons(sizeof(udphdr));
    inner_udp->check = 0;
    inner_udp->check = calculate_udp_checksum_ipv4(*inner_ip, *inner_udp, nullptr, 0);
    if (inner_udp->check == 0) {
        inner_udp->check = 0xFFFF;
    }

    if (variant == IcmpErrorVariant::BadInnerIpChecksum) {
        inner_ip->check ^= htons(0x00FF);
    } else if (variant == IcmpErrorVariant::BadUdpChecksum) {
        inner_udp->check ^= htons(0x00FF);
    }

    icmp->checksum = calculate_checksum(icmp, packet.size() - sizeof(iphdr));
    if (variant == IcmpErrorVariant::BadOuterChecksum) {
        icmp->checksum ^= htons(0x00FF);
    }

    sockaddr_in dest{};
    dest.sin_family = AF_INET;
    std::memcpy(&dest.sin_addr, peer.address.data(), 4);
    const ssize_t sent = sendto(raw_fd, packet.data(), packet.size(), 0, reinterpret_cast<sockaddr*>(&dest), sizeof(dest));
    close(raw_fd);
    return sent == static_cast<ssize_t>(packet.size());
}

bool send_out_of_order_fragmented_udp_ipv4(const IpEndpoint& peer, const IpEndpoint& local) {
    if (peer.family != AF_INET || local.family != AF_INET) {
        return false;
    }

    int raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_fd < 0) {
        std::cerr << "Warning: Failed to create raw socket for out-of-order fragments. Error: "
                  << std::strerror(errno) << '\n';
        return false;
    }
    int enable = 1;
    if (setsockopt(raw_fd, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)) != 0) {
        close(raw_fd);
        return false;
    }

    constexpr std::size_t first_payload_size = 16;
    constexpr std::size_t second_payload_size = kRfc4787OutOfOrderFragmentPayload.size() - first_payload_size;
    constexpr std::size_t first_fragment_data_len = sizeof(udphdr) + first_payload_size;
    constexpr std::size_t second_fragment_data_len = second_payload_size;

    std::array<std::uint8_t, first_payload_size> first_payload{};
    std::array<std::uint8_t, second_payload_size> second_payload{};
    std::memcpy(first_payload.data(), kRfc4787OutOfOrderFragmentPayload.data(), first_payload.size());
    std::memcpy(second_payload.data(),
                kRfc4787OutOfOrderFragmentPayload.data() + first_payload.size(),
                second_payload.size());

    iphdr ip_base{};
    ip_base.ihl = 5;
    ip_base.version = 4;
    ip_base.tos = 0;
    ip_base.id = htons(0x4A87);
    ip_base.ttl = 64;
    ip_base.protocol = IPPROTO_UDP;
    std::memcpy(&ip_base.saddr, local.address.data(), 4);
    std::memcpy(&ip_base.daddr, peer.address.data(), 4);

    udphdr udp{};
    udp.source = htons(local.port);
    udp.dest = htons(peer.port);
    udp.len = htons(sizeof(udphdr) + first_payload.size() + second_payload.size());
    udp.check = 0;
    udp.check = calculate_udp_checksum_ipv4(ip_base, udp, reinterpret_cast<const std::uint8_t*>(kRfc4787OutOfOrderFragmentPayload.data()),
                                            kRfc4787OutOfOrderFragmentPayload.size());
    if (udp.check == 0) {
        udp.check = 0xFFFF;
    }

    std::vector<std::uint8_t> first_fragment(sizeof(iphdr) + first_fragment_data_len, 0);
    auto* first_ip = reinterpret_cast<iphdr*>(first_fragment.data());
    *first_ip = ip_base;
    first_ip->tot_len = htons(first_fragment.size());
    first_ip->frag_off = htons(IP_MF);
    first_ip->check = 0;
    first_ip->check = calculate_checksum(first_ip, sizeof(iphdr));
    std::memcpy(first_fragment.data() + sizeof(iphdr), &udp, sizeof(udphdr));
    std::memcpy(first_fragment.data() + sizeof(iphdr) + sizeof(udphdr), first_payload.data(), first_payload.size());

    std::vector<std::uint8_t> second_fragment(sizeof(iphdr) + second_fragment_data_len, 0);
    auto* second_ip = reinterpret_cast<iphdr*>(second_fragment.data());
    *second_ip = ip_base;
    second_ip->tot_len = htons(second_fragment.size());
    second_ip->frag_off = htons(static_cast<std::uint16_t>(first_fragment_data_len / 8));
    second_ip->check = 0;
    second_ip->check = calculate_checksum(second_ip, sizeof(iphdr));
    std::memcpy(second_fragment.data() + sizeof(iphdr), second_payload.data(), second_payload.size());

    sockaddr_in destination{};
    destination.sin_family = AF_INET;
    std::memcpy(&destination.sin_addr, peer.address.data(), 4);

    ssize_t second_sent = sendto(raw_fd,
                                 second_fragment.data(),
                                 second_fragment.size(),
                                 0,
                                 reinterpret_cast<sockaddr*>(&destination),
                                 sizeof(destination));
    if (second_sent != static_cast<ssize_t>(second_fragment.size())) {
        close(raw_fd);
        return false;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    ssize_t first_sent = sendto(raw_fd,
                                first_fragment.data(),
                                first_fragment.size(),
                                0,
                                reinterpret_cast<sockaddr*>(&destination),
                                sizeof(destination));
    close(raw_fd);
    return first_sent == static_cast<ssize_t>(first_fragment.size());
}
// ---------------------------------------------------------

std::optional<std::uint16_t> parse_payload_id(std::string_view payload, std::string_view token) {
    const std::string prefix = "VID:" + std::string(token) + ":";
    if (!payload.starts_with(prefix)) {
        return std::nullopt;
    }
    std::string_view id_text = payload.substr(prefix.size());
    const std::size_t newline = id_text.find('\n');
    if (newline != std::string_view::npos) {
        id_text = id_text.substr(0, newline);
    }
    if (id_text.empty()) {
        return std::nullopt;
    }
    try {
        const int parsed = std::stoi(std::string(id_text));
        if (parsed < 0 || parsed > 65535) {
            return std::nullopt;
        }
        return static_cast<std::uint16_t>(parsed);
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<std::uint16_t> observe_udp_ipv4_id(const IpEndpoint& peer,
                                                 const IpEndpoint& local,
                                                 std::string_view token,
                                                 int timeout_ms) {
    if (peer.family != AF_INET || local.family != AF_INET) {
        return std::nullopt;
    }
    int raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (raw_fd < 0) {
        return std::nullopt;
    }

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    try {
        while (std::chrono::steady_clock::now() < deadline) {
            const int remaining = static_cast<int>(
                std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count());
            if (remaining <= 0) {
                break;
            }
            pollfd descriptor{raw_fd, POLLIN, 0};
            if (poll(&descriptor, 1, remaining) <= 0 || (descriptor.revents & POLLIN) == 0) {
                continue;
            }

            std::array<std::uint8_t, 2048> buffer{};
            const ssize_t received = recv(raw_fd, buffer.data(), buffer.size(), 0);
            if (received <= static_cast<ssize_t>(sizeof(iphdr) + sizeof(udphdr))) {
                continue;
            }

            const auto* ip_header = reinterpret_cast<const iphdr*>(buffer.data());
            if (ip_header->version != 4 || ip_header->protocol != IPPROTO_UDP) {
                continue;
            }
            const std::size_t ip_header_length = static_cast<std::size_t>(ip_header->ihl) * 4;
            if (ip_header_length < sizeof(iphdr) || received <= static_cast<ssize_t>(ip_header_length + sizeof(udphdr))) {
                continue;
            }
            const auto* udp_header =
                reinterpret_cast<const udphdr*>(buffer.data() + ip_header_length);
            if (ntohs(udp_header->dest) != local.port) {
                continue;
            }
            if (std::memcmp(&ip_header->saddr, peer.address.data(), 4) != 0 ||
                std::memcmp(&ip_header->daddr, local.address.data(), 4) != 0) {
                continue;
            }

            const char* payload_data = reinterpret_cast<const char*>(buffer.data() + ip_header_length + sizeof(udphdr));
            const std::size_t payload_size =
                static_cast<std::size_t>(received) - ip_header_length - sizeof(udphdr);
            std::string_view payload(payload_data, payload_size);
            std::optional<std::uint16_t> payload_id = parse_payload_id(payload, token);
            if (!payload_id.has_value()) {
                continue;
            }
            const std::uint16_t observed_id = ntohs(ip_header->id);
            close(raw_fd);
            return observed_id;
        }
        close(raw_fd);
        return std::nullopt;
    } catch (...) {
        close(raw_fd);
        return std::nullopt;
    }
}


bool try_connect_from_source(const IpEndpoint& source_address_only, const IpEndpoint& target, int timeout_ms) {
    int socket_fd = socket(target.family, SOCK_STREAM, IPPROTO_TCP);
    if (socket_fd < 0) {
        return false;
    }

    bool success = false;
    try {
        set_reuse_options(socket_fd);
        SocketAddress source = to_sockaddr(source_address_only);
        if (bind(socket_fd, reinterpret_cast<sockaddr*>(&source.storage), source.length) != 0) {
            close(socket_fd);
            return false;
        }

        const int flags = fcntl(socket_fd, F_GETFL, 0);
        if (flags < 0 || fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK) != 0) {
            close(socket_fd);
            return false;
        }

        SocketAddress destination = to_sockaddr(target);
        int rc = connect(socket_fd, reinterpret_cast<sockaddr*>(&destination.storage), destination.length);
        if (rc == 0) {
            success = true;
        } else if (errno == EINPROGRESS) {
            pollfd descriptor{socket_fd, POLLOUT, 0};
            rc = poll(&descriptor, 1, timeout_ms);
            if (rc > 0) {
                int error = 0;
                socklen_t error_length = sizeof(error);
                if (getsockopt(socket_fd, SOL_SOCKET, SO_ERROR, &error, &error_length) == 0 && error == 0) {
                    success = true;
                }
            }
        }
    } catch (...) {
        success = false;
    }

    close(socket_fd);
    return success;
}

bool try_send_udp_from_source(const IpEndpoint& source_address_only, const IpEndpoint& target, std::string_view payload) {
    int socket_fd = socket(target.family, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd < 0) {
        return false;
    }

    bool success = false;
    try {
        set_reuse_options(socket_fd);
        bind_socket(socket_fd, source_address_only);
        SocketAddress destination = to_sockaddr(target);
        const ssize_t sent =
            sendto(socket_fd, payload.data(), payload.size(), 0, reinterpret_cast<sockaddr*>(&destination.storage), destination.length);
        success = sent > 0;
    } catch (...) {
        success = false;
    }
    close(socket_fd);
    return success;
}

std::optional<std::string> parse_rfc5508_mapping_token(std::string_view payload) {
    constexpr std::string_view prefix = "RFC5508-M:";
    if (!payload.starts_with(prefix)) {
        return std::nullopt;
    }
    std::string token(payload.substr(prefix.size()));
    const std::size_t newline = token.find('\n');
    if (newline != std::string::npos) {
        token = token.substr(0, newline);
    }
    if (token.empty()) {
        return std::nullopt;
    }
    return token;
}

void handle_icmp_packet(int raw_fd, IcmpRawContext& icmp_context) {
    std::array<std::uint8_t, 4096> buffer{};
    sockaddr_storage peer{};
    socklen_t peer_length = sizeof(peer);
    const ssize_t received =
        recvfrom(raw_fd, buffer.data(), buffer.size(), 0, reinterpret_cast<sockaddr*>(&peer), &peer_length);
    if (received <= static_cast<ssize_t>(sizeof(iphdr) + sizeof(icmphdr))) {
        return;
    }

    const auto* ip_header = reinterpret_cast<const iphdr*>(buffer.data());
    if (ip_header->version != 4 || ip_header->protocol != IPPROTO_ICMP) {
        return;
    }
    const std::size_t ip_header_length = static_cast<std::size_t>(ip_header->ihl) * 4;
    if (received <= static_cast<ssize_t>(ip_header_length + sizeof(icmphdr))) {
        return;
    }

    const auto* icmp = reinterpret_cast<const icmphdr*>(buffer.data() + ip_header_length);
    if (icmp->type == ICMP_DEST_UNREACH && icmp->code == ICMP_PORT_UNREACH) {
        const std::size_t min_size = ip_header_length + sizeof(icmphdr) + sizeof(iphdr) + sizeof(udphdr);
        if (static_cast<std::size_t>(received) >= min_size) {
            const auto* inner_ip = reinterpret_cast<const iphdr*>(buffer.data() + ip_header_length + sizeof(icmphdr));
            if (inner_ip->version == 4 && inner_ip->protocol == IPPROTO_UDP) {
                const std::uint16_t marker = ntohs(inner_ip->id);
                std::lock_guard<std::mutex> lock(icmp_context.observed_error_markers_mutex);
                icmp_context.observed_error_markers.insert(marker);
            }
        }
        return;
    }
    if (icmp->type != ICMP_ECHO || icmp->code != 0) {
        return;
    }

    const char* payload_data = reinterpret_cast<const char*>(buffer.data() + ip_header_length + sizeof(icmphdr));
    const std::size_t payload_size = static_cast<std::size_t>(received) - ip_header_length - sizeof(icmphdr);
    std::string_view payload(payload_data, payload_size);

    IpEndpoint peer_endpoint = from_sockaddr(reinterpret_cast<sockaddr*>(&peer), peer_length);
    if (std::optional<std::string> token = parse_rfc5508_mapping_token(payload); token.has_value()) {
        IcmpMappingRecord record;
        record.peer_host = endpoint_host(peer_endpoint);
        record.mapped_query = ntohs(icmp->un.echo.id);
        std::lock_guard<std::mutex> lock(icmp_context.mappings_mutex);
        icmp_context.mappings[*token] = record;
    }

    send_icmp_echo(raw_fd,
                   peer_endpoint,
                   ICMP_ECHOREPLY,
                   ntohs(icmp->un.echo.id),
                   ntohs(icmp->un.echo.sequence),
                   std::string(payload));
}

void handle_tcp_client(int client_fd,
                       const IpEndpoint& primary_server,
                       const IpEndpoint& secondary_server,
                       IcmpRawContext& icmp_context,
                       int connection_probe_timeout_ms,
                       int syn_delay_ms) {
    try {
        constexpr int kTcpClientCommandTimeoutMs = 30 * 1000;
        sockaddr_storage peer{};
        socklen_t peer_length = sizeof(peer);
        if (getpeername(client_fd, reinterpret_cast<sockaddr*>(&peer), &peer_length) != 0) {
            throw system_error("getpeername failed");
        }
        IpEndpoint peer_endpoint = from_sockaddr(reinterpret_cast<sockaddr*>(&peer), peer_length);
        
        while (true) {
            std::string command = recv_line(client_fd, kTcpClientCommandTimeoutMs);
            if (command.empty()) {
                return;
            }
            if (command == "M") {
                send_all(client_fd, endpoint_line(peer_endpoint));
                continue;
            }
            if (command == "F") {
                IpEndpoint primary_source = primary_server;
                primary_source.port = 0;
                IpEndpoint secondary_source = secondary_server;
                secondary_source.port = 0;
                bool primary_ok = try_connect_from_source(primary_source, peer_endpoint, connection_probe_timeout_ms);
                bool secondary_ok = try_connect_from_source(secondary_source, peer_endpoint, connection_probe_timeout_ms);
                send_all(client_fd, std::string("P=") + (primary_ok ? "1" : "0") + " S=" + (secondary_ok ? "1" : "0") + "\n");
                continue;
            }
            if (command == "S") {
                IpEndpoint immediate_source = secondary_server;
                immediate_source.port = 0;
                IpEndpoint delayed_source = primary_server;
                delayed_source.port = 0;
                bool immediate_ok = try_connect_from_source(immediate_source, peer_endpoint, connection_probe_timeout_ms);
                std::this_thread::sleep_for(std::chrono::milliseconds(syn_delay_ms));
                bool delayed_ok = try_connect_from_source(delayed_source, peer_endpoint, connection_probe_timeout_ms);
                send_all(client_fd, std::string("I=") + (immediate_ok ? "1" : "0") + " D=" + (delayed_ok ? "1" : "0") + "\n");
                continue;
            }
            if (command == "U") {
                IpEndpoint udp_source = primary_server;
                udp_source.port = 0;
                bool sent = try_send_udp_from_source(udp_source, peer_endpoint, kRfc7857UdpProbePayload);
                send_all(client_fd, std::string("R=") + (sent ? "1" : "0") + "\n");
                continue;
            }
            if (command.rfind("C ", 0) == 0) {
                const std::string endpoint_literal = command.substr(2);
                auto [target_host, target_port] = split_host_port(endpoint_literal, 0);
                IpEndpoint target = resolve_endpoint(target_host, target_port);
                IpEndpoint source = primary_server;
                source.port = 0;
                bool connected = try_connect_from_source(source, target, connection_probe_timeout_ms);
                send_all(client_fd, std::string("R=") + (connected ? "1" : "0") + "\n");
                continue;
            }
            // 新增: TCP 指令 `I`，用于触发 ICMP 错误测试
            if (command == "I") {
                sockaddr_storage local_addr{};
                socklen_t local_length = sizeof(local_addr);
                getsockname(client_fd, reinterpret_cast<sockaddr*>(&local_addr), &local_length);
                IpEndpoint local_endpoint = from_sockaddr(reinterpret_cast<sockaddr*>(&local_addr), local_length);

                bool icmp_sent = send_ipv4_icmp_error(peer_endpoint, local_endpoint, IPPROTO_TCP);
                send_all(client_fd, std::string("I=") + (icmp_sent ? "1" : "0") + "\n");
                continue;
            }
            if (command.rfind("V ", 0) == 0) {
                std::string token = command.substr(2);
                sockaddr_storage local_addr{};
                socklen_t local_length = sizeof(local_addr);
                getsockname(client_fd, reinterpret_cast<sockaddr*>(&local_addr), &local_length);
                IpEndpoint local_endpoint = from_sockaddr(reinterpret_cast<sockaddr*>(&local_addr), local_length);

                std::optional<std::uint16_t> observed_id =
                    observe_udp_ipv4_id(peer_endpoint, local_endpoint, token, connection_probe_timeout_ms);
                if (!observed_id.has_value()) {
                    send_all(client_fd, "V=-1\n");
                } else {
                    send_all(client_fd, "V=" + std::to_string(*observed_id) + "\n");
                }
                continue;
            }
            if (command.rfind("IE ", 0) == 0) {
                std::istringstream stream(command);
                std::string op;
                std::string target_literal;
                std::uint16_t marker_outer = 0;
                std::uint16_t marker_inner = 0;
                std::uint16_t marker_udp = 0;
                if (!(stream >> op >> target_literal >> marker_outer >> marker_inner >> marker_udp)) {
                    send_all(client_fd, "E=0\n");
                    continue;
                }

                auto [target_host, target_port] = split_host_port(target_literal, 0);
                IpEndpoint target = resolve_endpoint(target_host, target_port);
                if (target.family != AF_INET || peer_endpoint.family != AF_INET || primary_server.family != AF_INET) {
                    send_all(client_fd, "E=0\n");
                    continue;
                }

                const bool sent_outer = send_ipv4_icmp_error_variant(target,
                                                                     primary_server,
                                                                     peer_endpoint,
                                                                     primary_server,
                                                                     target.port,
                                                                     primary_server.port,
                                                                     marker_outer,
                                                                     IcmpErrorVariant::BadOuterChecksum);
                const bool sent_inner = send_ipv4_icmp_error_variant(target,
                                                                     primary_server,
                                                                     peer_endpoint,
                                                                     primary_server,
                                                                     target.port,
                                                                     primary_server.port,
                                                                     marker_inner,
                                                                     IcmpErrorVariant::BadInnerIpChecksum);
                const bool sent_udp = send_ipv4_icmp_error_variant(target,
                                                                    primary_server,
                                                                    peer_endpoint,
                                                                    primary_server,
                                                                    target.port,
                                                                    primary_server.port,
                                                                    marker_udp,
                                                                    IcmpErrorVariant::BadUdpChecksum);
                send_all(client_fd, std::string("E=") + ((sent_outer && sent_inner && sent_udp) ? "1" : "0") + "\n");
                continue;
            }
            if (command == "IRR") {
                {
                    std::lock_guard<std::mutex> lock(icmp_context.observed_error_markers_mutex);
                    icmp_context.observed_error_markers.clear();
                }
                send_all(client_fd, "R=1\n");
                continue;
            }
            if (command.rfind("IR ", 0) == 0) {
                std::istringstream stream(command);
                std::string op;
                std::uint16_t marker = 0;
                if (!(stream >> op >> marker)) {
                    send_all(client_fd, "R=0\n");
                    continue;
                }
                bool seen = false;
                {
                    std::lock_guard<std::mutex> lock(icmp_context.observed_error_markers_mutex);
                    seen = icmp_context.observed_error_markers.contains(marker);
                }
                send_all(client_fd, std::string("R=") + (seen ? "1" : "0") + "\n");
                continue;
            }
            if (command.rfind("IM ", 0) == 0) {
                const std::string token = command.substr(3);
                std::optional<IcmpMappingRecord> record;
                {
                    std::lock_guard<std::mutex> lock(icmp_context.mappings_mutex);
                    auto it = icmp_context.mappings.find(token);
                    if (it != icmp_context.mappings.end()) {
                        record = it->second;
                    }
                }
                if (!record.has_value()) {
                    send_all(client_fd, "ERR\n");
                    continue;
                }
                send_all(client_fd, "M " + record->peer_host + " " + std::to_string(record->mapped_query) + "\n");
                continue;
            }
            if (command.rfind("IF ", 0) == 0) {
                std::istringstream stream(command);
                std::string op;
                std::string role;
                std::string token;
                std::uint16_t probe_query = 0;
                if (!(stream >> op >> role >> token >> probe_query) || role.size() != 1) {
                    send_all(client_fd, "F=0\n");
                    continue;
                }
                std::optional<IcmpMappingRecord> record;
                {
                    std::lock_guard<std::mutex> lock(icmp_context.mappings_mutex);
                    auto it = icmp_context.mappings.find(token);
                    if (it != icmp_context.mappings.end()) {
                        record = it->second;
                    }
                }
                if (!record.has_value()) {
                    send_all(client_fd, "F=0\n");
                    continue;
                }

                int raw_fd = role[0] == 'P' ? icmp_context.primary_socket
                                            : (role[0] == 'S' ? icmp_context.secondary_socket : -1);
                if (raw_fd < 0) {
                    send_all(client_fd, "F=0\n");
                    continue;
                }
                IpEndpoint target = resolve_endpoint(record->peer_host, 0);
                target.port = 0;
                const std::string payload = "RFC5508-F:" + token + ":" + std::to_string(probe_query);
                const bool sent =
                    send_icmp_echo(raw_fd, target, ICMP_ECHO, record->mapped_query, probe_query, payload);
                send_all(client_fd, std::string("F=") + (sent ? "1" : "0") + "\n");
                continue;
            }
            send_all(client_fd, "ERR\n");
        }
    } catch (...) {
    }
}

void handle_udp_packet(int udp_fd, const IpEndpoint& server_endpoint) {
    constexpr std::size_t UDP_BUFFER_SIZE = 4096;
    sockaddr_storage peer{};
    socklen_t peer_length = sizeof(peer);
    std::vector<char> buffer(UDP_BUFFER_SIZE);
    ssize_t received = recvfrom(udp_fd, buffer.data(), buffer.size(), 0, reinterpret_cast<sockaddr*>(&peer), &peer_length);
    if (received <= 0) {
        return;
    }

    const bool is_mapping_request = received >= 1 && buffer[0] == 'M';
    if (is_mapping_request) {
        IpEndpoint peer_endpoint = from_sockaddr(reinterpret_cast<sockaddr*>(&peer), peer_length);
        std::string payload = endpoint_line(peer_endpoint);
        sendto(udp_fd, payload.data(), payload.size(), 0, reinterpret_cast<sockaddr*>(&peer), peer_length);
        return;
    }

    // 新增: UDP 指令 `I`，触发发往该 UDP 映射的 ICMP 包
    const bool is_icmp_request = received >= 1 && buffer[0] == 'I';
    if (is_icmp_request) {
        IpEndpoint peer_endpoint = from_sockaddr(reinterpret_cast<sockaddr*>(&peer), peer_length);
        bool sent = send_ipv4_icmp_error(peer_endpoint, server_endpoint, IPPROTO_UDP);
        std::string reply = std::string("I=") + (sent ? "1" : "0") + "\n";
        sendto(udp_fd, reply.data(), reply.size(), 0, reinterpret_cast<sockaddr*>(&peer), peer_length);
        return;
    }

    const bool is_out_of_order_fragment_request = received >= 1 && buffer[0] == 'O';
    if (is_out_of_order_fragment_request) {
        IpEndpoint peer_endpoint = from_sockaddr(reinterpret_cast<sockaddr*>(&peer), peer_length);
        bool sent = send_out_of_order_fragmented_udp_ipv4(peer_endpoint, server_endpoint);
        std::string reply = std::string("O=") + (sent ? "1" : "0") + "\n";
        sendto(udp_fd, reply.data(), reply.size(), 0, reinterpret_cast<sockaddr*>(&peer), peer_length);
        return;
    }

    sendto(udp_fd, buffer.data(), static_cast<std::size_t>(received), 0, reinterpret_cast<sockaddr*>(&peer), peer_length);
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc < 3) {
            fail("Insufficient arguments. Use --help for usage information.");
        }

        std::optional<std::string> primary_arg;
        std::optional<std::string> secondary_arg;
        int connection_probe_timeout_ms = 1200;
        int syn_delay_ms = 350;
        for (int index = 1; index < argc; ++index) {
            std::string token = argv[index];
            if (token == "--primary" && index + 1 < argc) {
                primary_arg = argv[++index];
            } else if (token == "--secondary" && index + 1 < argc) {
                secondary_arg = argv[++index];
            } else if (token == "--probe-timeout-ms" && index + 1 < argc) {
                connection_probe_timeout_ms = std::stoi(argv[++index]);
            } else if (token == "--syn-delay-ms" && index + 1 < argc) {
                syn_delay_ms = std::stoi(argv[++index]);
            } else if (token == "--help" || token == "-h") {
                std::cout << "Usage: sudo nat_type_tester_server --primary host[:port] --secondary host[:port] [--probe-timeout-ms 1200] [--syn-delay-ms 350]\n";
                return 0;
            } else {
                fail("Unknown or incomplete argument: " + token);
            }
        }

        if (!primary_arg.has_value() || !secondary_arg.has_value()) {
            fail("Both --primary and --secondary are required.");
        }

        constexpr std::uint16_t default_port = 3478;
        auto [primary_host, primary_port] = split_host_port(*primary_arg, default_port);
        auto [secondary_host, secondary_port] = split_host_port(*secondary_arg, default_port);
        IpEndpoint primary_server = resolve_endpoint(primary_host, primary_port);
        IpEndpoint secondary_server = resolve_endpoint(secondary_host, secondary_port);
        if (primary_server.family != secondary_server.family) {
            fail("Primary and secondary addresses must use the same family.");
        }

        try_disable_kernel_icmp_echo_auto_reply();

        int primary_tcp_fd = create_tcp_listener(primary_server);
        int secondary_tcp_fd = create_tcp_listener(secondary_server);
        int primary_udp_fd = create_udp_listener(primary_server);
        int secondary_udp_fd = create_udp_listener(secondary_server);
        IcmpRawContext icmp_context;
        icmp_context.primary_server = primary_server;
        icmp_context.secondary_server = secondary_server;
        if (primary_server.family == AF_INET) {
            icmp_context.primary_socket = create_icmp_raw_listener(primary_server);
            icmp_context.secondary_socket = create_icmp_raw_listener(secondary_server);
        }

        std::cout << "Server ready. Primary=" << primary_host << ":" << primary_port
                  << " Secondary=" << secondary_host << ":" << secondary_port << '\n';
        std::cout << "Note: Must run as root (sudo) for ICMP Raw socket testing to work.\n";

        while (true) {
            std::array<pollfd, 6> descriptors{{
                {primary_tcp_fd, POLLIN, 0},
                {secondary_tcp_fd, POLLIN, 0},
                {primary_udp_fd, POLLIN, 0},
                {secondary_udp_fd, POLLIN, 0},
                {icmp_context.primary_socket, POLLIN, 0},
                {icmp_context.secondary_socket, POLLIN, 0},
            }};
            int rc = poll(descriptors.data(), descriptors.size(), -1);
            if (rc < 0) {
                throw system_error("poll failed");
            }

            if (descriptors[2].revents & POLLIN) {
                handle_udp_packet(primary_udp_fd, primary_server);
            }
            if (descriptors[3].revents & POLLIN) {
                handle_udp_packet(secondary_udp_fd, secondary_server);
            }
            if (icmp_context.primary_socket >= 0 && (descriptors[4].revents & POLLIN)) {
                handle_icmp_packet(icmp_context.primary_socket, icmp_context);
            }
            if (icmp_context.secondary_socket >= 0 && (descriptors[5].revents & POLLIN)) {
                handle_icmp_packet(icmp_context.secondary_socket, icmp_context);
            }
            if (descriptors[0].revents & POLLIN) {
                sockaddr_storage client{};
                socklen_t length = sizeof(client);
                int client_fd = accept(primary_tcp_fd, reinterpret_cast<sockaddr*>(&client), &length);
                if (client_fd >= 0) {
                    std::thread([client_fd,
                                 primary_server,
                                 secondary_server,
                                 &icmp_context,
                                 connection_probe_timeout_ms,
                                 syn_delay_ms]() {
                        handle_tcp_client(client_fd,
                                          primary_server,
                                          secondary_server,
                                          icmp_context,
                                          connection_probe_timeout_ms,
                                          syn_delay_ms);
                        close(client_fd);
                    }).detach();
                }
            }
            if (descriptors[1].revents & POLLIN) {
                sockaddr_storage client{};
                socklen_t length = sizeof(client);
                int client_fd = accept(secondary_tcp_fd, reinterpret_cast<sockaddr*>(&client), &length);
                if (client_fd >= 0) {
                    std::thread([client_fd,
                                 primary_server,
                                 secondary_server,
                                 &icmp_context,
                                 connection_probe_timeout_ms,
                                 syn_delay_ms]() {
                        handle_tcp_client(client_fd,
                                          primary_server,
                                          secondary_server,
                                          icmp_context,
                                          connection_probe_timeout_ms,
                                          syn_delay_ms);
                        close(client_fd);
                    }).detach();
                }
            }
        }
    } catch (const std::exception& exception) {
        std::cerr << "Error: " << exception.what() << '\n';
        return 1;
    }
}
