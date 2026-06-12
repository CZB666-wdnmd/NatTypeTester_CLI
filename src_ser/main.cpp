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

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

#include <algorithm>
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
    StunNode tls_nodes[4];
    IcmpRawContext icmp_ctx;
};

enum class IcmpErrorVariant : std::uint8_t {
    BadOuterChecksum = 1,
    BadInnerIpChecksum = 2,
    BadUdpChecksum = 3,
};

SSL_CTX* tls_ctx = nullptr;
SSL_CTX* dtls_ctx = nullptr;
X509* generated_cert = nullptr;
EVP_PKEY* generated_key = nullptr;

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
    if (!run_shell_command("nft list table ip raw >/dev/null 2>&1") &&
        !run_shell_command("nft add table ip raw >/dev/null 2>&1")) ok = false;
    if (!run_shell_command("nft list chain ip raw prerouting >/dev/null 2>&1") &&
        !run_shell_command("nft add chain ip raw prerouting '{ type filter hook prerouting priority raw; }' >/dev/null 2>&1")) ok = false;
    if (!run_shell_command("nft list chain ip raw output >/dev/null 2>&1") &&
        !run_shell_command("nft add chain ip raw output '{ type filter hook output priority raw; }' >/dev/null 2>&1")) ok = false;
    
    if (!run_shell_command("nft list chain ip raw output 2>/dev/null | grep -Eq '^[[:space:]]*ip protocol icmp notrack([[:space:]].*)?$'")) {
        if (!run_shell_command("nft add rule ip raw output ip protocol icmp notrack >/dev/null 2>&1")) ok = false;
    }
    if (!run_shell_command("nft list chain ip raw prerouting 2>/dev/null | grep -Eq '^[[:space:]]*ip protocol icmp notrack([[:space:]].*)?$'")) {
        if (!run_shell_command("nft add rule ip raw prerouting ip protocol icmp notrack >/dev/null 2>&1")) ok = false;
    }
    return ok;
}

void ensure_icmp_conntrack_bypass() {
    bool configured = ensure_iptables_icmp_notrack();
    if (!configured) configured = ensure_nftables_icmp_notrack();
    if (configured) {
        std::cout << "Note: ICMP conntrack bypass (notrack) is active for raw ICMP probes.\n";
        return;
    }
    if (geteuid() != 0) std::cerr << "Warning: ICMP notrack rules not configured (run as root). Raw ICMP probes may be dropped.\n";
    else std::cerr << "Warning: Failed to configure ICMP notrack rules via iptables/nft.\n";
}

static bool s_fragment_rules_added = false;

bool ensure_iptables_fragment_notrack() {
    if (!command_exists("iptables")) return false;
    bool ok = true;
    constexpr const char* kOutputMatch = "-m u32 --u32 \"" "6 & 0x3FFF != 0" "\" -j CT --notrack";
    constexpr const char* kPreroutingMatch = "-m u32 --u32 \"" "6 & 0x3FFF != 0" "\" -j CT --notrack";

    bool has_u32 = run_shell_command("iptables -m u32 -h >/dev/null 2>&1");
    auto try_add_rule = [&](const char* chain, const char* match) -> bool {
        if (!run_shell_command(std::string("iptables -t raw -C ") + chain + " " + match + " >/dev/null 2>&1")) {
            if (!run_shell_command(std::string("iptables -t raw -I ") + chain + " " + match + " >/dev/null 2>&1")) return false;
        }
        return true;
    };

    if (has_u32) {
        if (!try_add_rule("OUTPUT", kOutputMatch)) ok = false;
        if (!try_add_rule("PREROUTING", kPreroutingMatch)) ok = false;
    } else {
        if (!run_shell_command("iptables -t raw -C OUTPUT -f -j CT --notrack >/dev/null 2>&1")) {
            if (!run_shell_command("iptables -t raw -I OUTPUT -f -j CT --notrack >/dev/null 2>&1")) ok = false;
        }
        if (!run_shell_command("iptables -t raw -C PREROUTING -f -j CT --notrack >/dev/null 2>&1")) {
            if (!run_shell_command("iptables -t raw -I PREROUTING -f -j CT --notrack >/dev/null 2>&1")) ok = false;
        }
    }
    return ok;
}

bool ensure_nftables_fragment_notrack() {
    if (!command_exists("nft")) return false;
    bool ok = true;
    if (!run_shell_command("nft list table ip nat_type_tester_frag >/dev/null 2>&1") &&
        !run_shell_command("nft add table ip nat_type_tester_frag >/dev/null 2>&1")) ok = false;
    if (!run_shell_command("nft list chain ip nat_type_tester_frag prerouting >/dev/null 2>&1") &&
        !run_shell_command("nft add chain ip nat_type_tester_frag prerouting '{ type filter hook prerouting priority raw; }' >/dev/null 2>&1")) ok = false;
    if (!run_shell_command("nft list chain ip nat_type_tester_frag output >/dev/null 2>&1") &&
        !run_shell_command("nft add chain ip nat_type_tester_frag output '{ type filter hook output priority raw; }' >/dev/null 2>&1")) ok = false;
    if (!run_shell_command("nft list chain ip nat_type_tester_frag output 2>/dev/null | grep -Eq 'ip frag-off .* notrack'")) {
        if (!run_shell_command("nft add rule ip nat_type_tester_frag output ip frag-off '&' 0x3fff != 0 notrack >/dev/null 2>&1")) ok = false;
    }
    if (!run_shell_command("nft list chain ip nat_type_tester_frag prerouting 2>/dev/null | grep -Eq 'ip frag-off .* notrack'")) {
        if (!run_shell_command("nft add rule ip nat_type_tester_frag prerouting ip frag-off '&' 0x3fff != 0 notrack >/dev/null 2>&1")) ok = false;
    }
    return ok;
}

void cleanup_fragment_conntrack_bypass() {
    if (!s_fragment_rules_added) return;
    s_fragment_rules_added = false;
    if (command_exists("iptables")) {
        run_shell_command("iptables -t raw -D OUTPUT -m u32 --u32 \"6 & 0x3FFF != 0\" -j CT --notrack >/dev/null 2>&1");
        run_shell_command("iptables -t raw -D PREROUTING -m u32 --u32 \"6 & 0x3FFF != 0\" -j CT --notrack >/dev/null 2>&1");
        run_shell_command("iptables -t raw -D OUTPUT -f -j CT --notrack >/dev/null 2>&1");
        run_shell_command("iptables -t raw -D PREROUTING -f -j CT --notrack >/dev/null 2>&1");
    }
    if (command_exists("nft")) run_shell_command("nft delete table ip nat_type_tester_frag >/dev/null 2>&1");
}

void ensure_fragment_conntrack_bypass() {
    bool configured = ensure_nftables_fragment_notrack();
    if (!configured) configured = ensure_iptables_fragment_notrack();
    s_fragment_rules_added = configured;
    if (configured) {
        std::cout << "Note: IP Fragment conntrack bypass (notrack) is active.\n";
        std::atexit(cleanup_fragment_conntrack_bypass);
        return;
    }
    if (geteuid() != 0) std::cerr << "Warning: Fragment notrack rules not configured (run as root). OutOfOrderTest may fail.\n";
    else std::cerr << "Warning: Failed to configure fragment notrack rules via iptables/nft.\n";
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
            if (std::memcmp(&ipv4->sin_addr, endpoint.address.data(), 4) == 0) return ifa->ifa_name;
        } else if (endpoint.family == AF_INET6) {
            auto* ipv6 = reinterpret_cast<sockaddr_in6*>(ifa->ifa_addr);
            if (std::memcmp(&ipv6->sin6_addr, endpoint.address.data(), 16) == 0) return ifa->ifa_name;
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
    hints.ai_socktype = SOCK_STREAM; 
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo* result = nullptr;
    
    int rc = getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &result);
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

int create_tcp_listener(const IpEndpoint& endpoint, const std::string& iface) {
    int socket_fd = socket(endpoint.family, SOCK_STREAM, IPPROTO_TCP);
    if (socket_fd < 0) throw system_error("socket failed");
    set_reuse_options(socket_fd);
    bind_socket_to_device(socket_fd, iface);
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

int create_icmp_raw_listener(const IpEndpoint& endpoint, const std::string& iface) {
    if (endpoint.family != AF_INET) return -1;
    int socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (socket_fd < 0) return -1;
    set_reuse_options(socket_fd);
    bind_socket_to_device(socket_fd, iface);
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

ssize_t stream_read(SSL* ssl, int fd, void* buf, size_t count) {
    if (ssl) {
        int ret = SSL_read(ssl, buf, count);
        if (ret <= 0) return -1;
        return ret;
    } else {
        return recv(fd, buf, count, 0);
    }
}

bool stream_send(SSL* ssl, int fd, std::string_view payload) {
    std::size_t offset = 0;
    while (offset < payload.size()) {
        ssize_t written;
        if (ssl) {
            int to_write = static_cast<int>(std::min<std::size_t>(payload.size() - offset, 2147483647));
            written = SSL_write(ssl, payload.data() + offset, to_write);
            if (written <= 0) return false;
        } else {
            written = send(fd, payload.data() + offset, payload.size() - offset, 0);
            if (written <= 0) return false;
        }
        offset += static_cast<std::size_t>(written);
    }
    return true;
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
    return htons(static_cast<std::uint16_t>(~sum)); 
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
    return htons(static_cast<std::uint16_t>(~sum));
}

bool try_connect_from_source(const IpEndpoint& source_bind, const std::string& iface, const IpEndpoint& target, int timeout_ms) {
    int socket_fd = socket(target.family, SOCK_STREAM, IPPROTO_TCP);
    if (socket_fd < 0) return false;
    bool success = false;
    try {
        set_reuse_options(socket_fd);
        bind_socket_to_device(socket_fd, iface);
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

bool try_send_udp_from_source(const IpEndpoint& source_bind, const std::string& iface, const IpEndpoint& target, std::string_view payload) {
    int socket_fd = socket(target.family, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd < 0) return false;
    bool success = false;
    try {
        set_reuse_options(socket_fd);
        bind_socket_to_device(socket_fd, iface);
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
    try {
        const int parsed = std::stoi(std::string(id_text));
        if (parsed < 0 || parsed > 65535) return std::nullopt;
        return static_cast<std::uint16_t>(parsed);
    } catch (...) { return std::nullopt; }
}

std::optional<std::uint16_t> observe_udp_ipv4_id(const IpEndpoint& peer, const IpEndpoint& local_bind, std::string_view token, const std::string& iface, int timeout_ms) {
    if (peer.family != AF_INET || local_bind.family != AF_INET) return std::nullopt;
    int raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (raw_fd < 0) return std::nullopt;
    bind_socket_to_device(raw_fd, iface);

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
            if (ntohs(udp_header->dest) != local_bind.port) continue;
            if (std::memcmp(&ip_header->saddr, peer.address.data(), 4) != 0 || std::memcmp(&ip_header->daddr, local_bind.address.data(), 4) != 0) continue;

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

bool send_ipv4_icmp_error(const IpEndpoint& peer, const IpEndpoint& local_pub, int protocol, const std::string& iface) {
    if (peer.family == AF_INET) {
        int raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (raw_fd < 0) return false;
        bind_socket_to_device(raw_fd, iface);

        std::vector<std::uint8_t> packet(sizeof(icmphdr) + sizeof(iphdr) + 8, 0);
        auto* icmp = reinterpret_cast<icmphdr*>(packet.data());
        icmp->type = ICMP_DEST_UNREACH; icmp->code = ICMP_PORT_UNREACH; 

        auto* inner_ip = reinterpret_cast<iphdr*>(packet.data() + sizeof(icmphdr));
        inner_ip->ihl = 5; inner_ip->version = 4; inner_ip->tot_len = htons(sizeof(iphdr) + 8);
        inner_ip->id = htons(0x1234); inner_ip->ttl = 64; inner_ip->protocol = protocol; 
        std::memcpy(&inner_ip->saddr, peer.address.data(), 4);
        std::memcpy(&inner_ip->daddr, local_pub.address.data(), 4); 
        inner_ip->check = calculate_checksum(inner_ip, sizeof(iphdr));

        std::uint8_t* inner_l4 = packet.data() + sizeof(icmphdr) + sizeof(iphdr);
        std::uint16_t sport = htons(peer.port), dport = htons(local_pub.port); 
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

bool send_ipv4_icmp_error_variant(const IpEndpoint& peer, const IpEndpoint& outer_source_bind,
                                  const IpEndpoint& inner_source, const IpEndpoint& inner_destination_pub,
                                  std::uint16_t inner_source_port, std::uint16_t inner_destination_port,
                                  std::uint16_t marker, IcmpErrorVariant variant, const std::string& iface) {
    if (peer.family != AF_INET || outer_source_bind.family != AF_INET) return false;
    int raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_fd < 0) return false;
    int enable = 1; setsockopt(raw_fd, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));
    bind_socket_to_device(raw_fd, iface);

    std::vector<std::uint8_t> packet(sizeof(iphdr) + sizeof(icmphdr) + sizeof(iphdr) + sizeof(udphdr), 0);
    auto* outer_ip = reinterpret_cast<iphdr*>(packet.data());
    outer_ip->ihl = 5; outer_ip->version = 4; outer_ip->tot_len = htons(packet.size());
    outer_ip->ttl = 64; outer_ip->protocol = IPPROTO_ICMP;
    std::memcpy(&outer_ip->saddr, outer_source_bind.address.data(), 4); 
    std::memcpy(&outer_ip->daddr, peer.address.data(), 4);
    outer_ip->check = calculate_checksum(outer_ip, sizeof(iphdr));

    auto* icmp = reinterpret_cast<icmphdr*>(packet.data() + sizeof(iphdr));
    icmp->type = ICMP_DEST_UNREACH; icmp->code = ICMP_PORT_UNREACH;

    auto* inner_ip = reinterpret_cast<iphdr*>(packet.data() + sizeof(iphdr) + sizeof(icmphdr));
    inner_ip->ihl = 5; inner_ip->version = 4; inner_ip->tot_len = htons(sizeof(iphdr) + sizeof(udphdr));
    inner_ip->id = htons(marker); inner_ip->ttl = 64; inner_ip->protocol = IPPROTO_UDP;
    std::memcpy(&inner_ip->saddr, inner_source.address.data(), 4);
    std::memcpy(&inner_ip->daddr, inner_destination_pub.address.data(), 4); 
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

bool send_out_of_order_fragmented_udp(const IpEndpoint& peer, const IpEndpoint& local_bind, const std::string& iface) {
    if (peer.family != AF_INET || local_bind.family != AF_INET) return false;
    int raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_fd < 0) return false;
    int enable = 1; setsockopt(raw_fd, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));
    bind_socket_to_device(raw_fd, iface);

    constexpr std::size_t first_payload_size = 16;
    constexpr std::size_t second_payload_size = kRfc4787OutOfOrderFragmentPayload.size() - first_payload_size;
    
    iphdr ip_base{};
    ip_base.ihl = 5; ip_base.version = 4; ip_base.id = htons(0x4A87); ip_base.ttl = 64; ip_base.protocol = IPPROTO_UDP;
    std::memcpy(&ip_base.saddr, local_bind.address.data(), 4); 
    std::memcpy(&ip_base.daddr, peer.address.data(), 4);

    udphdr udp{};
    udp.source = htons(local_bind.port); udp.dest = htons(peer.port);
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

void append_stun_address(std::vector<uint8_t>& out, uint16_t attr_type, const IpEndpoint& ep, const uint8_t* tx_id, bool xor_mapped) {
    out.push_back(attr_type >> 8); 
    out.push_back(attr_type & 0xFF);
    uint16_t len = (ep.family == AF_INET) ? 8 : 20;
    out.push_back(len >> 8); 
    out.push_back(len & 0xFF);
    
    out.push_back(0); 
    out.push_back((ep.family == AF_INET) ? 1 : 2); 

    uint16_t port = ep.port;
    if (xor_mapped && tx_id) port ^= (static_cast<uint16_t>(tx_id[0]) << 8) | tx_id[1];
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

std::vector<uint8_t> generate_stun_binding_response(const uint8_t* tx_id, const IpEndpoint& peer_endpoint, 
                                                    const IpEndpoint& reply_pub_ep, const IpEndpoint& other_pub_ep, bool is_rfc5389) {
    std::vector<uint8_t> stun_resp(20, 0);
    stun_resp[0] = 0x01; stun_resp[1] = 0x01; 
    std::memcpy(&stun_resp[4], tx_id, 16); 
    
    append_stun_address(stun_resp, 0x0001, peer_endpoint, tx_id, false); 
    append_stun_address(stun_resp, 0x0004, reply_pub_ep, tx_id, false);  
    append_stun_address(stun_resp, 0x0005, other_pub_ep, tx_id, false); 
    append_stun_address(stun_resp, 0x802b, reply_pub_ep, tx_id, false);  
    append_stun_address(stun_resp, 0x802c, other_pub_ep, tx_id, false); 

    if (is_rfc5389) append_stun_address(stun_resp, 0x0020, peer_endpoint, tx_id, true);  

    uint16_t total_attr_len = stun_resp.size() - 20;
    stun_resp[2] = total_attr_len >> 8; 
    stun_resp[3] = total_attr_len & 0xFF;
    return stun_resp;
}

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

void handle_stream_client(int client_fd, int rx_idx, const StunContext& ctx, bool is_tls, IcmpRawContext& icmp_ctx, int timeout_ms, int syn_delay_ms) {
    try {
        const StunNode* current_nodes = is_tls ? ctx.tls_nodes : ctx.nodes;
        const StunNode& rx_node = current_nodes[rx_idx];
        const StunNode& other_node = current_nodes[rx_idx ^ 3];

        sockaddr_storage peer{}; socklen_t peer_length = sizeof(peer);
        if (getpeername(client_fd, reinterpret_cast<sockaddr*>(&peer), &peer_length) != 0) return;
        IpEndpoint peer_endpoint = from_sockaddr(reinterpret_cast<sockaddr*>(&peer), peer_length);
        
        sockaddr_storage local{}; socklen_t local_length = sizeof(local);
        getsockname(client_fd, reinterpret_cast<sockaddr*>(&local), &local_length);
        IpEndpoint local_endpoint = from_sockaddr(reinterpret_cast<sockaddr*>(&local), local_length);

        auto log_stream = [&](const std::string& cmd, const std::string& extra = "") {
            std::ostringstream oss;
            oss << "[" << (is_tls ? "TLS-CUST" : "TCP-CUST") << "] Req from " << endpoint_host(peer_endpoint) << ":" << peer_endpoint.port << " | Cmd: " << cmd;
            if (!extra.empty()) oss << " | " << extra;
            oss << "\n";
            std::cout << oss.str();
        };

        log_stream("NEW_CONNECTION", "Interface: " + (rx_node.iface_name.empty() ? "default" : rx_node.iface_name));

        struct timeval tv;
        tv.tv_sec = 30;
        tv.tv_usec = 0;
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        std::unique_ptr<SSL, decltype(&SSL_free)> ssl_ptr(nullptr, SSL_free);
        if (is_tls) {
            SSL* ssl = SSL_new(tls_ctx);
            SSL_set_fd(ssl, client_fd);
            if (SSL_accept(ssl) <= 0) {
                log_stream("HANDSHAKE_FAILED");
                return;
            }
            ssl_ptr.reset(ssl);
        }
        SSL* active_ssl = ssl_ptr.get();

        std::vector<uint8_t> tcp_buffer;
        while (true) {
            std::array<uint8_t, 2048> buf{};
            ssize_t received = stream_read(active_ssl, client_fd, buf.data(), buf.size());
            if (received <= 0) { log_stream("DISCONNECT", "Closed/Timeout"); return; }
            
            tcp_buffer.insert(tcp_buffer.end(), buf.begin(), buf.begin() + received);

            while (!tcp_buffer.empty()) {
                if (tcp_buffer[0] == 0x00 || tcp_buffer[0] == 0x01) { 
                    if (tcp_buffer.size() < 20) break;
                    uint16_t msg_length = static_cast<uint16_t>((tcp_buffer[2] << 8) | tcp_buffer[3]);
                    if (tcp_buffer.size() < 20U + msg_length) break;

                    uint16_t msg_type = static_cast<uint16_t>((tcp_buffer[0] << 8) | tcp_buffer[1]);
                    if (msg_type == 0x0001) { 
                        const uint8_t* tx_id = tcp_buffer.data() + 4;
                        bool is_rfc5389 = (tx_id[0] == 0x21 && tx_id[1] == 0x12 && tx_id[2] == 0xA4 && tx_id[3] == 0x42);
                        
                        auto stun_resp = generate_stun_binding_response(tx_id, peer_endpoint, rx_node.pub_ep, other_node.pub_ep, is_rfc5389);
                        stream_send(active_ssl, client_fd, std::string_view(reinterpret_cast<const char*>(stun_resp.data()), stun_resp.size()));
                        log_stream("STUN Binding Req", "Sent mapped address");
                    }
                    tcp_buffer.erase(tcp_buffer.begin(), tcp_buffer.begin() + 20 + msg_length);
                } else {
                    auto newline_pos = std::find(tcp_buffer.begin(), tcp_buffer.end(), '\n');
                    if (newline_pos == tcp_buffer.end()) {
                        if (tcp_buffer.size() > 4096) throw std::runtime_error("Line too long");
                        break;
                    }
                    std::string command(tcp_buffer.begin(), newline_pos);
                    tcp_buffer.erase(tcp_buffer.begin(), newline_pos + 1);
                    if (!command.empty() && command.back() == '\r') command.pop_back();

                    // Commands testing out-of-band features ALWAYS rely on plain UDP context (Node 0 & 2) 
                    const StunNode& primary = ctx.nodes[0];
                    const StunNode& secondary = ctx.nodes[2];

                    if (command == "M") {
                        log_stream("M (Mapping Test)"); stream_send(active_ssl, client_fd, endpoint_line(peer_endpoint));
                    }
                    else if (command == "F") {
                        IpEndpoint p_src = primary.bind_ep; p_src.port = 0;
                        IpEndpoint s_src = secondary.bind_ep; s_src.port = 0;
                        bool p_ok = try_connect_from_source(p_src, primary.iface_name, peer_endpoint, timeout_ms);
                        bool s_ok = try_connect_from_source(s_src, secondary.iface_name, peer_endpoint, timeout_ms);
                        std::string res = std::string("P=") + (p_ok ? "1" : "0") + " S=" + (s_ok ? "1" : "0");
                        log_stream("F (Filter Probe)", res); stream_send(active_ssl, client_fd, res + "\n");
                    }
                    else if (command == "S") {
                        IpEndpoint imm_src = secondary.bind_ep; imm_src.port = 0;
                        IpEndpoint del_src = primary.bind_ep; del_src.port = 0;
                        bool imm_ok = try_connect_from_source(imm_src, secondary.iface_name, peer_endpoint, timeout_ms);
                        std::this_thread::sleep_for(std::chrono::milliseconds(syn_delay_ms));
                        bool del_ok = try_connect_from_source(del_src, primary.iface_name, peer_endpoint, timeout_ms);
                        std::string res = std::string("I=") + (imm_ok ? "1" : "0") + " D=" + (del_ok ? "1" : "0");
                        log_stream("S (SYN Delay Test)", res); stream_send(active_ssl, client_fd, res + "\n");
                    }
                    else if (command == "U") {
                        IpEndpoint udp_src = primary.bind_ep; udp_src.port = 0;
                        bool sent = try_send_udp_from_source(udp_src, primary.iface_name, peer_endpoint, kRfc7857UdpProbePayload);
                        std::string res = std::string("R=") + (sent ? "1" : "0");
                        log_stream("U (UDP Probe)", res); stream_send(active_ssl, client_fd, res + "\n");
                    }
                    else if (command.rfind("C ", 0) == 0) {
                        const std::string ep_str = command.substr(2);
                        auto [target_host, target_port] = split_host_port(ep_str, 0);
                        IpEndpoint target = resolve_endpoint(target_host, target_port);
                        IpEndpoint src = primary.bind_ep; src.port = 0;
                        bool connected = try_connect_from_source(src, primary.iface_name, target, timeout_ms);
                        std::string res = std::string("R=") + (connected ? "1" : "0");
                        log_stream("C (Connect Target)", target_host + ":" + std::to_string(target_port) + " -> " + res);
                        stream_send(active_ssl, client_fd, res + "\n");
                    }
                    else if (command == "I") {
                        bool icmp_sent = send_ipv4_icmp_error(peer_endpoint, rx_node.pub_ep, IPPROTO_TCP, rx_node.iface_name);
                        std::string res = std::string("I=") + (icmp_sent ? "1" : "0");
                        log_stream("I (ICMP TCP Inject)", res); stream_send(active_ssl, client_fd, res + "\n");
                    }
                    else if (command.rfind("V ", 0) == 0) {
                        std::string token = command.substr(2);
                        std::optional<std::uint16_t> obs_id = observe_udp_ipv4_id(peer_endpoint, local_endpoint, token, rx_node.iface_name, timeout_ms);
                        std::string res = obs_id.has_value() ? ("V=" + std::to_string(*obs_id)) : "V=-1";
                        log_stream("V (Verify ID)", "Token=" + token + " -> " + res); stream_send(active_ssl, client_fd, res + "\n");
                    }
                    else if (command.rfind("IE ", 0) == 0) {
                        std::istringstream stream(command); std::string op, target_literal;
                        std::uint16_t m_out = 0, m_in = 0, m_udp = 0;
                        if (!(stream >> op >> target_literal >> m_out >> m_in >> m_udp)) {
                            log_stream("IE (ICMP Error Variants)", "Invalid Params"); stream_send(active_ssl, client_fd, "E=0\n"); continue;
                        }
                        auto [target_host, target_port] = split_host_port(target_literal, 0);
                        IpEndpoint target = resolve_endpoint(target_host, target_port);
                        if (target.family != AF_INET || peer_endpoint.family != AF_INET) { 
                            log_stream("IE (ICMP Error Variants)", "Family mismatch"); stream_send(active_ssl, client_fd, "E=0\n"); continue; 
                        }
                        bool s_out = send_ipv4_icmp_error_variant(target, primary.bind_ep, peer_endpoint, primary.pub_ep, target.port, primary.pub_ep.port, m_out, IcmpErrorVariant::BadOuterChecksum, primary.iface_name);
                        bool s_in  = send_ipv4_icmp_error_variant(target, primary.bind_ep, peer_endpoint, primary.pub_ep, target.port, primary.pub_ep.port, m_in,  IcmpErrorVariant::BadInnerIpChecksum, primary.iface_name);
                        bool s_udp = send_ipv4_icmp_error_variant(target, primary.bind_ep, peer_endpoint, primary.pub_ep, target.port, primary.pub_ep.port, m_udp, IcmpErrorVariant::BadUdpChecksum, primary.iface_name);
                        std::string res = std::string("E=") + ((s_out && s_in && s_udp) ? "1" : "0");
                        log_stream("IE (ICMP Error Variants)", res); stream_send(active_ssl, client_fd, res + "\n");
                    }
                    else if (command == "IRR") {
                        { std::lock_guard<std::mutex> lock(icmp_ctx.observed_error_markers_mutex); icmp_ctx.observed_error_markers.clear(); }
                        log_stream("IRR (ICMP Reset Markers)"); stream_send(active_ssl, client_fd, "R=1\n");
                    }
                    else if (command.rfind("IR ", 0) == 0) {
                        std::istringstream stream(command); std::string op; std::uint16_t marker = 0;
                        if (!(stream >> op >> marker)) { log_stream("IR (ICMP Check Marker)", "Invalid"); stream_send(active_ssl, client_fd, "R=0\n"); continue; }
                        bool seen = false;
                        { std::lock_guard<std::mutex> lock(icmp_ctx.observed_error_markers_mutex); seen = icmp_ctx.observed_error_markers.contains(marker); }
                        std::string res = std::string("R=") + (seen ? "1" : "0");
                        log_stream("IR (ICMP Check Marker)", "Marker=" + std::to_string(marker) + " -> " + res); stream_send(active_ssl, client_fd, res + "\n");
                    }
                    else if (command.rfind("IM ", 0) == 0) {
                        const std::string token = command.substr(3);
                        std::optional<IcmpMappingRecord> record;
                        {
                            std::lock_guard<std::mutex> lock(icmp_ctx.mappings_mutex);
                            auto it = icmp_ctx.mappings.find(token);
                            if (it != icmp_ctx.mappings.end()) record = it->second;
                        }
                        if (!record.has_value()) { log_stream("IM", token + " -> Not Found"); stream_send(active_ssl, client_fd, "ERR\n"); continue; }
                        log_stream("IM (ICMP Get Mapping)", token + " -> Found");
                        stream_send(active_ssl, client_fd, "M " + record->peer_host + " " + std::to_string(record->mapped_query) + "\n");
                    }
                    else if (command.rfind("IF ", 0) == 0) {
                        std::istringstream stream(command); std::string op, role, token; std::uint16_t probe_query = 0;
                        if (!(stream >> op >> role >> token >> probe_query) || role.size() != 1) { log_stream("IF", "Invalid Params"); stream_send(active_ssl, client_fd, "F=0\n"); continue; }
                        std::optional<IcmpMappingRecord> record;
                        {
                            std::lock_guard<std::mutex> lock(icmp_ctx.mappings_mutex);
                            auto it = icmp_ctx.mappings.find(token);
                            if (it != icmp_ctx.mappings.end()) record = it->second;
                        }
                        if (!record.has_value()) { log_stream("IF", token + " -> No Mapping"); stream_send(active_ssl, client_fd, "F=0\n"); continue; }

                        int raw_fd = (role[0] == 'P') ? icmp_ctx.primary_socket : ((role[0] == 'S') ? icmp_ctx.secondary_socket : -1);
                        if (raw_fd < 0) { log_stream("IF", "Invalid Socket"); stream_send(active_ssl, client_fd, "F=0\n"); continue; }
                        IpEndpoint target = resolve_endpoint(record->peer_host, 0); target.port = 0;
                        const std::string payload = "RFC5508-F:" + token + ":" + std::to_string(probe_query);
                        bool sent = send_icmp_echo(raw_fd, target, ICMP_ECHO, record->mapped_query, probe_query, payload);
                        std::string res = std::string("F=") + (sent ? "1" : "0");
                        log_stream("IF (ICMP Fragment/Echo)", "Token=" + token + " Role=" + role + " -> " + res); stream_send(active_ssl, client_fd, res + "\n");
                    } else {
                        log_stream("UNKNOWN_CMD", command); stream_send(active_ssl, client_fd, "ERR\n");
                    }
                }
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "[" << (is_tls ? "TLS-CUST" : "TCP-CUST") << "] Error handling client: " << e.what() << "\n";
    }
}

void handle_dtls_client(SSL* ssl, int dtls_fd, int rx_idx, const StunContext& ctx) {
    const StunNode& rx_node = ctx.tls_nodes[rx_idx];
    const StunNode& other_node = ctx.tls_nodes[rx_idx ^ 3];
    
    sockaddr_storage peer{}; socklen_t peer_len = sizeof(peer);
    getpeername(dtls_fd, reinterpret_cast<sockaddr*>(&peer), &peer_len);
    IpEndpoint peer_endpoint = from_sockaddr(reinterpret_cast<sockaddr*>(&peer), peer_len);

    auto log_dtls = [&](const std::string& msg) {
        std::cout << "[DTLS] Req from " << endpoint_host(peer_endpoint) << ":" << peer_endpoint.port << " | " << msg << "\n";
    };

    log_dtls("Handshake Success! Connection established.");

    while (true) {
        std::array<char, 4096> buffer{};
        int received = SSL_read(ssl, buffer.data(), buffer.size());
        if (received <= 0) { 
            log_dtls("Closed/Timeout"); 
            break; 
        }
        
        if (received >= 20 && (buffer[0] & 0xC0) == 0) {
            uint16_t msg_type = static_cast<uint16_t>((static_cast<uint8_t>(buffer[0]) << 8) | static_cast<uint8_t>(buffer[1]));
            
            if (msg_type == 0x0001) { 
                const uint8_t* tx_id = reinterpret_cast<const uint8_t*>(buffer.data() + 4); 
                bool is_rfc5389 = (tx_id[0] == 0x21 && tx_id[1] == 0x12 && tx_id[2] == 0xA4 && tx_id[3] == 0x42);
                
                auto stun_resp = generate_stun_binding_response(tx_id, peer_endpoint, rx_node.pub_ep, other_node.pub_ep, is_rfc5389);
                SSL_write(ssl, stun_resp.data(), stun_resp.size());
                log_dtls("STUN Binding Req -> Sent mapped address");
            }
        } else if (received >= 1 && buffer[0] == 'M') {
            log_dtls("Cmd: M");
            std::string payload = endpoint_line(peer_endpoint);
            SSL_write(ssl, payload.data(), payload.size());
        } else if (received >= 1 && buffer[0] == 'C') {
            log_dtls("Cmd: C");
            std::string payload = 
                "PRIMARY " + endpoint_host(ctx.nodes[0].pub_ep) + " " + std::to_string(ctx.nodes[0].pub_ep.port) + "\n" +
                "SECONDARY " + endpoint_host(ctx.nodes[2].pub_ep) + " " + std::to_string(ctx.nodes[2].pub_ep.port) + "\n";
            SSL_write(ssl, payload.data(), payload.size());
        }
    }
}

void handle_dtls_listen(int listen_fd, int rx_idx, const StunContext& ctx) {
    BIO_ADDR *client_addr = BIO_ADDR_new();
    if (!client_addr) return;

    SSL *ssl = SSL_new(dtls_ctx);
    BIO *bio = BIO_new_dgram(listen_fd, BIO_NOCLOSE);
    SSL_set_bio(ssl, bio, bio);

    int ret = DTLSv1_listen(ssl, client_addr);
    if (ret <= 0) {
        if (ret < 0) {
            int err = SSL_get_error(ssl, ret);
            char buf[256];
            ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
            std::cout << "[DTLS] DTLSv1_listen error: " << err << ", " << buf << "\n";
        }
        BIO_ADDR_free(client_addr);
        SSL_free(ssl);
        return;
    }

    IpEndpoint peer_endpoint{};
    peer_endpoint.family = BIO_ADDR_family(client_addr);
    peer_endpoint.port = ntohs(BIO_ADDR_rawport(client_addr));
    
    // 修复1：初始化 addr_len 为最大尺寸，否则 OpenSSL 不会拷贝任何 IP 地址！
    size_t addr_len = peer_endpoint.address.size(); 
    BIO_ADDR_rawaddress(client_addr, peer_endpoint.address.data(), &addr_len);
    peer_endpoint.address_length = addr_len;
    BIO_ADDR_free(client_addr);

    int new_fd = socket(peer_endpoint.family, SOCK_DGRAM, IPPROTO_UDP);
    if (new_fd < 0) { SSL_free(ssl); return; }
    set_reuse_options(new_fd);

    const StunNode& rx_node = ctx.tls_nodes[rx_idx];
    bind_socket_to_device(new_fd, rx_node.iface_name);

    SocketAddress local_addr = to_sockaddr(rx_node.bind_ep);
    if (bind(new_fd, reinterpret_cast<sockaddr*>(&local_addr.storage), local_addr.length) < 0) {
        std::cout << "[DTLS] Failed to bind new socket.\n";
        close(new_fd); SSL_free(ssl); return;
    }

    SocketAddress peer_addr = to_sockaddr(peer_endpoint);
    if (connect(new_fd, reinterpret_cast<sockaddr*>(&peer_addr.storage), peer_addr.length) < 0) {
        std::cout << "[DTLS] Failed to connect new socket.\n";
        close(new_fd); SSL_free(ssl); return;
    }

    BIO *new_bio = BIO_new_dgram(new_fd, BIO_NOCLOSE);
    
    // 修复2：强制通知 OpenSSL 当前的 dgram BIO 已经处于 connected 状态
    // 并且把对方的地址注入，以防止 OpenSSL 使用 sendto 时内部抛出异常中断握手
    BIO_ctrl(new_bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &peer_addr.storage);
    
    SSL_set_bio(ssl, new_bio, new_bio);

    std::thread([ssl, new_fd, rx_idx, &ctx]() {
        // 修复3：握手阶段（SSL_accept）极其容易发生丢包
        // 必须在握手前就设定好系统级的 Socket I/O 超时，防止被挂起
        struct timeval tv;
        tv.tv_sec = 10;
        tv.tv_usec = 0;
        setsockopt(new_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(new_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        int accept_ret = SSL_accept(ssl);
        if (accept_ret > 0) {
            handle_dtls_client(ssl, new_fd, rx_idx, ctx);
        } else {
            int err = SSL_get_error(ssl, accept_ret);
            char buf[256];
            ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
            std::cout << "[DTLS] SSL_accept handshake failed: " << err << ", " << buf << "\n";
        }
        
        SSL_free(ssl);
        close(new_fd);
    }).detach();
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
        
        if (msg_type == 0x0001) { 
            bool change_ip = false, change_port = false;
            size_t offset = 20;
            
            while (offset + 4 <= static_cast<size_t>(received) && offset + 4 <= 20U + msg_length) {
                uint16_t attr_type = static_cast<uint16_t>((static_cast<uint8_t>(buffer[offset]) << 8) | static_cast<uint8_t>(buffer[offset + 1]));
                uint16_t attr_len = static_cast<uint16_t>((static_cast<uint8_t>(buffer[offset + 2]) << 8) | static_cast<uint8_t>(buffer[offset + 3]));
                size_t next_offset = offset + 4 + ((attr_len + 3) & ~3);
                if (next_offset > static_cast<size_t>(received) || next_offset > 20U + msg_length) break;

                if (attr_type == 0x0003 && attr_len == 4) {
                    uint32_t change_flags = 0;
                    std::memcpy(&change_flags, buffer.data() + offset + 4, 4); 
                    change_flags = ntohl(change_flags);
                    change_ip = (change_flags & 0x0004); 
                    change_port = (change_flags & 0x0002); 
                }
                offset = next_offset;
            }

            int ip_bit = rx_idx & 2, port_bit = rx_idx & 1;   
            if (change_ip) ip_bit ^= 2;
            if (change_port) port_bit ^= 1;
            int reply_idx = ip_bit | port_bit;
            int other_idx = rx_idx ^ 3;

            const StunNode& reply_node = ctx.nodes[reply_idx];
            const StunNode& other_node = ctx.nodes[other_idx];

            const uint8_t* tx_id = reinterpret_cast<const uint8_t*>(buffer.data() + 4); 
            bool is_rfc5389 = (tx_id[0] == 0x21 && tx_id[1] == 0x12 && tx_id[2] == 0xA4 && tx_id[3] == 0x42);

            std::cout << "[STUN] Req from " << endpoint_host(peer_endpoint) << ":" << peer_endpoint.port 
                      << " | Rx: " << rx_node.pub_ep.port << " (IP-" << (rx_idx & 2 ? "2" : "1") << ")"
                      << " | ChgIP=" << change_ip << " ChgPort=" << change_port 
                      << " | Reply: " << endpoint_host(reply_node.pub_ep) << ":" << reply_node.pub_ep.port 
                      << (reply_node.iface_name.empty() ? "" : (" via " + reply_node.iface_name)) << "\n";

            auto stun_resp = generate_stun_binding_response(tx_id, peer_endpoint, reply_node.pub_ep, other_node.pub_ep, is_rfc5389);
            sendto(reply_node.fd, stun_resp.data(), stun_resp.size(), 0, reinterpret_cast<sockaddr*>(&peer), peer_length);
            return;
        }
    }

    if (received >= 1 && buffer[0] == 'M') {
        std::cout << "[UDP-CUST] Req from " << endpoint_host(peer_endpoint) << ":" << peer_endpoint.port << " | Cmd: M\n";
        std::string payload = endpoint_line(peer_endpoint);
        sendto(udp_fd, payload.data(), payload.size(), 0, reinterpret_cast<sockaddr*>(&peer), peer_length);
        return;
    }

    if (received >= 1 && buffer[0] == 'C') {
        std::cout << "[UDP-CUST] Req from " << endpoint_host(peer_endpoint) << ":" << peer_endpoint.port << " | Cmd: C\n";
        std::string payload = 
            "PRIMARY " + endpoint_host(ctx.nodes[0].pub_ep) + " " + std::to_string(ctx.nodes[0].pub_ep.port) + "\n" +
            "SECONDARY " + endpoint_host(ctx.nodes[2].pub_ep) + " " + std::to_string(ctx.nodes[2].pub_ep.port) + "\n";
        sendto(udp_fd, payload.data(), payload.size(), 0, reinterpret_cast<sockaddr*>(&peer), peer_length);
        return;
    }

    if (received >= 1 && buffer[0] == 'I') {
        bool sent = send_ipv4_icmp_error(peer_endpoint, rx_node.pub_ep, IPPROTO_UDP, rx_node.iface_name);
        std::cout << "[UDP-CUST] Req from " << endpoint_host(peer_endpoint) << ":" << peer_endpoint.port << " | Cmd: I | Sent=" << sent << "\n";
        std::string reply = std::string("I=") + (sent ? "1" : "0") + "\n";
        sendto(udp_fd, reply.data(), reply.size(), 0, reinterpret_cast<sockaddr*>(&peer), peer_length);
        return;
    }

    if (received >= 1 && buffer[0] == 'O') {
        bool sent = send_out_of_order_fragmented_udp(peer_endpoint, rx_node.bind_ep, rx_node.iface_name);
        std::cout << "[UDP-CUST] Req from " << endpoint_host(peer_endpoint) << ":" << peer_endpoint.port << " | Cmd: O | Sent=" << sent << "\n";
        std::string reply = std::string("O=") + (sent ? "1" : "0") + "\n";
        sendto(udp_fd, reply.data(), reply.size(), 0, reinterpret_cast<sockaddr*>(&peer), peer_length);
        return;
    }

    sendto(udp_fd, buffer.data(), received, 0, reinterpret_cast<sockaddr*>(&peer), peer_length);
}

void generate_self_signed_cert() {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1); // 使用高兼容性的 prime256v1 (secp256r1)
    EVP_PKEY_keygen(pctx, &generated_key);
    EVP_PKEY_CTX_free(pctx);

    generated_cert = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(generated_cert), 1);
    X509_gmtime_adj(X509_get_notBefore(generated_cert), 0);
    X509_gmtime_adj(X509_get_notAfter(generated_cert), 31536000L); // 1 year
    X509_set_pubkey(generated_cert, generated_key);
    X509_NAME *name = X509_get_subject_name(generated_cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("NatTypeTester"), -1, -1, 0);
    X509_set_issuer_name(generated_cert, name);
    X509_sign(generated_cert, generated_key, EVP_sha256());
}

int dtls_verify_cookie(SSL*, const unsigned char*, unsigned int) {
    return 1;
}

int dtls_generate_cookie(SSL*, unsigned char* cookie, unsigned int* cookie_len) {
    *cookie_len = 16;
    std::memset(cookie, 0, 16);
    return 1;
}

void init_openssl(const std::string& cert_file, const std::string& key_file) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    if (cert_file.empty() || key_file.empty()) {
        std::cout << "Generating self-signed certificate (ECDSA prime256v1) for TLS/DTLS...\n";
        generate_self_signed_cert();
    }

    tls_ctx = SSL_CTX_new(TLS_server_method());
    dtls_ctx = SSL_CTX_new(DTLS_server_method());
    if (!tls_ctx || !dtls_ctx) fail("Failed to create OpenSSL contexts");

    SSL_CTX_set_cookie_generate_cb(dtls_ctx, dtls_generate_cookie);
    SSL_CTX_set_cookie_verify_cb(dtls_ctx, dtls_verify_cookie);

    // 启用最高兼容性的 Cipher 列表并放宽安全级别以兼容所有版本的测试客户端
    SSL_CTX_set_cipher_list(tls_ctx, "ALL:!aNULL:!eNULL");
    SSL_CTX_set_cipher_list(dtls_ctx, "ALL:!aNULL:!eNULL");
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    SSL_CTX_set_security_level(tls_ctx, 0);
    SSL_CTX_set_security_level(dtls_ctx, 0);
#endif

    auto configure_ctx = [&](SSL_CTX* ctx) {
        if (!cert_file.empty() && !key_file.empty()) {
            if (SSL_CTX_use_certificate_file(ctx, cert_file.c_str(), SSL_FILETYPE_PEM) <= 0) fail("Failed to load cert");
            if (SSL_CTX_use_PrivateKey_file(ctx, key_file.c_str(), SSL_FILETYPE_PEM) <= 0) fail("Failed to load key");
        } else {
            SSL_CTX_use_certificate(ctx, generated_cert);
            SSL_CTX_use_PrivateKey(ctx, generated_key);
        }
    };
    configure_ctx(tls_ctx);
    configure_ctx(dtls_ctx);
}

} // namespace

int main(int argc, char** argv) {
    try {
        std::string bind_ip1 = "0.0.0.0", pub_ip1 = "";
        std::string bind_ip2 = "0.0.0.0", pub_ip2 = "";
        std::string cert_file, key_file;
        uint16_t port1 = 3478, port2 = 3479;
        uint16_t tls_port1 = 5349, tls_port2 = 5350;
        int probe_timeout_ms = 1200;
        int syn_delay_ms = 350;

        for (int index = 1; index < argc; ++index) {
            std::string token = argv[index];
            if (token == "--bind-ip1") bind_ip1 = argv[++index];
            else if (token == "--pub-ip1") pub_ip1 = argv[++index];
            else if (token == "--bind-ip2") bind_ip2 = argv[++index];
            else if (token == "--pub-ip2") pub_ip2 = argv[++index];
            else if (token == "--port1") port1 = static_cast<uint16_t>(std::stoi(argv[++index]));
            else if (token == "--port2") port2 = static_cast<uint16_t>(std::stoi(argv[++index]));
            else if (token == "--tls-port1") tls_port1 = static_cast<uint16_t>(std::stoi(argv[++index]));
            else if (token == "--tls-port2") tls_port2 = static_cast<uint16_t>(std::stoi(argv[++index]));
            else if (token == "--cert") cert_file = argv[++index];
            else if (token == "--key") key_file = argv[++index];
            else if (token == "--probe-timeout-ms") probe_timeout_ms = std::stoi(argv[++index]);
            else if (token == "--syn-delay-ms") syn_delay_ms = std::stoi(argv[++index]);
        }

        if (pub_ip1.empty() || pub_ip2.empty()) fail("Both --pub-ip1 and --pub-ip2 are required.");

        ensure_icmp_conntrack_bypass();
        try_disable_kernel_icmp_echo_auto_reply();
        ensure_fragment_conntrack_bypass();
        init_openssl(cert_file, key_file);

        StunContext stun_ctx;
        stun_ctx.nodes[0].bind_ep = resolve_endpoint(bind_ip1, port1); stun_ctx.nodes[0].pub_ep = resolve_endpoint(pub_ip1, port1);
        stun_ctx.nodes[1].bind_ep = resolve_endpoint(bind_ip1, port2); stun_ctx.nodes[1].pub_ep = resolve_endpoint(pub_ip1, port2);
        stun_ctx.nodes[2].bind_ep = resolve_endpoint(bind_ip2, port1); stun_ctx.nodes[2].pub_ep = resolve_endpoint(pub_ip2, port1);
        stun_ctx.nodes[3].bind_ep = resolve_endpoint(bind_ip2, port2); stun_ctx.nodes[3].pub_ep = resolve_endpoint(pub_ip2, port2);
        
        stun_ctx.tls_nodes[0].bind_ep = resolve_endpoint(bind_ip1, tls_port1); stun_ctx.tls_nodes[0].pub_ep = resolve_endpoint(pub_ip1, tls_port1);
        stun_ctx.tls_nodes[1].bind_ep = resolve_endpoint(bind_ip1, tls_port2); stun_ctx.tls_nodes[1].pub_ep = resolve_endpoint(pub_ip1, tls_port2);
        stun_ctx.tls_nodes[2].bind_ep = resolve_endpoint(bind_ip2, tls_port1); stun_ctx.tls_nodes[2].pub_ep = resolve_endpoint(pub_ip2, tls_port1);
        stun_ctx.tls_nodes[3].bind_ep = resolve_endpoint(bind_ip2, tls_port2); stun_ctx.tls_nodes[3].pub_ep = resolve_endpoint(pub_ip2, tls_port2);

        int tcp_fds[4], tls_fds[4], dtls_fds[4];
        std::cout << "Starting Server Engine with TCP/UDP Multiplexing & Interface Binding Penetration...\n";
        for (int i = 0; i < 4; ++i) {
            stun_ctx.nodes[i].iface_name = get_interface_name(stun_ctx.nodes[i].bind_ep);
            stun_ctx.nodes[i].fd = create_udp_listener(stun_ctx.nodes[i].bind_ep, stun_ctx.nodes[i].iface_name);
            tcp_fds[i] = create_tcp_listener(stun_ctx.nodes[i].bind_ep, stun_ctx.nodes[i].iface_name);
            
            int flags = fcntl(tcp_fds[i], F_GETFL, 0); fcntl(tcp_fds[i], F_SETFL, flags | O_NONBLOCK);
            
            std::cout << "  Node " << i << ": Bind=" << endpoint_host(stun_ctx.nodes[i].bind_ep) << ":" << stun_ctx.nodes[i].bind_ep.port 
                      << "  Public=" << endpoint_host(stun_ctx.nodes[i].pub_ep) << ":" << stun_ctx.nodes[i].pub_ep.port << "\n";
        }
        
        std::cout << "Starting TLS/DTLS Endpoints...\n";
        for (int i = 0; i < 4; ++i) {
            stun_ctx.tls_nodes[i].iface_name = get_interface_name(stun_ctx.tls_nodes[i].bind_ep);
            tls_fds[i] = create_tcp_listener(stun_ctx.tls_nodes[i].bind_ep, stun_ctx.tls_nodes[i].iface_name);
            dtls_fds[i] = create_udp_listener(stun_ctx.tls_nodes[i].bind_ep, stun_ctx.tls_nodes[i].iface_name);
            
            int tcp_f = fcntl(tls_fds[i], F_GETFL, 0); fcntl(tls_fds[i], F_SETFL, tcp_f | O_NONBLOCK);
            int udp_f = fcntl(dtls_fds[i], F_GETFL, 0); fcntl(dtls_fds[i], F_SETFL, udp_f | O_NONBLOCK);
            
            std::cout << "  TLS Node " << i << ": Bind=" << endpoint_host(stun_ctx.tls_nodes[i].bind_ep) << ":" << stun_ctx.tls_nodes[i].bind_ep.port 
                      << "  Public=" << endpoint_host(stun_ctx.tls_nodes[i].pub_ep) << ":" << stun_ctx.tls_nodes[i].pub_ep.port << "\n";
        }

        if (stun_ctx.nodes[0].bind_ep.family == AF_INET) {
            stun_ctx.icmp_ctx.primary_socket = create_icmp_raw_listener(stun_ctx.nodes[0].bind_ep, stun_ctx.nodes[0].iface_name);
            stun_ctx.icmp_ctx.secondary_socket = create_icmp_raw_listener(stun_ctx.nodes[2].bind_ep, stun_ctx.nodes[2].iface_name);
        }

        std::cout << "\n>>> Server fully ready! Logs will appear below...\n";
        std::cout << "========================================================\n";

        std::vector<pollfd> descriptors;
        for (int i = 0; i < 4; i++) descriptors.push_back({tcp_fds[i], POLLIN, 0});
        for (int i = 0; i < 4; i++) descriptors.push_back({stun_ctx.nodes[i].fd, POLLIN, 0});
        for (int i = 0; i < 4; i++) descriptors.push_back({tls_fds[i], POLLIN, 0});
        for (int i = 0; i < 4; i++) descriptors.push_back({dtls_fds[i], POLLIN, 0});
        if (stun_ctx.icmp_ctx.primary_socket >= 0) descriptors.push_back({stun_ctx.icmp_ctx.primary_socket, POLLIN, 0});
        if (stun_ctx.icmp_ctx.secondary_socket >= 0) descriptors.push_back({stun_ctx.icmp_ctx.secondary_socket, POLLIN, 0});

        while (true) {
            for (auto& d : descriptors) d.revents = 0;
            if (poll(descriptors.data(), descriptors.size(), -1) < 0) throw system_error("poll failed");
            
            int idx = 0;
            for (int i = 0; i < 4; i++, idx++) {
                if (descriptors[idx].revents & POLLIN) {
                    sockaddr_storage client{}; socklen_t len = sizeof(client);
                    int client_fd = accept(tcp_fds[i], reinterpret_cast<sockaddr*>(&client), &len);
                    if (client_fd >= 0) {
                        std::thread([client_fd, i, &stun_ctx, probe_timeout_ms, syn_delay_ms]() {
                            handle_stream_client(client_fd, i, stun_ctx, false, const_cast<IcmpRawContext&>(stun_ctx.icmp_ctx), probe_timeout_ms, syn_delay_ms);
                            close(client_fd);
                        }).detach();
                    }
                }
            }
            for (int i = 0; i < 4; i++, idx++) {
                if (descriptors[idx].revents & POLLIN) handle_udp_packet(i, stun_ctx);
            }
            for (int i = 0; i < 4; i++, idx++) {
                if (descriptors[idx].revents & POLLIN) {
                    sockaddr_storage client{}; socklen_t len = sizeof(client);
                    int client_fd = accept(tls_fds[i], reinterpret_cast<sockaddr*>(&client), &len);
                    if (client_fd >= 0) {
                        std::thread([client_fd, i, &stun_ctx, probe_timeout_ms, syn_delay_ms]() {
                            handle_stream_client(client_fd, i, stun_ctx, true, const_cast<IcmpRawContext&>(stun_ctx.icmp_ctx), probe_timeout_ms, syn_delay_ms);
                            close(client_fd);
                        }).detach();
                    }
                }
            }
            for (int i = 0; i < 4; i++, idx++) {
                if (descriptors[idx].revents & POLLIN) handle_dtls_listen(dtls_fds[i], i, stun_ctx);
            }
            if (stun_ctx.icmp_ctx.primary_socket >= 0) {
                if (descriptors[idx].revents & POLLIN) handle_icmp_packet(stun_ctx.icmp_ctx.primary_socket, stun_ctx.icmp_ctx);
                idx++;
            }
            if (stun_ctx.icmp_ctx.secondary_socket >= 0) {
                if (descriptors[idx].revents & POLLIN) handle_icmp_packet(stun_ctx.icmp_ctx.secondary_socket, stun_ctx.icmp_ctx);
                idx++;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }
}
