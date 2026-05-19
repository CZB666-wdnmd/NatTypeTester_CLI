#include "stun.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <memory>
#include <random>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace natcli {
namespace {

constexpr std::uint16_t kMappedAddress = 0x0001;
constexpr std::uint16_t kChangeRequest = 0x0003;
constexpr std::uint16_t kChangedAddress = 0x0005;
constexpr std::uint16_t kXorMappedAddress = 0x0020;
constexpr std::uint16_t kOtherAddress = 0x802C;
constexpr std::uint32_t kMagicCookie = 0x2112A442u;

struct SocketAddress {
    sockaddr_storage storage{};
    socklen_t length{};
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
    } else if (endpoint.family == AF_INET6) {
        auto* address = reinterpret_cast<sockaddr_in6*>(&result.storage);
        address->sin6_family = AF_INET6;
        address->sin6_port = htons(endpoint.port);
        std::memcpy(&address->sin6_addr, endpoint.address.data(), 16);
    } else {
        throw std::runtime_error("Unsupported address family");
    }
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

IpEndpoint socket_local_endpoint(int socket_fd) {
    sockaddr_storage storage{};
    socklen_t length = sizeof(storage);
    if (getsockname(socket_fd, reinterpret_cast<sockaddr*>(&storage), &length) != 0) {
        throw system_error("getsockname failed");
    }
    return from_sockaddr(reinterpret_cast<sockaddr*>(&storage), length);
}

void set_socket_timeouts(int socket_fd, std::chrono::milliseconds timeout) {
    timeval value{};
    value.tv_sec = static_cast<long>(timeout.count() / 1000);
    value.tv_usec = static_cast<long>((timeout.count() % 1000) * 1000);
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &value, sizeof(value));
    setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, &value, sizeof(value));
}

void bind_if_needed(int socket_fd, const IpEndpoint& local_bind) {
    SocketAddress address = to_sockaddr(local_bind);
    int reuse = 1;
    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    if (bind(socket_fd, reinterpret_cast<sockaddr*>(&address.storage), address.length) != 0) {
        throw system_error("bind failed");
    }
}

void connect_with_timeout(int socket_fd, const IpEndpoint& remote, std::chrono::milliseconds timeout) {
    SocketAddress address = to_sockaddr(remote);
    const int flags = fcntl(socket_fd, F_GETFL, 0);
    if (flags < 0) {
        throw system_error("fcntl(F_GETFL) failed");
    }
    if (fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        throw system_error("fcntl(F_SETFL) failed");
    }

    int rc = connect(socket_fd, reinterpret_cast<sockaddr*>(&address.storage), address.length);
    if (rc != 0 && errno != EINPROGRESS) {
        throw system_error("connect failed");
    }

    pollfd descriptor{socket_fd, POLLOUT, 0};
    rc = poll(&descriptor, 1, static_cast<int>(timeout.count()));
    if (rc <= 0) {
        throw std::runtime_error("connect timed out");
    }

    int error = 0;
    socklen_t error_length = sizeof(error);
    if (getsockopt(socket_fd, SOL_SOCKET, SO_ERROR, &error, &error_length) != 0) {
        throw system_error("getsockopt(SO_ERROR) failed");
    }
    if (error != 0) {
        errno = error;
        throw system_error("connect failed");
    }

    if (fcntl(socket_fd, F_SETFL, flags) != 0) {
        throw system_error("fcntl restore failed");
    }
}

bool wait_for_readable(int socket_fd, std::chrono::milliseconds timeout) {
    pollfd descriptor{socket_fd, POLLIN, 0};
    int rc = poll(&descriptor, 1, static_cast<int>(timeout.count()));
    return rc > 0 && (descriptor.revents & POLLIN) != 0;
}

bool is_ip_literal(const std::string& value) {
    in_addr address4{};
    in6_addr address6{};
    return inet_pton(AF_INET, value.c_str(), &address4) == 1 || inet_pton(AF_INET6, value.c_str(), &address6) == 1;
}

std::vector<std::uint8_t> encode_cookie_and_txid(const StunMessage& message) {
    std::vector<std::uint8_t> bytes(16);
    bytes[0] = static_cast<std::uint8_t>((message.magic_cookie >> 24) & 0xFFu);
    bytes[1] = static_cast<std::uint8_t>((message.magic_cookie >> 16) & 0xFFu);
    bytes[2] = static_cast<std::uint8_t>((message.magic_cookie >> 8) & 0xFFu);
    bytes[3] = static_cast<std::uint8_t>(message.magic_cookie & 0xFFu);
    std::memcpy(bytes.data() + 4, message.transaction_id.data(), message.transaction_id.size());
    return bytes;
}

std::optional<IpEndpoint> parse_address_attribute(const StunMessage& message, std::uint16_t type, bool xor_value) {
    for (const StunAttribute& attribute : message.attributes) {
        if (attribute.type != type || attribute.value.size() < 8) {
            continue;
        }

        IpEndpoint endpoint;
        endpoint.family = attribute.value[1] == 0x02 ? AF_INET6 : AF_INET;
        endpoint.address_length = endpoint.family == AF_INET ? 4 : 16;
        if (attribute.value.size() < 4 + endpoint.address_length) {
            continue;
        }

        std::uint16_t port = static_cast<std::uint16_t>((attribute.value[2] << 8) | attribute.value[3]);
        std::copy_n(attribute.value.begin() + 4, static_cast<long>(endpoint.address_length), endpoint.address.begin());

        if (xor_value) {
            std::vector<std::uint8_t> mask = encode_cookie_and_txid(message);
            port ^= static_cast<std::uint16_t>(message.magic_cookie >> 16);
            for (std::size_t index = 0; index < endpoint.address_length; ++index) {
                endpoint.address[index] ^= mask[index];
            }
        }

        endpoint.port = port;
        return endpoint;
    }
    return std::nullopt;
}

SSL_CTX* create_ssl_ctx(bool verify_peer) {
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == nullptr) {
        throw std::runtime_error("SSL_CTX_new failed");
    }
    if (verify_peer) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
        if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
            SSL_CTX_free(ctx);
            throw std::runtime_error("SSL_CTX_set_default_verify_paths failed");
        }
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    }
    return ctx;
}

} // namespace

bool operator==(const IpEndpoint& left, const IpEndpoint& right) {
    return left.family == right.family && left.port == right.port && left.address_length == right.address_length &&
           std::equal(left.address.begin(), left.address.begin() + static_cast<long>(left.address_length), right.address.begin());
}

bool same_address(const IpEndpoint& left, const IpEndpoint& right) {
    return left.family == right.family && left.address_length == right.address_length &&
           std::equal(left.address.begin(), left.address.begin() + static_cast<long>(left.address_length), right.address.begin());
}

std::string to_string(const IpEndpoint& endpoint) {
    char buffer[INET6_ADDRSTRLEN]{};
    if (endpoint.family == AF_INET) {
        inet_ntop(AF_INET, endpoint.address.data(), buffer, sizeof(buffer));
        return std::string(buffer) + ":" + std::to_string(endpoint.port);
    }
    inet_ntop(AF_INET6, endpoint.address.data(), buffer, sizeof(buffer));
    return std::string("[") + buffer + "]:" + std::to_string(endpoint.port);
}

std::string to_string(NatType value) {
    switch (value) {
    case NatType::Unknown: return "Unknown";
    case NatType::UnsupportedServer: return "UnsupportedServer";
    case NatType::UdpBlocked: return "UdpBlocked";
    case NatType::OpenInternet: return "OpenInternet";
    case NatType::SymmetricUdpFirewall: return "SymmetricUdpFirewall";
    case NatType::FullCone: return "FullCone";
    case NatType::RestrictedCone: return "RestrictedCone";
    case NatType::PortRestrictedCone: return "PortRestrictedCone";
    case NatType::Symmetric: return "Symmetric";
    }
    return "Unknown";
}

std::string to_string(BindingTestResult value) {
    switch (value) {
    case BindingTestResult::Unknown: return "Unknown";
    case BindingTestResult::UnsupportedServer: return "UnsupportedServer";
    case BindingTestResult::Success: return "Success";
    case BindingTestResult::Fail: return "Fail";
    }
    return "Unknown";
}

std::string to_string(MappingBehavior value) {
    switch (value) {
    case MappingBehavior::Unknown: return "Unknown";
    case MappingBehavior::UnsupportedServer: return "UnsupportedServer";
    case MappingBehavior::Direct: return "Direct";
    case MappingBehavior::EndpointIndependent: return "EndpointIndependent";
    case MappingBehavior::AddressDependent: return "AddressDependent";
    case MappingBehavior::AddressAndPortDependent: return "AddressAndPortDependent";
    case MappingBehavior::Fail: return "Fail";
    }
    return "Unknown";
}

std::string to_string(FilteringBehavior value) {
    switch (value) {
    case FilteringBehavior::Unknown: return "Unknown";
    case FilteringBehavior::UnsupportedServer: return "UnsupportedServer";
    case FilteringBehavior::EndpointIndependent: return "EndpointIndependent";
    case FilteringBehavior::AddressDependent: return "AddressDependent";
    case FilteringBehavior::AddressAndPortDependent: return "AddressAndPortDependent";
    case FilteringBehavior::None: return "None";
    }
    return "Unknown";
}

std::string to_string(ProbeStatus value) {
    switch (value) {
    case ProbeStatus::Unknown: return "Unknown";
    case ProbeStatus::Pass: return "Pass";
    case ProbeStatus::Fail: return "Fail";
    case ProbeStatus::Inconclusive: return "Inconclusive";
    }
    return "Unknown";
}

std::string to_string(TransportType value) {
    switch (value) {
    case TransportType::Udp: return "udp";
    case TransportType::Tcp: return "tcp";
    case TransportType::Tls: return "tls";
    }
    return "udp";
}

std::string to_string(StunTestType value) {
    switch (value) {
    case StunTestType::Combining: return "combining";
    case StunTestType::Binding: return "binding";
    case StunTestType::Mapping: return "mapping";
    case StunTestType::Filtering: return "filtering";
    case StunTestType::TcpFiltering: return "tcp-filtering";
    case StunTestType::ProtocolCorrelation: return "protocol-correlation";
    }
    return "combining";
}

std::pair<std::string, std::uint16_t> split_host_port(std::string_view input, std::uint16_t default_port) {
    if (input.empty()) {
        throw std::runtime_error("Endpoint cannot be empty");
    }

    if (input.front() == '[') {
        std::size_t end = input.find(']');
        if (end == std::string_view::npos) {
            throw std::runtime_error("Invalid IPv6 endpoint syntax");
        }
        std::string host(input.substr(1, end - 1));
        if (end + 1 == input.size()) {
            return {host, default_port};
        }
        if (input[end + 1] != ':') {
            throw std::runtime_error("Invalid endpoint syntax");
        }
        return {host, static_cast<std::uint16_t>(std::stoul(std::string(input.substr(end + 2))))};
    }

    std::size_t last_colon = input.rfind(':');
    if (last_colon == std::string_view::npos || input.find(':') != last_colon) {
        return {std::string(input), default_port};
    }
    return {std::string(input.substr(0, last_colon)), static_cast<std::uint16_t>(std::stoul(std::string(input.substr(last_colon + 1))))};
}

IpEndpoint parse_endpoint_literal(std::string_view input, std::uint16_t default_port) {
    auto [host, port] = split_host_port(input, default_port);
    return resolve_endpoint(host, port, SOCK_STREAM);
}

IpEndpoint resolve_endpoint(const std::string& host, std::uint16_t port, int socktype, int family) {
    addrinfo hints{};
    hints.ai_family = family;
    hints.ai_socktype = socktype;
    hints.ai_protocol = socktype == SOCK_DGRAM ? IPPROTO_UDP : IPPROTO_TCP;

    addrinfo* result = nullptr;
    const std::string port_string = std::to_string(port);
    int rc = getaddrinfo(host.c_str(), port_string.c_str(), &hints, &result);
    if (rc != 0) {
        throw std::runtime_error(std::string("getaddrinfo failed: ") + gai_strerror(rc));
    }

    std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> guard(result, freeaddrinfo);
    for (addrinfo* current = result; current != nullptr; current = current->ai_next) {
        if (current->ai_family == AF_INET || current->ai_family == AF_INET6) {
            return from_sockaddr(current->ai_addr, static_cast<socklen_t>(current->ai_addrlen));
        }
    }

    throw std::runtime_error("No supported address found for endpoint");
}

IpEndpoint wildcard_endpoint(int family, std::uint16_t port) {
    IpEndpoint endpoint;
    endpoint.family = family;
    endpoint.address_length = family == AF_INET ? 4 : 16;
    endpoint.port = port;
    endpoint.address.fill(0);
    return endpoint;
}

StunMessage create_binding_request(std::uint32_t magic_cookie, bool change_ip, bool change_port) {
    StunMessage message;
    message.magic_cookie = magic_cookie;
    std::random_device device;
    for (std::uint8_t& byte : message.transaction_id) {
        byte = static_cast<std::uint8_t>(device());
    }

    if (change_ip || change_port) {
        StunAttribute attribute;
        attribute.type = kChangeRequest;
        attribute.value = {0x00, 0x00, 0x00, static_cast<std::uint8_t>((change_ip ? 0x04 : 0x00) | (change_port ? 0x02 : 0x00))};
        message.attributes.push_back(std::move(attribute));
    }

    return message;
}

std::vector<std::uint8_t> serialize(const StunMessage& message) {
    std::size_t payload_length = 0;
    for (const StunAttribute& attribute : message.attributes) {
        payload_length += 4 + ((attribute.value.size() + 3) & ~std::size_t{3});
    }

    std::vector<std::uint8_t> buffer(20 + payload_length);
    buffer[0] = static_cast<std::uint8_t>((message.type >> 8) & 0xFFu);
    buffer[1] = static_cast<std::uint8_t>(message.type & 0xFFu);
    buffer[2] = static_cast<std::uint8_t>((payload_length >> 8) & 0xFFu);
    buffer[3] = static_cast<std::uint8_t>(payload_length & 0xFFu);
    buffer[4] = static_cast<std::uint8_t>((message.magic_cookie >> 24) & 0xFFu);
    buffer[5] = static_cast<std::uint8_t>((message.magic_cookie >> 16) & 0xFFu);
    buffer[6] = static_cast<std::uint8_t>((message.magic_cookie >> 8) & 0xFFu);
    buffer[7] = static_cast<std::uint8_t>(message.magic_cookie & 0xFFu);
    std::copy(message.transaction_id.begin(), message.transaction_id.end(), buffer.begin() + 8);

    std::size_t offset = 20;
    for (const StunAttribute& attribute : message.attributes) {
        buffer[offset] = static_cast<std::uint8_t>((attribute.type >> 8) & 0xFFu);
        buffer[offset + 1] = static_cast<std::uint8_t>(attribute.type & 0xFFu);
        buffer[offset + 2] = static_cast<std::uint8_t>((attribute.value.size() >> 8) & 0xFFu);
        buffer[offset + 3] = static_cast<std::uint8_t>(attribute.value.size() & 0xFFu);
        std::copy(attribute.value.begin(), attribute.value.end(), buffer.begin() + static_cast<long>(offset + 4));
        offset += 4 + attribute.value.size();
        while ((offset & 0x03u) != 0) {
            buffer[offset++] = 0;
        }
    }

    return buffer;
}

bool parse_message(const std::uint8_t* data, std::size_t size, StunMessage& message) {
    if (size < 20) {
        return false;
    }

    std::uint16_t payload_length = static_cast<std::uint16_t>((data[2] << 8) | data[3]);
    if (size < static_cast<std::size_t>(20 + payload_length)) {
        return false;
    }

    message.type = static_cast<std::uint16_t>((data[0] << 8) | data[1]);
    message.magic_cookie = (static_cast<std::uint32_t>(data[4]) << 24) | (static_cast<std::uint32_t>(data[5]) << 16) |
                           (static_cast<std::uint32_t>(data[6]) << 8) | static_cast<std::uint32_t>(data[7]);
    std::copy(data + 8, data + 20, message.transaction_id.begin());
    message.attributes.clear();

    std::size_t offset = 20;
    while (offset + 4 <= static_cast<std::size_t>(20 + payload_length)) {
        std::uint16_t type = static_cast<std::uint16_t>((data[offset] << 8) | data[offset + 1]);
        std::uint16_t length = static_cast<std::uint16_t>((data[offset + 2] << 8) | data[offset + 3]);
        offset += 4;
        if (offset + length > size) {
            return false;
        }
        StunAttribute attribute;
        attribute.type = type;
        attribute.value.assign(data + offset, data + offset + length);
        message.attributes.push_back(std::move(attribute));
        offset += length;
        while ((offset & 0x03u) != 0 && offset < size) {
            ++offset;
        }
    }

    return true;
}

std::optional<IpEndpoint> get_mapped_address_attribute(const StunMessage& message) {
    return parse_address_attribute(message, kMappedAddress, false);
}

std::optional<IpEndpoint> get_changed_address_attribute(const StunMessage& message) {
    return parse_address_attribute(message, kChangedAddress, false);
}

std::optional<IpEndpoint> get_xor_mapped_address_attribute(const StunMessage& message) {
    if (std::optional<IpEndpoint> endpoint = parse_address_attribute(message, kXorMappedAddress, true); endpoint.has_value()) {
        return endpoint;
    }
    return parse_address_attribute(message, kMappedAddress, false);
}

std::optional<IpEndpoint> get_other_address_attribute(const StunMessage& message) {
    if (std::optional<IpEndpoint> endpoint = parse_address_attribute(message, kOtherAddress, false); endpoint.has_value()) {
        return endpoint;
    }
    return parse_address_attribute(message, kChangedAddress, false);
}

UdpSession::UdpSession(const IpEndpoint& server, const std::optional<IpEndpoint>& local_bind, std::chrono::milliseconds timeout)
    : timeout_(timeout) {
    socket_ = socket(server.family, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_ < 0) {
        throw system_error("socket failed");
    }
    try {
        bind_if_needed(socket_, local_bind.value_or(wildcard_endpoint(server.family)));
        set_socket_timeouts(socket_, timeout_);
    } catch (...) {
        close(socket_);
        socket_ = -1;
        throw;
    }
}

UdpSession::~UdpSession() {
    if (socket_ >= 0) {
        close(socket_);
    }
}

std::optional<StunResponse> UdpSession::request(const StunDiscoveryAction& action) {
    std::vector<std::uint8_t> payload = serialize(action.message);
    SocketAddress remote = to_sockaddr(action.send_to);

    const auto deadline = std::chrono::steady_clock::now() + timeout_;
    
    // RFC 5389 推荐的初始重传超时时间 (RTO) 为 500ms
    std::chrono::milliseconds rto(500); 
    std::vector<std::uint8_t> buffer(65536);

    while (std::chrono::steady_clock::now() < deadline) {
        // 1. 发送 (或重传) STUN 请求包
        ssize_t sent = sendto(socket_, payload.data(), payload.size(), 0, reinterpret_cast<sockaddr*>(&remote.storage), remote.length);
        if (sent < 0) {
            throw system_error("sendto failed");
        }

        auto next_resend_time = std::chrono::steady_clock::now() + rto;

        // 2. 在当前 RTO 窗口内，循环等待并接收响应
        while (std::chrono::steady_clock::now() < std::min(next_resend_time, deadline)) {
            auto now = std::chrono::steady_clock::now();
            auto wait_time = std::chrono::duration_cast<std::chrono::milliseconds>(std::min(next_resend_time, deadline) - now);
            
            if (wait_time.count() <= 0) {
                break;
            }

            // 等待 Socket 可读
            if (!wait_for_readable(socket_, wait_time)) {
                break; // 当前 RTO 超时，跳出内层循环去重传
            }

            // Socket 可读，接收数据
            sockaddr_storage response_remote{};
            socklen_t response_length = sizeof(response_remote);
            ssize_t received = recvfrom(socket_, buffer.data(), buffer.size(), 0, reinterpret_cast<sockaddr*>(&response_remote), &response_length);
            if (received < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    continue;
                }
                throw system_error("recvfrom failed");
            }

            // 解析 STUN 消息
            StunMessage response_message;
            if (!parse_message(buffer.data(), static_cast<std::size_t>(received), response_message)) {
                continue; // 可能是杂音数据，忽略并继续等待
            }
            
            // 校验 Magic Cookie 和 Transaction ID 是否匹配
            if (response_message.magic_cookie != action.message.magic_cookie || 
                response_message.transaction_id != action.message.transaction_id) {
                continue; // 不是当前请求的响应，忽略并继续等待
            }

            // 成功匹配，返回结果
            return StunResponse{response_message, from_sockaddr(reinterpret_cast<sockaddr*>(&response_remote), response_length),
                                socket_local_endpoint(socket_)};
        }

        // 3. 指数退避：如果没收到响应，把等待时间翻倍
        rto *= 2; 
    }

    // 达到总超时时间，彻底失败
    return std::nullopt;
}

TcpSession::TcpSession(const std::string& server_name,
                       const std::optional<IpEndpoint>& local_bind,
                       std::chrono::milliseconds timeout,
                       bool use_tls,
                       bool skip_certificate_validation)
    : local_bind_(local_bind),
      timeout_(timeout),
      server_name_(server_name),
      use_tls_(use_tls),
      skip_certificate_validation_(skip_certificate_validation) {}

std::optional<StunResponse> TcpSession::request(const StunDiscoveryAction& action) {
    int socket_fd = socket(action.send_to.family, SOCK_STREAM, IPPROTO_TCP);
    if (socket_fd < 0) {
        throw system_error("socket failed");
    }

    try {
        bind_if_needed(socket_fd, local_bind_.value_or(wildcard_endpoint(action.send_to.family)));
        connect_with_timeout(socket_fd, action.send_to, timeout_);
        set_socket_timeouts(socket_fd, timeout_);

        std::vector<std::uint8_t> payload = serialize(action.message);
        IpEndpoint local = socket_local_endpoint(socket_fd);

        if (!local_bind_.has_value() || local_bind_->port == 0) {
            local_bind_ = local;
        }

        if (!use_tls_) {
            std::size_t offset = 0;
            while (offset < payload.size()) {
                ssize_t written = send(socket_fd, payload.data() + offset, payload.size() - offset, 0);
                if (written <= 0) {
                    throw system_error("send failed");
                }
                offset += static_cast<std::size_t>(written);
            }

            std::vector<std::uint8_t> buffer(65536);
            std::size_t received_total = 0;
            while (wait_for_readable(socket_fd, timeout_)) {
                ssize_t received = recv(socket_fd, buffer.data() + received_total, buffer.size() - received_total, 0);
                if (received <= 0) {
                    break;
                }
                received_total += static_cast<std::size_t>(received);
                StunMessage response_message;
                if (parse_message(buffer.data(), received_total, response_message) &&
                    response_message.magic_cookie == action.message.magic_cookie &&
                    response_message.transaction_id == action.message.transaction_id) {
                    close(socket_fd);
                    if (!local_bind_.has_value()) {
                        local_bind_ = local;
                    }
                    return StunResponse{response_message, action.send_to, local};
                }
            }
        } else {
            std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx(create_ssl_ctx(!skip_certificate_validation_), SSL_CTX_free);
            std::unique_ptr<SSL, decltype(&SSL_free)> ssl(SSL_new(ctx.get()), SSL_free);
            if (!ssl) {
                throw std::runtime_error("SSL_new failed");
            }

            if (!skip_certificate_validation_) {
                if (is_ip_literal(server_name_)) {
                    X509_VERIFY_PARAM* param = SSL_get0_param(ssl.get());
                    if (X509_VERIFY_PARAM_set1_ip_asc(param, server_name_.c_str()) != 1) {
                        throw std::runtime_error("failed to configure TLS IP verification");
                    }
                } else {
                    SSL_set_tlsext_host_name(ssl.get(), server_name_.c_str());
                    X509_VERIFY_PARAM* param = SSL_get0_param(ssl.get());
                    if (X509_VERIFY_PARAM_set1_host(param, server_name_.c_str(), 0) != 1) {
                        throw std::runtime_error("failed to configure TLS hostname verification");
                    }
                }
            }

            SSL_set_fd(ssl.get(), socket_fd);
            if (SSL_connect(ssl.get()) != 1) {
                throw std::runtime_error("SSL_connect failed");
            }

            std::size_t offset = 0;
            while (offset < payload.size()) {
                int written = SSL_write(ssl.get(), payload.data() + offset, static_cast<int>(payload.size() - offset));
                if (written <= 0) {
                    throw std::runtime_error("SSL_write failed");
                }
                offset += static_cast<std::size_t>(written);
            }

            std::vector<std::uint8_t> buffer(65536);
            std::size_t received_total = 0;
            while (wait_for_readable(socket_fd, timeout_)) {
                int received = SSL_read(ssl.get(), buffer.data() + received_total, static_cast<int>(buffer.size() - received_total));
                if (received <= 0) {
                    break;
                }
                received_total += static_cast<std::size_t>(received);
                StunMessage response_message;
                if (parse_message(buffer.data(), received_total, response_message) &&
                    response_message.magic_cookie == action.message.magic_cookie &&
                    response_message.transaction_id == action.message.transaction_id) {
                    SSL_shutdown(ssl.get());
                    close(socket_fd);
                    if (!local_bind_.has_value()) {
                        local_bind_ = local;
                    }
                    return StunResponse{response_message, action.send_to, local};
                }
            }
        }

        close(socket_fd);
    } catch (...) {
        close(socket_fd);
        throw;
    }

    return std::nullopt;
}

} // namespace natcli
