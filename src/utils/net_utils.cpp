#include "net_utils.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace natcli {

// ---- Socket address helpers ----

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
    throw std::runtime_error("Unsupported address family");
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

// ---- Error helpers ----

std::runtime_error system_error(const std::string& message) {
    return std::runtime_error(message + ": " + std::strerror(errno));
}

// ---- Socket option helpers ----

void set_reuse_options(int socket_fd) {
    int reuse = 1;
    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#ifdef SO_REUSEPORT
    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
#endif
}

void set_socket_timeouts(int socket_fd, std::chrono::milliseconds timeout) {
    timeval value{};
    value.tv_sec = static_cast<long>(timeout.count() / 1000);
    value.tv_usec = static_cast<long>((timeout.count() % 1000) * 1000);
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &value, sizeof(value));
    setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, &value, sizeof(value));
}

void bind_socket(int socket_fd, const IpEndpoint& endpoint) {
    SocketAddress address = to_sockaddr(endpoint);
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

// ---- I/O helpers ----

bool wait_for_readable(int socket_fd, std::chrono::milliseconds timeout) {
    pollfd descriptor{socket_fd, POLLIN, 0};
    int rc = poll(&descriptor, 1, static_cast<int>(timeout.count()));
    return rc > 0 && (descriptor.revents & POLLIN) != 0;
}

bool wait_for_error(int socket_fd, std::chrono::milliseconds timeout) {
    pollfd descriptor{socket_fd, 0, 0};
    int rc = poll(&descriptor, 1, static_cast<int>(timeout.count()));
    if (rc <= 0 || (descriptor.revents & POLLERR) == 0) {
        return false;
    }
    int socket_error = 0;
    socklen_t error_length = sizeof(socket_error);
    return getsockopt(socket_fd, SOL_SOCKET, SO_ERROR, &socket_error, &error_length) == 0 && socket_error != 0;
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

// ---- Socket state helpers ----

bool disconnect_udp_socket(int socket_fd) {
    sockaddr_storage storage{};
    storage.ss_family = AF_UNSPEC;
    return connect(socket_fd, reinterpret_cast<sockaddr*>(&storage), sizeof(sa_family_t)) == 0;
}

bool is_wildcard_endpoint_address(const IpEndpoint& endpoint) {
    if (endpoint.family == AF_INET) {
        constexpr std::size_t ipv4_size = 4;
        for (std::size_t index = 0; index < ipv4_size; ++index) {
            if (endpoint.address[index] != 0) {
                return false;
            }
        }
        return true;
    }
    if (endpoint.family == AF_INET6) {
        constexpr std::size_t ipv6_size = 16;
        for (std::size_t index = 0; index < ipv6_size; ++index) {
            if (endpoint.address[index] != 0) {
                return false;
            }
        }
        return true;
    }
    return false;
}

bool can_connect_udp_from_local_address(const IpEndpoint& local, const IpEndpoint& remote) {
    int socket_fd = socket(remote.family, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd < 0) {
        return false;
    }
    bool ok = false;
    try {
        IpEndpoint local_address_only = local;
        local_address_only.port = 0;
        bind_socket(socket_fd, local_address_only);
        SocketAddress remote_address = to_sockaddr(remote);
        ok = connect(socket_fd, reinterpret_cast<sockaddr*>(&remote_address.storage), remote_address.length) == 0;
    } catch (...) {
        ok = false;
    }
    close(socket_fd);
    return ok;
}

IpEndpoint infer_local_source_for_remote(const IpEndpoint& remote) {
    int socket_fd = socket(remote.family, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd < 0) {
        throw system_error("socket failed");
    }
    try {
        SocketAddress remote_address = to_sockaddr(remote);
        if (connect(socket_fd, reinterpret_cast<sockaddr*>(&remote_address.storage), remote_address.length) != 0) {
            throw system_error("connect failed");
        }
        IpEndpoint local = socket_local_endpoint(socket_fd);
        close(socket_fd);
        return local;
    } catch (...) {
        close(socket_fd);
        throw;
    }
}

IpEndpoint select_control_local_endpoint(const IpEndpoint& local, const IpEndpoint& remote) {
    IpEndpoint selected = local;
    if (!is_wildcard_endpoint_address(local) && can_connect_udp_from_local_address(local, remote)) {
        return selected;
    }
    IpEndpoint routed_local = infer_local_source_for_remote(remote);
    selected.address = routed_local.address;
    selected.address_length = routed_local.address_length;
    selected.family = routed_local.family;
    return selected;
}

// ---- Endpoint comparison helpers ----

bool same_endpoint_address(const IpEndpoint& left, const IpEndpoint& right) {
    if (left.family != right.family || left.address_length != right.address_length) {
        return false;
    }
    return std::equal(left.address.begin(), left.address.begin() + left.address_length, right.address.begin());
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

// ---- Checksum helpers ----

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
    add_buffer(&ip_header.saddr, sizeof(ip_header.saddr));
    add_buffer(&ip_header.daddr, sizeof(ip_header.daddr));
    std::uint16_t protocol = htons(IPPROTO_UDP);
    add_buffer(&protocol, sizeof(protocol));
    std::uint16_t udp_length = udp_header.len;
    add_buffer(&udp_length, sizeof(udp_length));
    add_buffer(&udp_header, sizeof(udphdr));
    if (payload != nullptr && payload_len > 0) {
        add_buffer(payload, payload_len);
    }
    while ((sum >> 16) != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    const std::uint16_t checksum = static_cast<std::uint16_t>(~sum);
    return checksum == 0 ? 0xFFFF : checksum;
}

// ---- Protocol line parsing helpers ----

std::optional<IpEndpoint> parse_endpoint_line(const std::string& line, int family) {
    std::istringstream stream(line);
    std::string host;
    std::uint16_t port = 0;
    if (!(stream >> host >> port)) {
        return std::nullopt;
    }
    return resolve_endpoint(host, port, SOCK_STREAM, family);
}

bool parse_flag_response(const std::string& response, char key) {
    if (response.size() != 3 || response[0] != key || response[1] != '=') {
        return false;
    }
    return response[2] == '1';
}

} // namespace natcli
