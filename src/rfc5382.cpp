#include "rfc5382.hpp"

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
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace natcli {
namespace {

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

void set_reuse_options(int socket_fd) {
    int reuse = 1;
    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#ifdef SO_REUSEPORT
    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
#endif
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

std::pair<bool, bool> parse_filter_line(const std::string& line) {
    std::istringstream stream(line);
    std::string p_field;
    std::string s_field;
    if (!(stream >> p_field >> s_field)) {
        throw std::runtime_error("Invalid filtering response");
    }
    auto parse_flag = [](const std::string& field, const char key) -> bool {
        constexpr std::size_t FLAG_FIELD_SIZE = 3; // "P=1" / "S=0"
        if (field.size() != FLAG_FIELD_SIZE || field[0] != key || field[1] != '=') {
            throw std::runtime_error("Invalid filtering response field");
        }
        return field[2] == '1';
    };
    return {parse_flag(p_field, 'P'), parse_flag(s_field, 'S')};
}

std::pair<bool, bool> parse_syn_line(const std::string& line) {
    std::istringstream stream(line);
    std::string immediate_field;
    std::string delayed_field;
    if (!(stream >> immediate_field >> delayed_field)) {
        throw std::runtime_error("Invalid SYN probe response");
    }
    auto parse_flag = [](const std::string& field, const char key) -> bool {
        constexpr std::size_t SYN_FLAG_FIELD_SIZE = 3; // "I=1" / "D=0"
        if (field.size() != SYN_FLAG_FIELD_SIZE || field[0] != key || field[1] != '=') {
            throw std::runtime_error("Invalid SYN probe response field");
        }
        return field[2] == '1';
    };
    return {parse_flag(immediate_field, 'I'), parse_flag(delayed_field, 'D')};
}

std::string request_tcp_command(const IpEndpoint& local,
                                const IpEndpoint& server,
                                std::string_view command,
                                std::chrono::milliseconds timeout) {
    int control = socket(server.family, SOCK_STREAM, IPPROTO_TCP);
    if (control < 0) {
        throw system_error("socket failed");
    }
    try {
        set_reuse_options(control);
        bind_socket(control, local);
        connect_with_timeout(control, server, timeout);
        send_all(control, command);
        std::string line = recv_line(control, timeout);
        close(control);
        return line;
    } catch (...) {
        close(control);
        throw;
    }
}

std::optional<IpEndpoint> request_udp_mapping(const IpEndpoint& local, const IpEndpoint& server, std::chrono::milliseconds timeout) {
    int socket_fd = socket(server.family, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd < 0) {
        throw system_error("socket failed");
    }

    try {
        set_reuse_options(socket_fd);
        bind_socket(socket_fd, local);
        SocketAddress remote = to_sockaddr(server);
        ssize_t sent = sendto(socket_fd, "M\n", 2, 0, reinterpret_cast<sockaddr*>(&remote.storage), remote.length);
        if (sent <= 0) {
            throw system_error("sendto failed");
        }
        if (!wait_for_readable(socket_fd, timeout)) {
            close(socket_fd);
            return std::nullopt;
        }
        std::array<char, 256> buffer{};
        ssize_t received = recv(socket_fd, buffer.data(), buffer.size() - 1, 0);
        if (received <= 0) {
            close(socket_fd);
            return std::nullopt;
        }
        buffer[static_cast<std::size_t>(received)] = '\0';
        close(socket_fd);
        return parse_endpoint_line(std::string(buffer.data()), server.family);
    } catch (...) {
        close(socket_fd);
        throw;
    }
}

} // namespace

Rfc5382TcpResult run_rfc5382_tests(const RequestOptions& options,
                                   const IpEndpoint& primary_server,
                                   const IpEndpoint& secondary_server,
                                   const std::optional<IpEndpoint>& local_bind) {
    if (primary_server.family != secondary_server.family) {
        throw std::runtime_error("Primary and secondary server must use the same IP family.");
    }

    int listener = socket(primary_server.family, SOCK_STREAM, IPPROTO_TCP);
    if (listener < 0) {
        throw system_error("socket failed");
    }

    Rfc5382TcpResult result;
    try {
        set_reuse_options(listener);
        bind_socket(listener, local_bind.value_or(wildcard_endpoint(primary_server.family)));
        if (listen(listener, 8) != 0) {
            throw system_error("listen failed");
        }
        result.local_endpoint = socket_local_endpoint(listener);
        IpEndpoint control_local = *result.local_endpoint;
        if (is_wildcard_endpoint_address(control_local)) {
            IpEndpoint routed_local = infer_local_source_for_remote(primary_server);
            control_local.address = routed_local.address;
            control_local.address_length = routed_local.address_length;
            control_local.family = routed_local.family;
        }
        result.local_endpoint = control_local;
        result.tcp_public_endpoint =
            parse_endpoint_line(request_tcp_command(control_local, primary_server, "M\n", options.timeout), primary_server.family);

        if (result.local_endpoint.has_value()) {
            result.udp_public_endpoint = request_udp_mapping(*result.local_endpoint, primary_server, options.timeout);
        }

        auto [primary_ok, secondary_ok] = parse_filter_line(
            request_tcp_command(control_local, primary_server, "F\n", options.timeout));
        result.primary_probe_success = primary_ok;
        result.secondary_probe_success = secondary_ok;
        if (secondary_ok) {
            result.filtering_behavior = FilteringBehavior::EndpointIndependent;
        } else if (primary_ok) {
            result.filtering_behavior = FilteringBehavior::AddressDependent;
        } else {
            result.filtering_behavior = FilteringBehavior::AddressAndPortDependent;
        }
        auto [immediate_ok, delayed_ok] =
            parse_syn_line(request_tcp_command(control_local, primary_server, "S\n", options.timeout));
        result.simultaneous_open = immediate_ok ? ProbeStatus::Pass : ProbeStatus::Fail;
        result.unexpected_syn = delayed_ok ? ProbeStatus::Pass : ProbeStatus::Fail;
        result.icmp_error_handling = ProbeStatus::Inconclusive;

        constexpr int max_drain_accepts = 4; // server sends up to primary+secondary probe connections plus retries
        for (int index = 0; index < max_drain_accepts; ++index) {
            if (!wait_for_readable(listener, std::chrono::milliseconds(100))) {
                break;
            }
            sockaddr_storage incoming{};
            socklen_t length = sizeof(incoming);
            int accepted = accept(listener, reinterpret_cast<sockaddr*>(&incoming), &length);
            if (accepted >= 0) {
                close(accepted);
            }
        }

        close(listener);
        return result;
    } catch (...) {
        close(listener);
        throw;
    }
}

} // namespace natcli
