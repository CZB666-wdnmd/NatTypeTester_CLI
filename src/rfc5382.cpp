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
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace natcli {
namespace {

constexpr std::string_view kUdpMappingRequest = "M\n";
constexpr std::string_view kRfc7857UdpProbePayload = "RFC7857-UDP-PROBE\n";
constexpr char kProbeResultFlagKey = 'R';
constexpr std::string_view kHairpinUdpPayload = "RFC-HAIRPIN-UDP\n";
constexpr std::string_view kHairpinIcmpPayload = "RFC-HAIRPIN-ICMP\n";

struct SocketAddress {
    sockaddr_storage storage{};
    socklen_t length{};
};

void bind_socket(int socket_fd, const IpEndpoint& endpoint);

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

bool parse_flag_response(const std::string& line, char key) {
    if (line.size() != 3 || line[0] != key || line[1] != '=') {
        throw std::runtime_error("Invalid single-flag response");
    }
    if (line[2] == '0') {
        return false;
    }
    if (line[2] == '1') {
        return true;
    }
    throw std::runtime_error("Invalid single-flag value");
}

std::optional<IpEndpoint> request_stun_udp_mapping(int socket_fd,
                                                   const IpEndpoint& stun_server,
                                                   std::chrono::milliseconds timeout) {
    StunMessage request = create_binding_request(0x2112A442u);
    std::vector<std::uint8_t> payload = serialize(request);
    SocketAddress remote = to_sockaddr(stun_server);
    ssize_t sent = sendto(socket_fd,
                          payload.data(),
                          payload.size(),
                          0,
                          reinterpret_cast<sockaddr*>(&remote.storage),
                          remote.length);
    if (sent != static_cast<ssize_t>(payload.size())) {
        return std::nullopt;
    }
    if (!wait_for_readable(socket_fd, timeout)) {
        return std::nullopt;
    }

    std::array<std::uint8_t, 2048> buffer{};
    ssize_t received = recv(socket_fd, buffer.data(), buffer.size(), 0);
    if (received <= 0) {
        return std::nullopt;
    }

    StunMessage response;
    if (!parse_message(buffer.data(), static_cast<std::size_t>(received), response) ||
        response.magic_cookie != request.magic_cookie || response.transaction_id != request.transaction_id) {
        return std::nullopt;
    }

    if (std::optional<IpEndpoint> xor_mapped = get_xor_mapped_address_attribute(response); xor_mapped.has_value()) {
        return xor_mapped;
    }
    return get_mapped_address_attribute(response);
}

std::optional<IpEndpoint> request_stun_tcp_mapping(const IpEndpoint& local_bind,
                                                   const IpEndpoint& stun_server,
                                                   std::chrono::milliseconds timeout,
                                                   std::optional<IpEndpoint>* local_endpoint) {
    int socket_fd = socket(stun_server.family, SOCK_STREAM, IPPROTO_TCP);
    if (socket_fd < 0) {
        return std::nullopt;
    }

    try {
        set_reuse_options(socket_fd);
        bind_socket(socket_fd, local_bind);
        connect_with_timeout(socket_fd, stun_server, timeout);
        *local_endpoint = socket_local_endpoint(socket_fd);

        StunMessage request = create_binding_request(0x2112A442u);
        std::vector<std::uint8_t> payload = serialize(request);
        std::size_t offset = 0;
        while (offset < payload.size()) {
            ssize_t written = send(socket_fd, payload.data() + offset, payload.size() - offset, 0);
            if (written <= 0) {
                close(socket_fd);
                return std::nullopt;
            }
            offset += static_cast<std::size_t>(written);
        }

        std::vector<std::uint8_t> buffer(65536);
        std::size_t received_total = 0;
        while (wait_for_readable(socket_fd, timeout)) {
            ssize_t received = recv(socket_fd, buffer.data() + received_total, buffer.size() - received_total, 0);
            if (received <= 0) {
                break;
            }
            received_total += static_cast<std::size_t>(received);
            StunMessage response;
            if (parse_message(buffer.data(), received_total, response) &&
                response.magic_cookie == request.magic_cookie &&
                response.transaction_id == request.transaction_id) {
                close(socket_fd);
                if (std::optional<IpEndpoint> xor_mapped = get_xor_mapped_address_attribute(response); xor_mapped.has_value()) {
                    return xor_mapped;
                }
                return get_mapped_address_attribute(response);
            }
            if (received_total == buffer.size()) {
                break;
            }
        }
        close(socket_fd);
        return std::nullopt;
    } catch (...) {
        close(socket_fd);
        return std::nullopt;
    }
}

ProbeStatus run_udp_hairpin_probe(const IpEndpoint& stun_server,
                                  const std::optional<IpEndpoint>& local_bind,
                                  std::chrono::milliseconds timeout,
                                  std::optional<IpEndpoint>* public_endpoint) {
    int receiver = socket(stun_server.family, SOCK_DGRAM, IPPROTO_UDP);
    int sender = socket(stun_server.family, SOCK_DGRAM, IPPROTO_UDP);
    if (receiver < 0 || sender < 0) {
        if (receiver >= 0) {
            close(receiver);
        }
        if (sender >= 0) {
            close(sender);
        }
        return ProbeStatus::Inconclusive;
    }

    try {
        set_reuse_options(receiver);
        set_reuse_options(sender);
        const IpEndpoint receiver_bind = local_bind.value_or(wildcard_endpoint(stun_server.family));
        bind_socket(receiver, receiver_bind);

        IpEndpoint sender_bind = receiver_bind;
        sender_bind.port = 0;
        bind_socket(sender, sender_bind);

        *public_endpoint = request_stun_udp_mapping(receiver, stun_server, timeout);
        if (!public_endpoint->has_value()) {
            close(receiver);
            close(sender);
            return ProbeStatus::Inconclusive;
        }

        SocketAddress public_receiver = to_sockaddr(**public_endpoint);
        ssize_t sent = sendto(sender,
                              kHairpinUdpPayload.data(),
                              kHairpinUdpPayload.size(),
                              0,
                              reinterpret_cast<sockaddr*>(&public_receiver.storage),
                              public_receiver.length);
        if (sent != static_cast<ssize_t>(kHairpinUdpPayload.size())) {
            close(receiver);
            close(sender);
            return ProbeStatus::Fail;
        }
        if (!wait_for_readable(receiver, timeout)) {
            close(receiver);
            close(sender);
            return ProbeStatus::Fail;
        }

        std::array<char, 256> buffer{};
        ssize_t received = recv(receiver, buffer.data(), buffer.size(), 0);
        close(receiver);
        close(sender);
        if (received != static_cast<ssize_t>(kHairpinUdpPayload.size())) {
            return ProbeStatus::Fail;
        }
        const std::string_view received_payload(buffer.data(), static_cast<std::size_t>(received));
        return received_payload == kHairpinUdpPayload ? ProbeStatus::Pass : ProbeStatus::Fail;
    } catch (...) {
        close(receiver);
        close(sender);
        return ProbeStatus::Inconclusive;
    }
}

ProbeStatus run_tcp_hairpin_probe(const IpEndpoint& stun_server,
                                  const std::optional<IpEndpoint>& local_bind,
                                  std::chrono::milliseconds timeout) {
    std::optional<IpEndpoint> mapped_public;
    std::optional<IpEndpoint> mapped_local;
    IpEndpoint mapping_bind = local_bind.value_or(wildcard_endpoint(stun_server.family));
    mapping_bind.port = 0;
    mapped_public = request_stun_tcp_mapping(mapping_bind, stun_server, timeout, &mapped_local);
    if (!mapped_public.has_value() || !mapped_local.has_value()) {
        return ProbeStatus::Inconclusive;
    }

    int listener = socket(stun_server.family, SOCK_STREAM, IPPROTO_TCP);
    if (listener < 0) {
        return ProbeStatus::Inconclusive;
    }

    try {
        set_reuse_options(listener);
        bind_socket(listener, *mapped_local);
        if (listen(listener, 1) != 0) {
            close(listener);
            return ProbeStatus::Inconclusive;
        }

        int connector = socket(stun_server.family, SOCK_STREAM, IPPROTO_TCP);
        if (connector < 0) {
            close(listener);
            return ProbeStatus::Inconclusive;
        }
        set_reuse_options(connector);
        IpEndpoint connector_bind = local_bind.value_or(wildcard_endpoint(stun_server.family));
        connector_bind.port = 0;
        bind_socket(connector, connector_bind);

        ProbeStatus status = ProbeStatus::Fail;
        try {
            connect_with_timeout(connector, *mapped_public, timeout);
            if (wait_for_readable(listener, timeout)) {
                sockaddr_storage incoming{};
                socklen_t length = sizeof(incoming);
                int accepted = accept(listener, reinterpret_cast<sockaddr*>(&incoming), &length);
                if (accepted >= 0) {
                    status = ProbeStatus::Pass;
                    close(accepted);
                }
            }
        } catch (...) {
            status = ProbeStatus::Fail;
        }

        close(connector);
        close(listener);
        return status;
    } catch (...) {
        close(listener);
        return ProbeStatus::Inconclusive;
    }
}

ProbeStatus run_icmp_hairpin_probe(const IpEndpoint& stun_server,
                                   const std::optional<IpEndpoint>& local_bind,
                                   std::chrono::milliseconds timeout,
                                   const std::optional<IpEndpoint>& udp_public_endpoint) {
    if (!udp_public_endpoint.has_value()) {
        return ProbeStatus::Inconclusive;
    }

    int socket_fd = socket(stun_server.family, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd < 0) {
        return ProbeStatus::Inconclusive;
    }

    try {
        set_reuse_options(socket_fd);
        IpEndpoint local = local_bind.value_or(wildcard_endpoint(stun_server.family));
        local.port = 0;
        bind_socket(socket_fd, local);

        IpEndpoint probe_target = *udp_public_endpoint;
        probe_target.port = probe_target.port == std::numeric_limits<std::uint16_t>::max()
                                ? std::numeric_limits<std::uint16_t>::max() - 1
                                : probe_target.port + 1;
        SocketAddress target = to_sockaddr(probe_target);
        if (connect(socket_fd, reinterpret_cast<sockaddr*>(&target.storage), target.length) != 0) {
            close(socket_fd);
            return ProbeStatus::Inconclusive;
        }

        ssize_t sent = send(socket_fd, kHairpinIcmpPayload.data(), kHairpinIcmpPayload.size(), 0);
        if (sent != static_cast<ssize_t>(kHairpinIcmpPayload.size())) {
            close(socket_fd);
            return ProbeStatus::Fail;
        }

        pollfd descriptor{socket_fd, POLLIN | POLLERR, 0};
        const int rc = poll(&descriptor, 1, static_cast<int>(timeout.count()));
        if (rc > 0 && (descriptor.revents & POLLERR) != 0) {
            int error = 0;
            socklen_t error_length = sizeof(error);
            if (getsockopt(socket_fd, SOL_SOCKET, SO_ERROR, &error, &error_length) == 0 && error != 0) {
                close(socket_fd);
                return ProbeStatus::Pass;
            }
        }
        if (rc > 0 && (descriptor.revents & POLLIN) != 0) {
            close(socket_fd);
            return ProbeStatus::Fail;
        }

        close(socket_fd);
        return ProbeStatus::Inconclusive;
    } catch (...) {
        close(socket_fd);
        return ProbeStatus::Inconclusive;
    }
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
        
        // 关键修正: 配置 SO_LINGER，在关闭 socket 时直接发送 RST。
        // 这将跳过 TCP 的 TIME_WAIT 状态，释放掉五元组，
        // 使得后续的 connect 能够成功，从而解决 EADDRNOTAVAIL 报错。
        linger sl{1, 0};
        setsockopt(control, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));

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
        ssize_t sent = sendto(socket_fd, kUdpMappingRequest.data(), kUdpMappingRequest.size(), 0,
                              reinterpret_cast<sockaddr*>(&remote.storage), remote.length);
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

std::optional<bool> probe_tcp_mapping_allows_udp(const IpEndpoint& local,
                                                 const IpEndpoint& server,
                                                 std::chrono::milliseconds timeout) {
    int socket_fd = socket(server.family, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd < 0) {
        throw system_error("socket failed");
    }

    try {
        set_reuse_options(socket_fd);
        bind_socket(socket_fd, local);
        const bool server_probe_sent =
            parse_flag_response(request_tcp_command(local, server, "U\n", timeout), kProbeResultFlagKey);
        if (!server_probe_sent) {
            close(socket_fd);
            return std::nullopt;
        }

        if (!wait_for_readable(socket_fd, timeout)) {
            close(socket_fd);
            return false;
        }
        std::array<char, 256> buffer{};
        ssize_t received = recv(socket_fd, buffer.data(), buffer.size(), 0);
        close(socket_fd);
        if (received <= 0) {
            return false;
        }
        const std::string_view received_payload(buffer.data(), static_cast<std::size_t>(received));
        return received_payload == kRfc7857UdpProbePayload;
    } catch (...) {
        close(socket_fd);
        throw;
    }
}

std::optional<bool> probe_udp_mapping_allows_tcp(const IpEndpoint& local,
                                                 const IpEndpoint& server,
                                                 std::chrono::milliseconds timeout) {
    int udp_socket = socket(server.family, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_socket < 0) {
        throw system_error("socket failed");
    }

    try {
        set_reuse_options(udp_socket);
        bind_socket(udp_socket, local);

        SocketAddress remote = to_sockaddr(server);
        ssize_t sent = sendto(udp_socket, kUdpMappingRequest.data(), kUdpMappingRequest.size(), 0,
                              reinterpret_cast<sockaddr*>(&remote.storage), remote.length);
        if (sent <= 0) {
            throw system_error("sendto failed");
        }
        if (!wait_for_readable(udp_socket, timeout)) {
            close(udp_socket);
            return std::nullopt;
        }
        std::array<char, 256> buffer{};
        ssize_t received = recv(udp_socket, buffer.data(), buffer.size() - 1, 0);
        if (received <= 0) {
            close(udp_socket);
            return std::nullopt;
        }
        buffer[static_cast<std::size_t>(received)] = '\0';
        std::optional<IpEndpoint> udp_public = parse_endpoint_line(std::string(buffer.data()), server.family);
        if (!udp_public.has_value()) {
            close(udp_socket);
            return std::nullopt;
        }

        const std::string command = "C " + to_string(*udp_public) + "\n";
        const bool tcp_probe_connected =
            parse_flag_response(request_tcp_command(local, server, command, timeout), kProbeResultFlagKey);
        close(udp_socket);
        return tcp_probe_connected;
    } catch (...) {
        close(udp_socket);
        throw;
    }
}

} // namespace

HairpinningResult run_hairpinning_tests(const RequestOptions& options,
                                        const IpEndpoint& stun_server,
                                        const std::optional<IpEndpoint>& local_bind) {
    HairpinningResult result;
    std::optional<IpEndpoint> udp_public_endpoint;
    result.udp = run_udp_hairpin_probe(stun_server, local_bind, options.timeout, &udp_public_endpoint);
    result.tcp = run_tcp_hairpin_probe(stun_server, local_bind, options.timeout);
    result.icmp = run_icmp_hairpin_probe(stun_server, local_bind, options.timeout, udp_public_endpoint);
    return result;
}

Rfc5382TcpResult run_rfc5382_tests(const RequestOptions& options,
                                   const IpEndpoint& stun_server,
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
        IpEndpoint control_local = select_control_local_endpoint(*result.local_endpoint, primary_server);
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
        HairpinningResult hairpin = run_hairpinning_tests(options, stun_server, local_bind);
        result.udp_hairpinning = hairpin.udp;
        result.tcp_hairpinning = hairpin.tcp;
        result.icmp_hairpinning = hairpin.icmp;
        if (result.local_endpoint.has_value()) {
            result.tcp_mapping_allows_udp =
                probe_tcp_mapping_allows_udp(*result.local_endpoint, primary_server, options.timeout);
            result.udp_mapping_allows_tcp =
                probe_udp_mapping_allows_tcp(*result.local_endpoint, primary_server, options.timeout);
        }

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
