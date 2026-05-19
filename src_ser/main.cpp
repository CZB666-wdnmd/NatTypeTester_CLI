#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {

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

std::string recv_line(int socket_fd) {
    std::string line;
    std::array<char, 256> buffer{};
    while (line.find('\n') == std::string::npos) {
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

void handle_tcp_client(int client_fd,
                       const IpEndpoint& primary_server,
                       const IpEndpoint& secondary_server,
                       int connection_probe_timeout_ms,
                       int syn_delay_ms) {
    try {
        sockaddr_storage peer{};
        socklen_t peer_length = sizeof(peer);
        if (getpeername(client_fd, reinterpret_cast<sockaddr*>(&peer), &peer_length) != 0) {
            throw system_error("getpeername failed");
        }
        IpEndpoint peer_endpoint = from_sockaddr(reinterpret_cast<sockaddr*>(&peer), peer_length);
        while (true) {
            std::string command = recv_line(client_fd);
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
                constexpr std::string_view payload = "RFC7857-UDP-PROBE\n";
                bool sent = try_send_udp_from_source(udp_source, peer_endpoint, payload);
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
            send_all(client_fd, "ERR\n");
        }
    } catch (...) {
    }
}

void handle_udp_packet(int udp_fd) {
    constexpr std::size_t UDP_BUFFER_SIZE = 4096;
    sockaddr_storage peer{};
    socklen_t peer_length = sizeof(peer);
    std::vector<char> buffer(UDP_BUFFER_SIZE);
    ssize_t received = recvfrom(udp_fd, buffer.data(), buffer.size(), 0, reinterpret_cast<sockaddr*>(&peer), &peer_length);
    if (received <= 0) {
        return;
    }

    const bool is_mapping_request = received <= 2 && buffer[0] == 'M';
    if (is_mapping_request) {
        IpEndpoint peer_endpoint = from_sockaddr(reinterpret_cast<sockaddr*>(&peer), peer_length);
        std::string payload = endpoint_line(peer_endpoint);
        sendto(udp_fd, payload.data(), payload.size(), 0, reinterpret_cast<sockaddr*>(&peer), peer_length);
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
                std::cout << "Usage: nat_type_tester_rfc5382_server --primary host[:port] --secondary host[:port] [--probe-timeout-ms 1200] [--syn-delay-ms 350]\n";
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

        int primary_tcp_fd = create_tcp_listener(primary_server);
        int secondary_tcp_fd = create_tcp_listener(secondary_server);
        int primary_udp_fd = create_udp_listener(primary_server);
        int secondary_udp_fd = create_udp_listener(secondary_server);

        std::cout << "Server ready. Primary=" << primary_host << ":" << primary_port
                  << " Secondary=" << secondary_host << ":" << secondary_port << '\n';

        while (true) {
            std::array<pollfd, 4> descriptors{{
                {primary_tcp_fd, POLLIN, 0},
                {secondary_tcp_fd, POLLIN, 0},
                {primary_udp_fd, POLLIN, 0},
                {secondary_udp_fd, POLLIN, 0},
            }};
            int rc = poll(descriptors.data(), descriptors.size(), -1);
            if (rc < 0) {
                throw system_error("poll failed");
            }

            if (descriptors[2].revents & POLLIN) {
                handle_udp_packet(primary_udp_fd);
            }
            if (descriptors[3].revents & POLLIN) {
                handle_udp_packet(secondary_udp_fd);
            }
            if (descriptors[0].revents & POLLIN) {
                sockaddr_storage client{};
                socklen_t length = sizeof(client);
                int client_fd = accept(primary_tcp_fd, reinterpret_cast<sockaddr*>(&client), &length);
                if (client_fd >= 0) {
                    handle_tcp_client(client_fd, primary_server, secondary_server, connection_probe_timeout_ms, syn_delay_ms);
                    close(client_fd);
                }
            }
            if (descriptors[1].revents & POLLIN) {
                sockaddr_storage client{};
                socklen_t length = sizeof(client);
                int client_fd = accept(secondary_tcp_fd, reinterpret_cast<sockaddr*>(&client), &length);
                if (client_fd >= 0) {
                    handle_tcp_client(client_fd, primary_server, secondary_server, connection_probe_timeout_ms, syn_delay_ms);
                    close(client_fd);
                }
            }
        }
    } catch (const std::exception& exception) {
        std::cerr << "Error: " << exception.what() << '\n';
        return 1;
    }
}
