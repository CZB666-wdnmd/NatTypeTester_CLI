#include "rfc5508.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <optional>
#include <random>
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

struct MappingProbeSample {
    std::string token;
    std::optional<IpEndpoint> public_endpoint;
    std::optional<std::uint16_t> public_query;
    bool path_ok{false};
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

void set_reuse_options(int socket_fd) {
    int reuse = 1;
    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#ifdef SO_REUSEPORT
    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
#endif
}

bool wait_for_readable(int socket_fd, std::chrono::milliseconds timeout) {
    pollfd descriptor{socket_fd, POLLIN, 0};
    int rc = poll(&descriptor, 1, static_cast<int>(timeout.count()));
    return rc > 0 && (descriptor.revents & POLLIN) != 0;
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
        sockaddr_storage local_storage{};
        socklen_t local_length = sizeof(local_storage);
        if (getsockname(socket_fd, reinterpret_cast<sockaddr*>(&local_storage), &local_length) != 0) {
            throw system_error("getsockname failed");
        }
        close(socket_fd);
        return from_sockaddr(reinterpret_cast<sockaddr*>(&local_storage), local_length);
    } catch (...) {
        close(socket_fd);
        throw;
    }
}

std::uint16_t calculate_checksum(const void* data, std::size_t len) {
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

std::vector<std::uint8_t> build_icmp_echo(std::uint8_t type,
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
    icmp->checksum = calculate_checksum(packet.data(), packet.size());
    return packet;
}

bool send_icmp_echo(int raw_fd,
                    const IpEndpoint& target,
                    std::uint8_t type,
                    std::uint16_t identifier,
                    std::uint16_t sequence,
                    std::string_view payload) {
    std::vector<std::uint8_t> packet = build_icmp_echo(type, identifier, sequence, payload);
    SocketAddress destination = to_sockaddr(target);
    const ssize_t sent = sendto(raw_fd,
                                packet.data(),
                                packet.size(),
                                0,
                                reinterpret_cast<sockaddr*>(&destination.storage),
                                destination.length);
    return sent == static_cast<ssize_t>(packet.size());
}

struct IcmpPacket {
    IpEndpoint source;
    std::uint8_t type{0};
    std::uint8_t code{0};
    std::uint16_t identifier{0};
    std::uint16_t sequence{0};
    std::string payload;
};

std::optional<IcmpPacket> receive_icmp_packet(int raw_fd, std::chrono::milliseconds timeout) {
    if (!wait_for_readable(raw_fd, timeout)) {
        return std::nullopt;
    }
    std::array<std::uint8_t, 4096> buffer{};
    sockaddr_storage peer{};
    socklen_t peer_length = sizeof(peer);
    const ssize_t received =
        recvfrom(raw_fd, buffer.data(), buffer.size(), 0, reinterpret_cast<sockaddr*>(&peer), &peer_length);
    if (received <= static_cast<ssize_t>(sizeof(iphdr) + sizeof(icmphdr))) {
        return std::nullopt;
    }

    const auto* ip = reinterpret_cast<const iphdr*>(buffer.data());
    if (ip->version != 4 || ip->protocol != IPPROTO_ICMP) {
        return std::nullopt;
    }
    const std::size_t ip_header_size = static_cast<std::size_t>(ip->ihl) * 4;
    if (received <= static_cast<ssize_t>(ip_header_size + sizeof(icmphdr))) {
        return std::nullopt;
    }

    const auto* icmp = reinterpret_cast<const icmphdr*>(buffer.data() + ip_header_size);
    const char* payload_data = reinterpret_cast<const char*>(buffer.data() + ip_header_size + sizeof(icmphdr));
    const std::size_t payload_size = static_cast<std::size_t>(received) - ip_header_size - sizeof(icmphdr);

    IcmpPacket packet;
    packet.source = from_sockaddr(reinterpret_cast<sockaddr*>(&peer), peer_length);
    packet.type = icmp->type;
    packet.code = icmp->code;
    packet.identifier = ntohs(icmp->un.echo.id);
    packet.sequence = ntohs(icmp->un.echo.sequence);
    packet.payload.assign(payload_data, payload_size);
    return packet;
}

void try_disable_kernel_icmp_echo_auto_reply() {
    std::ofstream sysctl_file("/proc/sys/net/ipv4/icmp_echo_ignore_all");
    if (sysctl_file.good()) {
        sysctl_file << "1\n";
    }
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

std::string request_control_command(const IpEndpoint& control_local,
                                    const IpEndpoint& server,
                                    std::string_view command,
                                    std::chrono::milliseconds timeout) {
    int control = socket(server.family, SOCK_STREAM, IPPROTO_TCP);
    if (control < 0) {
        throw system_error("socket failed");
    }
    try {
        set_reuse_options(control);
        SocketAddress local_address = to_sockaddr(control_local);
        if (bind(control, reinterpret_cast<sockaddr*>(&local_address.storage), local_address.length) != 0) {
            throw system_error("bind failed");
        }

        SocketAddress remote = to_sockaddr(server);
        const int flags = fcntl(control, F_GETFL, 0);
        if (flags < 0 || fcntl(control, F_SETFL, flags | O_NONBLOCK) != 0) {
            throw system_error("fcntl failed");
        }
        int rc = connect(control, reinterpret_cast<sockaddr*>(&remote.storage), remote.length);
        if (rc != 0 && errno != EINPROGRESS) {
            throw system_error("connect failed");
        }
        pollfd out_descriptor{control, POLLOUT, 0};
        rc = poll(&out_descriptor, 1, static_cast<int>(timeout.count()));
        if (rc <= 0) {
            throw std::runtime_error("connect timed out");
        }
        int error = 0;
        socklen_t error_length = sizeof(error);
        if (getsockopt(control, SOL_SOCKET, SO_ERROR, &error, &error_length) != 0 || error != 0) {
            if (error != 0) {
                errno = error;
            }
            throw system_error("connect failed");
        }
        (void)fcntl(control, F_SETFL, flags);

        send_all(control, command);
        std::string line = recv_line(control, timeout);
        close(control);
        return line;
    } catch (...) {
        close(control);
        throw;
    }
}

std::string make_token(std::mt19937& generator) {
    std::uniform_int_distribution<std::uint32_t> distribution(0, 0xFFFFFFFFu);
    std::ostringstream stream;
    stream << "T" << std::hex << distribution(generator) << distribution(generator);
    return stream.str();
}

MappingProbeSample run_mapping_probe(int raw_fd,
                                     const IpEndpoint& target_server,
                                     const IpEndpoint& control_server,
                                     const IpEndpoint& control_local,
                                     std::uint16_t local_query,
                                     std::uint16_t remote_query,
                                     std::chrono::milliseconds timeout,
                                     std::mt19937& generator) {
    MappingProbeSample sample;
    sample.token = make_token(generator);
    const std::string payload = "RFC5508-M:" + sample.token;

    if (!send_icmp_echo(raw_fd, target_server, ICMP_ECHO, local_query, remote_query, payload)) {
        return sample;
    }

    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
        std::optional<IcmpPacket> packet = receive_icmp_packet(raw_fd, remaining);
        if (!packet.has_value()) {
            break;
        }
        if (packet->type != ICMP_ECHOREPLY || packet->payload != payload || !same_address(packet->source, target_server)) {
            continue;
        }
        sample.path_ok = true;
        break;
    }
    if (!sample.path_ok) {
        return sample;
    }

    const std::string response =
        request_control_command(control_local, control_server, "IM " + sample.token + "\n", timeout);
    std::istringstream stream(response);
    std::string prefix;
    std::string host;
    std::uint16_t mapped_query = 0;
    if (!(stream >> prefix >> host >> mapped_query) || prefix != "M") {
        return sample;
    }

    sample.public_endpoint = resolve_endpoint(host, 0, SOCK_STREAM, AF_INET);
    sample.public_endpoint->port = mapped_query;
    sample.public_query = mapped_query;
    return sample;
}

bool parse_flag_response(const std::string& response, char key) {
    if (response.size() != 3 || response[0] != key || response[1] != '=') {
        return false;
    }
    return response[2] == '1';
}

bool run_filter_probe(int raw_fd,
                      const IpEndpoint& control_local,
                      const IpEndpoint& control_server,
                      std::string_view role,
                      const std::string& token,
                      std::uint16_t probe_query,
                      const IpEndpoint& expected_source,
                      std::chrono::milliseconds timeout) {
    const std::string command = "IF " + std::string(role) + " " + token + " " + std::to_string(probe_query) + "\n";
    const std::string sent = request_control_command(control_local, control_server, command, timeout);
    if (!parse_flag_response(sent, 'F')) {
        return false;
    }

    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
        std::optional<IcmpPacket> packet = receive_icmp_packet(raw_fd, remaining);
        if (!packet.has_value()) {
            return false;
        }
        if (packet->type != ICMP_ECHO || !same_address(packet->source, expected_source)) {
            continue;
        }
        const std::string expected_payload = "RFC5508-F:" + token + ":" + std::to_string(probe_query);
        if (packet->payload == expected_payload) {
            return true;
        }
    }
    return false;
}

} // namespace

Rfc5508Result run_rfc5508_tests(const RequestOptions& options,
                                Rfc5508TestType test_type,
                                const IpEndpoint& primary_server,
                                const IpEndpoint& secondary_server,
                                const std::optional<IpEndpoint>& local_bind) {
    if (primary_server.family != AF_INET || secondary_server.family != AF_INET) {
        throw std::runtime_error("RFC5508 ICMP test currently supports IPv4 only.");
    }

    try_disable_kernel_icmp_echo_auto_reply();

    Rfc5508Result result;
    result.local_endpoint = local_bind.has_value() ? local_bind : std::optional<IpEndpoint>(infer_local_source_for_remote(primary_server));

    int raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (raw_fd < 0) {
        throw system_error("socket failed");
    }

    try {
        set_reuse_options(raw_fd);
        if (result.local_endpoint.has_value()) {
            IpEndpoint bind_local = *result.local_endpoint;
            bind_local.port = 0;
            SocketAddress local = to_sockaddr(bind_local);
            if (bind(raw_fd, reinterpret_cast<sockaddr*>(&local.storage), local.length) != 0) {
                throw system_error("bind failed");
            }
        }

        std::random_device seed;
        std::mt19937 generator(seed());
        std::uniform_int_distribution<int> query_dist(1024, 65535);
        const std::uint16_t local_query = static_cast<std::uint16_t>(query_dist(generator));
        result.local_query = local_query;

        const bool run_all = test_type == Rfc5508TestType::All;

        if (run_all || test_type == Rfc5508TestType::Mapping) {
            const MappingProbeSample primary_sample = run_mapping_probe(raw_fd,
                                                                        primary_server,
                                                                        primary_server,
                                                                        *result.local_endpoint,
                                                                        local_query,
                                                                        100,
                                                                        options.timeout,
                                                                        generator);
            const MappingProbeSample secondary_sample = run_mapping_probe(raw_fd,
                                                                          secondary_server,
                                                                          primary_server,
                                                                          *result.local_endpoint,
                                                                          local_query,
                                                                          100,
                                                                          options.timeout,
                                                                          generator);

            result.public_endpoint = primary_sample.public_endpoint;
            result.public_query = primary_sample.public_query;

            if (!primary_sample.path_ok || !secondary_sample.path_ok || !primary_sample.public_query.has_value() ||
                !secondary_sample.public_query.has_value()) {
                result.mapping_behavior = MappingBehavior::Fail;
            } else if (*primary_sample.public_query == *secondary_sample.public_query) {
                result.mapping_behavior = MappingBehavior::EndpointIndependent;
            } else {
                const MappingProbeSample same_ip_diff_query = run_mapping_probe(raw_fd,
                                                                                 primary_server,
                                                                                 primary_server,
                                                                                 *result.local_endpoint,
                                                                                 local_query,
                                                                                 200,
                                                                                 options.timeout,
                                                                                 generator);
                if (!same_ip_diff_query.path_ok || !same_ip_diff_query.public_query.has_value()) {
                    result.mapping_behavior = MappingBehavior::Fail;
                } else if (*same_ip_diff_query.public_query == *primary_sample.public_query) {
                    result.mapping_behavior = MappingBehavior::AddressDependent;
                } else {
                    result.mapping_behavior = MappingBehavior::AddressAndPortDependent;
                }
            }
        }

        if (run_all || test_type == Rfc5508TestType::Filtering) {
            const MappingProbeSample base = run_mapping_probe(raw_fd,
                                                              primary_server,
                                                              primary_server,
                                                              *result.local_endpoint,
                                                              local_query,
                                                              300,
                                                              options.timeout,
                                                              generator);
            if (!base.path_ok || !base.public_query.has_value()) {
                result.filtering_behavior = FilteringBehavior::None;
            } else {
                const bool primary_ok = run_filter_probe(raw_fd,
                                                         *result.local_endpoint,
                                                         primary_server,
                                                         "P",
                                                         base.token,
                                                         4100,
                                                         primary_server,
                                                         options.timeout);
                if (!primary_ok) {
                    result.filtering_behavior = FilteringBehavior::AddressAndPortDependent;
                } else {
                    const bool secondary_ok = run_filter_probe(raw_fd,
                                                               *result.local_endpoint,
                                                               primary_server,
                                                               "S",
                                                               base.token,
                                                               4100,
                                                               secondary_server,
                                                               options.timeout);
                    if (secondary_ok) {
                        result.filtering_behavior = FilteringBehavior::EndpointIndependent;
                    } else {
                        const bool primary_diff_query_ok = run_filter_probe(raw_fd,
                                                                            *result.local_endpoint,
                                                                            primary_server,
                                                                            "P",
                                                                            base.token,
                                                                            4200,
                                                                            primary_server,
                                                                            options.timeout);
                        result.filtering_behavior =
                            primary_diff_query_ok ? FilteringBehavior::AddressDependent
                                                  : FilteringBehavior::AddressAndPortDependent;
                    }
                }
            }
        }

        close(raw_fd);
        return result;
    } catch (...) {
        close(raw_fd);
        throw;
    }
}

} // namespace natcli
