#include "rfc4787.hpp"

#include "discovery.hpp"
#include "rfc5382.hpp"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/errqueue.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

namespace natcli {
namespace {

struct SocketAddress {
    sockaddr_storage storage{};
    socklen_t length{};
};

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
    auto* address = reinterpret_cast<sockaddr_in6*>(&result.storage);
    address->sin6_family = AF_INET6;
    address->sin6_port = htons(endpoint.port);
    std::memcpy(&address->sin6_addr, endpoint.address.data(), 16);
    return result;
}

bool wait_for_readable(int socket_fd, std::chrono::milliseconds timeout) {
    pollfd descriptor{socket_fd, POLLIN, 0};
    int rc = poll(&descriptor, 1, static_cast<int>(timeout.count()));
    return rc > 0 && (descriptor.revents & POLLIN) != 0;
}

void set_reuse_options(int socket_fd) {
    int reuse = 1;
    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#ifdef SO_REUSEPORT
    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
#endif
}

ProbeStatus evaluate_port_range(const std::optional<IpEndpoint>& local, const std::optional<IpEndpoint>& mapped) {
    if (!local.has_value() || !mapped.has_value()) {
        return ProbeStatus::Inconclusive;
    }
    const bool local_well_known = local->port <= 1023;
    const bool mapped_well_known = mapped->port <= 1023;
    return local_well_known == mapped_well_known ? ProbeStatus::Pass : ProbeStatus::Fail;
}

ProbeStatus evaluate_port_parity(const std::optional<IpEndpoint>& local, const std::optional<IpEndpoint>& mapped) {
    if (!local.has_value() || !mapped.has_value()) {
        return ProbeStatus::Inconclusive;
    }
    return (local->port % 2) == (mapped->port % 2) ? ProbeStatus::Pass : ProbeStatus::Fail;
}

ProbeStatus run_udp_echo_probe(const IpEndpoint& target,
                               const std::optional<IpEndpoint>& local_bind,
                               std::chrono::milliseconds timeout,
                               std::size_t payload_size) {
    int socket_fd = socket(target.family, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd < 0) {
        return ProbeStatus::Inconclusive;
    }

    ProbeStatus result = ProbeStatus::Fail;
    try {
        if (local_bind.has_value()) {
            SocketAddress local = to_sockaddr(*local_bind);
            if (bind(socket_fd, reinterpret_cast<sockaddr*>(&local.storage), local.length) != 0) {
                close(socket_fd);
                return ProbeStatus::Inconclusive;
            }
        }

        SocketAddress remote = to_sockaddr(target);
        std::vector<std::uint8_t> payload(payload_size, 0x7A);
        ssize_t sent = sendto(socket_fd,
                              payload.data(),
                              payload.size(),
                              0,
                              reinterpret_cast<sockaddr*>(&remote.storage),
                              remote.length);
        if (sent != static_cast<ssize_t>(payload.size())) {
            close(socket_fd);
            return ProbeStatus::Fail;
        }

        if (!wait_for_readable(socket_fd, timeout)) {
            close(socket_fd);
            return ProbeStatus::Fail;
        }

        std::vector<std::uint8_t> received(payload_size + 64, 0);
        ssize_t received_size = recv(socket_fd, received.data(), received.size(), 0);
        if (received_size == static_cast<ssize_t>(payload.size()) &&
            std::equal(payload.begin(), payload.end(), received.begin())) {
            result = ProbeStatus::Pass;
        }
        close(socket_fd);
        return result;
    } catch (...) {
        close(socket_fd);
        return ProbeStatus::Inconclusive;
    }
}

std::optional<IpEndpoint> parse_endpoint_line(const std::string& line, int family) {
    std::istringstream stream(line);
    std::string host;
    std::uint16_t port = 0;
    if (!(stream >> host >> port)) {
        return std::nullopt;
    }
    return resolve_endpoint(host, port, SOCK_DGRAM, family);
}

std::optional<std::string> exchange_udp_server_command(int socket_fd,
                                                       const IpEndpoint& server,
                                                       std::string_view command,
                                                       std::chrono::milliseconds timeout) {
    SocketAddress remote = to_sockaddr(server);
    const ssize_t sent = sendto(socket_fd,
                                command.data(),
                                command.size(),
                                0,
                                reinterpret_cast<sockaddr*>(&remote.storage),
                                remote.length);
    if (sent != static_cast<ssize_t>(command.size())) {
        return std::nullopt;
    }
    if (!wait_for_readable(socket_fd, timeout)) {
        return std::nullopt;
    }
    std::array<char, 512> buffer{};
    ssize_t received = recv(socket_fd, buffer.data(), buffer.size() - 1, 0);
    if (received <= 0) {
        return std::nullopt;
    }
    buffer[static_cast<std::size_t>(received)] = '\0';
    return std::string(buffer.data());
}

ProbeStatus run_udp_df_fragmentation_probe(const IpEndpoint& target,
                                           const std::optional<IpEndpoint>& local_bind,
                                           std::chrono::milliseconds timeout) {
    if (target.family != AF_INET) {
        return ProbeStatus::Inconclusive;
    }
    int socket_fd = socket(target.family, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd < 0) {
        return ProbeStatus::Inconclusive;
    }
    try {
        set_reuse_options(socket_fd);
        int enable = 1;
        setsockopt(socket_fd, SOL_IP, IP_RECVERR, &enable, sizeof(enable));
        int pmtu_mode = IP_PMTUDISC_DO;
        setsockopt(socket_fd, SOL_IP, IP_MTU_DISCOVER, &pmtu_mode, sizeof(pmtu_mode));
        if (local_bind.has_value()) {
            SocketAddress local = to_sockaddr(*local_bind);
            if (bind(socket_fd, reinterpret_cast<sockaddr*>(&local.storage), local.length) != 0) {
                close(socket_fd);
                return ProbeStatus::Inconclusive;
            }
        }

        SocketAddress remote = to_sockaddr(target);
        if (connect(socket_fd, reinterpret_cast<sockaddr*>(&remote.storage), remote.length) != 0) {
            close(socket_fd);
            return ProbeStatus::Inconclusive;
        }

        std::vector<std::uint8_t> payload(2000, 0x5A);
        const ssize_t sent = send(socket_fd, payload.data(), payload.size(), 0);
        if (sent < 0 && errno == EMSGSIZE) {
            close(socket_fd);
            return ProbeStatus::Pass;
        }
        if (sent != static_cast<ssize_t>(payload.size())) {
            close(socket_fd);
            return ProbeStatus::Fail;
        }

        pollfd descriptor{socket_fd, POLLERR, 0};
        const int rc = poll(&descriptor, 1, static_cast<int>(timeout.count()));
        if (rc <= 0 || (descriptor.revents & POLLERR) == 0) {
            close(socket_fd);
            return ProbeStatus::Fail;
        }

        std::array<std::uint8_t, 256> data{};
        std::array<std::uint8_t, 512> control{};
        iovec io{data.data(), data.size()};
        msghdr msg{};
        msg.msg_iov = &io;
        msg.msg_iovlen = 1;
        msg.msg_control = control.data();
        msg.msg_controllen = control.size();
        if (recvmsg(socket_fd, &msg, MSG_ERRQUEUE) < 0) {
            close(socket_fd);
            return ProbeStatus::Fail;
        }

        for (cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
            if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVERR) {
                const auto* error = reinterpret_cast<const sock_extended_err*>(CMSG_DATA(cmsg));
                if (error != nullptr &&
                    error->ee_origin == SO_EE_ORIGIN_ICMP &&
                    error->ee_type == ICMP_DEST_UNREACH &&
                    error->ee_code == ICMP_FRAG_NEEDED) {
                    close(socket_fd);
                    return ProbeStatus::Pass;
                }
            }
        }

        close(socket_fd);
        return ProbeStatus::Fail;
    } catch (...) {
        close(socket_fd);
        return ProbeStatus::Inconclusive;
    }
}

ProbeStatus run_udp_out_of_order_fragment_probe(const IpEndpoint& primary_server,
                                                const std::optional<IpEndpoint>& local_bind,
                                                std::chrono::milliseconds timeout) {
    constexpr std::string_view kOutOfOrderFragmentPayload = "RFC4787-OOO-FRAGMENT\n";
    int socket_fd = socket(primary_server.family, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd < 0) {
        return ProbeStatus::Inconclusive;
    }
    try {
        set_reuse_options(socket_fd);
        IpEndpoint local = local_bind.value_or(wildcard_endpoint(primary_server.family));
        local.port = 0;
        SocketAddress local_address = to_sockaddr(local);
        if (bind(socket_fd, reinterpret_cast<sockaddr*>(&local_address.storage), local_address.length) != 0) {
            close(socket_fd);
            return ProbeStatus::Inconclusive;
        }

        std::optional<std::string> mapping_line = exchange_udp_server_command(socket_fd, primary_server, "M\n", timeout);
        if (!mapping_line.has_value()) {
            close(socket_fd);
            return ProbeStatus::Inconclusive;
        }
        if (!parse_endpoint_line(*mapping_line, primary_server.family).has_value()) {
            close(socket_fd);
            return ProbeStatus::Inconclusive;
        }

        SocketAddress remote = to_sockaddr(primary_server);
        const ssize_t sent = sendto(socket_fd, "O\n", 2, 0, reinterpret_cast<sockaddr*>(&remote.storage), remote.length);
        if (sent != 2) {
            close(socket_fd);
            return ProbeStatus::Fail;
        }

        const auto deadline = std::chrono::steady_clock::now() + timeout;
        bool send_acknowledged = false;
        bool fragmented_payload_received = false;
        while (std::chrono::steady_clock::now() < deadline && (!send_acknowledged || !fragmented_payload_received)) {
            const auto now = std::chrono::steady_clock::now();
            const auto remaining =
                std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
            if (!wait_for_readable(socket_fd, remaining)) {
                break;
            }
            std::array<char, 512> buffer{};
            ssize_t received = recv(socket_fd, buffer.data(), buffer.size(), 0);
            if (received <= 0) {
                continue;
            }
            std::string_view payload(buffer.data(), static_cast<std::size_t>(received));
            if (payload == "O=1\n") {
                send_acknowledged = true;
                continue;
            }
            if (payload == kOutOfOrderFragmentPayload) {
                fragmented_payload_received = true;
            }
        }

        close(socket_fd);
        return (send_acknowledged && fragmented_payload_received) ? ProbeStatus::Pass : ProbeStatus::Fail;
    } catch (...) {
        close(socket_fd);
        return ProbeStatus::Inconclusive;
    }
}

} // namespace

Rfc4787Result run_rfc4787_tests(const RequestOptions& options,
                                Rfc4787TestType test_type,
                                const IpEndpoint& stun_server,
                                const IpEndpoint& primary_server,
                                const IpEndpoint& secondary_server,
                                const std::optional<IpEndpoint>& local_bind) {
    RequestOptions udp_options = options;
    udp_options.transport = TransportType::Udp;

    Rfc4787Result result;
    const bool run_all = test_type == Rfc4787TestType::All;

    const bool need_binding = run_all || test_type == Rfc4787TestType::PortAllocation || test_type == Rfc4787TestType::Icmp;
    if (need_binding) {
        StunResult5389 binding = run_rfc5780_test(udp_options, StunTestType::Binding, stun_server, local_bind);
        result.binding_test_result = binding.binding_test_result;
        result.public_endpoint = binding.public_endpoint;
        result.local_endpoint = binding.local_endpoint;
    }

    if (run_all || test_type == Rfc4787TestType::Mapping) {
        result.mapping_behavior = run_rfc5780_test(udp_options, StunTestType::Mapping, stun_server, local_bind).mapping_behavior;
    }
    if (run_all || test_type == Rfc4787TestType::Filtering) {
        result.filtering_behavior = run_rfc5780_test(udp_options, StunTestType::Filtering, stun_server, local_bind).filtering_behavior;
    }

    if (run_all || test_type == Rfc4787TestType::PortAllocation) {
        result.port_range_preservation = evaluate_port_range(result.local_endpoint, result.public_endpoint);
        result.port_parity_preservation = evaluate_port_parity(result.local_endpoint, result.public_endpoint);
    }

    if (run_all || test_type == Rfc4787TestType::Icmp) {
        result.icmp_error_handling = run_udp_icmp_error_handling_test(options, primary_server, local_bind);
        UdpHairpinningResult hairpinning = run_udp_hairpinning_checks(options, stun_server, local_bind);
        result.udp_hairpinning = hairpinning.connectivity;
        result.udp_hairpinning_source_address = hairpinning.source_address_match;
    }

    if (run_all || test_type == Rfc4787TestType::Fragmentation) {
        constexpr std::size_t payload_size = 2000;
        result.outbound_fragmentation = run_udp_echo_probe(primary_server, local_bind, options.timeout, payload_size);
        result.outbound_df_fragmentation_error = run_udp_df_fragmentation_probe(primary_server, local_bind, options.timeout);
        result.inbound_fragmentation = run_udp_echo_probe(secondary_server, local_bind, options.timeout, payload_size);
        result.out_of_order_fragmentation =
            run_udp_out_of_order_fragment_probe(primary_server, local_bind, options.timeout);
    }

    return result;
}

} // namespace natcli
