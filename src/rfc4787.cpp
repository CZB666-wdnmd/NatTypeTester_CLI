#include "rfc4787.hpp"

#include "discovery.hpp"
#include "rfc5382.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstring>
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
        result.icmp_error_handling = ProbeStatus::Inconclusive;
        HairpinningResult hairpin = run_hairpinning_tests(options, stun_server, local_bind);
        result.udp_hairpinning = hairpin.udp;
        result.tcp_hairpinning = hairpin.tcp;
        result.icmp_hairpinning = hairpin.icmp;
    }

    if (run_all || test_type == Rfc4787TestType::Fragmentation) {
        constexpr std::size_t payload_size = 2000;
        result.outbound_fragmentation = run_udp_echo_probe(primary_server, local_bind, options.timeout, payload_size);
        result.inbound_fragmentation = run_udp_echo_probe(secondary_server, local_bind, options.timeout, payload_size);
    }

    return result;
}

} // namespace natcli
