#pragma once

#include "stun.hpp"

#include <optional>

namespace natcli {

struct Rfc5382TcpResult {
    FilteringBehavior filtering_behavior{FilteringBehavior::Unknown};
    std::optional<IpEndpoint> tcp_public_endpoint;
    std::optional<IpEndpoint> udp_public_endpoint;
    std::optional<IpEndpoint> local_endpoint;
    ProbeStatus simultaneous_open{ProbeStatus::Unknown};
    ProbeStatus unexpected_syn{ProbeStatus::Unknown};
    ProbeStatus icmp_error_handling{ProbeStatus::Inconclusive};
    bool primary_probe_success{false};
    bool secondary_probe_success{false};
};

Rfc5382TcpResult run_rfc5382_tests(const RequestOptions& options,
                                   const IpEndpoint& primary_server,
                                   const IpEndpoint& secondary_server,
                                   const std::optional<IpEndpoint>& local_bind);

} // namespace natcli
