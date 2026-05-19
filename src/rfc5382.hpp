#pragma once

#include "stun.hpp"

#include <optional>

namespace natcli {

struct Rfc5382TcpResult {
    FilteringBehavior filtering_behavior{FilteringBehavior::Unknown};
    std::optional<IpEndpoint> tcp_public_endpoint;
    std::optional<IpEndpoint> udp_public_endpoint;
    std::optional<bool> tcp_mapping_allows_udp;
    std::optional<bool> udp_mapping_allows_tcp;
    std::optional<IpEndpoint> local_endpoint;
    ProbeStatus simultaneous_open{ProbeStatus::Unknown};
    ProbeStatus unexpected_syn{ProbeStatus::Unknown};
    ProbeStatus icmp_error_handling{ProbeStatus::Inconclusive};
    ProbeStatus udp_hairpinning{ProbeStatus::Unknown};
    ProbeStatus tcp_hairpinning{ProbeStatus::Unknown};
    ProbeStatus icmp_hairpinning{ProbeStatus::Unknown};
    bool primary_probe_success{false};
    bool secondary_probe_success{false};
};

ProbeStatus run_udp_hairpinning_test(const RequestOptions& options,
                                     const IpEndpoint& stun_server,
                                     const std::optional<IpEndpoint>& local_bind);
ProbeStatus run_tcp_hairpinning_test(const RequestOptions& options,
                                     const IpEndpoint& stun_server,
                                     const std::optional<IpEndpoint>& local_bind);
ProbeStatus run_udp_icmp_error_handling_test(const RequestOptions& options,
                                             const IpEndpoint& stun_server,
                                             const std::optional<IpEndpoint>& local_bind);
ProbeStatus run_tcp_icmp_error_handling_test(const RequestOptions& options,
                                             const IpEndpoint& stun_server,
                                             const IpEndpoint& primary_server,
                                             const std::optional<IpEndpoint>& local_bind);
ProbeStatus run_rfc7857_icmp_hairpinning_test(const RequestOptions& options,
                                              const IpEndpoint& stun_server,
                                              const IpEndpoint& primary_server,
                                              const std::optional<IpEndpoint>& local_bind);

Rfc5382TcpResult run_rfc5382_tests(const RequestOptions& options,
                                   const IpEndpoint& stun_server,
                                   const IpEndpoint& primary_server,
                                   const IpEndpoint& secondary_server,
                                   const std::optional<IpEndpoint>& local_bind);

} // namespace natcli
