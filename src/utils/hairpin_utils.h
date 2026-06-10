#pragma once

#include "stun.hpp"

#include <optional>

namespace natcli {

// ---- Shared hairpinning result types (used by RFC 4787, 5382, 7857) ----

struct UdpHairpinningResult {
    ProbeStatus connectivity{ProbeStatus::Unknown};
    ProbeStatus source_address_match{ProbeStatus::Unknown};
};

struct TcpHairpinningResult {
    ProbeStatus connectivity{ProbeStatus::Unknown};
    ProbeStatus source_address_match{ProbeStatus::Unknown};
};

// ---- RFC 5382 TCP result type (used by RFC 7857 for section 7) ----

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
    ProbeStatus tcp_hairpinning_source_address{ProbeStatus::Unknown};
    ProbeStatus icmp_hairpinning{ProbeStatus::Unknown};
    bool primary_probe_success{false};
    bool secondary_probe_success{false};
};

// ---- Shared hairpinning and ICMP test functions ----

ProbeStatus run_udp_hairpinning_test(const RequestOptions& options,
                                     const IpEndpoint& stun_server,
                                     const std::optional<IpEndpoint>& local_bind);
UdpHairpinningResult run_udp_hairpinning_checks(const RequestOptions& options,
                                                const IpEndpoint& stun_server,
                                                const std::optional<IpEndpoint>& local_bind);
ProbeStatus run_tcp_hairpinning_test(const RequestOptions& options,
                                     const IpEndpoint& stun_server,
                                     const std::optional<IpEndpoint>& local_bind);
TcpHairpinningResult run_tcp_hairpinning_checks(const RequestOptions& options,
                                                const IpEndpoint& stun_server,
                                                const std::optional<IpEndpoint>& local_bind);
ProbeStatus run_udp_icmp_error_handling_test(const RequestOptions& options,
                                             const IpEndpoint& primary_server,
                                             const std::optional<IpEndpoint>& local_bind);
ProbeStatus run_tcp_icmp_error_handling_test(const RequestOptions& options,
                                             const IpEndpoint& primary_server,
                                             const std::optional<IpEndpoint>& local_bind);
ProbeStatus run_rfc7857_cross_protocol_icmp_error_test(const RequestOptions& options,
                                              const IpEndpoint& stun_server,
                                              const IpEndpoint& primary_server,
                                              const std::optional<IpEndpoint>& local_bind);

Rfc5382TcpResult run_rfc5382_tests(const RequestOptions& options,
                                   const IpEndpoint& stun_server,
                                   const IpEndpoint& primary_server,
                                   const IpEndpoint& secondary_server,
                                   const std::optional<IpEndpoint>& local_bind);

} // namespace natcli
