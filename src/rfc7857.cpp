#include "rfc7857.hpp"

#include "discovery.hpp"

namespace natcli {
namespace {

ProbeStatus classify_port_parity(const std::optional<IpEndpoint>& local,
                                 const std::optional<IpEndpoint>& udp_public,
                                 const std::optional<IpEndpoint>& tcp_public) {
    if (!udp_public.has_value() || !tcp_public.has_value()) {
        return ProbeStatus::Inconclusive;
    }
    if (!local.has_value()) {
        return ProbeStatus::Inconclusive;
    }
    const bool local_parity = (local->port % 2) == 0;
    const bool udp_parity = (udp_public->port % 2) == 0;
    const bool tcp_parity = (tcp_public->port % 2) == 0;
    return (local_parity == udp_parity && local_parity == tcp_parity) ? ProbeStatus::Pass : ProbeStatus::Fail;
}

} // namespace

ProbeStatus classify_rfc7857_eim_protocol_independence(const std::optional<IpEndpoint>& udp_public,
                                                       const std::optional<IpEndpoint>& tcp_public) {
    if (!udp_public.has_value() || !tcp_public.has_value()) {
        return ProbeStatus::Inconclusive;
    }
    // Per project requirement: cross-protocol endpoint reuse means protocol-independence is not preserved.
    return *udp_public == *tcp_public ? ProbeStatus::Fail : ProbeStatus::Pass;
}

ProbeStatus classify_rfc7857_eif_protocol_independence(const std::optional<bool>& tcp_mapping_allows_udp,
                                                       const std::optional<bool>& udp_mapping_allows_tcp) {
    if (!tcp_mapping_allows_udp.has_value() || !udp_mapping_allows_tcp.has_value()) {
        return ProbeStatus::Inconclusive;
    }
    if (*tcp_mapping_allows_udp || *udp_mapping_allows_tcp) {
        return ProbeStatus::Fail;
    }
    return ProbeStatus::Pass;
}

Rfc7857Result run_rfc7857_tests(const RequestOptions& options,
                                const IpEndpoint& stun_server,
                                const IpEndpoint& primary_server,
                                const IpEndpoint& secondary_server,
                                const std::optional<IpEndpoint>& local_bind) {
    RequestOptions udp_options = options;
    udp_options.transport = TransportType::Udp;

    StunResult5389 udp_mapping = run_rfc5780_test(udp_options, StunTestType::Mapping, stun_server, local_bind);
    StunResult5389 udp_filtering = run_rfc5780_test(udp_options, StunTestType::Filtering, stun_server, local_bind);
    Rfc5382TcpResult tcp_result = run_rfc5382_tests(options, primary_server, secondary_server, local_bind);

    Rfc7857Result result;
    result.udp_mapping_behavior = udp_mapping.mapping_behavior;
    result.udp_filtering_behavior = udp_filtering.filtering_behavior;
    result.tcp_filtering_behavior = tcp_result.filtering_behavior;
    result.local_endpoint = tcp_result.local_endpoint.has_value() ? tcp_result.local_endpoint : udp_mapping.local_endpoint;
    result.udp_public_endpoint = udp_mapping.public_endpoint;
    result.tcp_public_endpoint = tcp_result.tcp_public_endpoint;
    result.eim_protocol_independence =
        classify_rfc7857_eim_protocol_independence(result.udp_public_endpoint, result.tcp_public_endpoint);
    result.eif_protocol_independence = classify_rfc7857_eif_protocol_independence(
        tcp_result.tcp_mapping_allows_udp, tcp_result.udp_mapping_allows_tcp);
    result.port_parity_preservation =
        classify_port_parity(result.local_endpoint, result.udp_public_endpoint, result.tcp_public_endpoint);

    return result;
}

} // namespace natcli
