#include "rfc7857.hpp"

#include "discovery.hpp"

namespace natcli {
namespace {

ProbeStatus classify_eim_independence(const std::optional<IpEndpoint>& udp_public,
                                      const std::optional<IpEndpoint>& tcp_public) {
    if (!udp_public.has_value() || !tcp_public.has_value()) {
        return ProbeStatus::Inconclusive;
    }
    return *udp_public == *tcp_public ? ProbeStatus::Pass : ProbeStatus::Fail;
}

ProbeStatus classify_eif_independence(FilteringBehavior udp_filtering, FilteringBehavior tcp_filtering) {
    if (udp_filtering == FilteringBehavior::Unknown || tcp_filtering == FilteringBehavior::Unknown) {
        return ProbeStatus::Inconclusive;
    }
    if (udp_filtering == FilteringBehavior::EndpointIndependent &&
        tcp_filtering == FilteringBehavior::EndpointIndependent) {
        return ProbeStatus::Pass;
    }
    return ProbeStatus::Fail;
}

ProbeStatus classify_port_parity(const std::optional<IpEndpoint>& local,
                                 const std::optional<IpEndpoint>& udp_public,
                                 const std::optional<IpEndpoint>& tcp_public) {
    if (!local.has_value() || !udp_public.has_value() || !tcp_public.has_value()) {
        return ProbeStatus::Inconclusive;
    }
    const bool local_parity = (local->port % 2) == 0;
    const bool udp_parity = (udp_public->port % 2) == 0;
    const bool tcp_parity = (tcp_public->port % 2) == 0;
    return (local_parity == udp_parity && local_parity == tcp_parity) ? ProbeStatus::Pass : ProbeStatus::Fail;
}

} // namespace

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
    result.eim_protocol_independence = classify_eim_independence(result.udp_public_endpoint, result.tcp_public_endpoint);
    result.eif_protocol_independence = classify_eif_independence(result.udp_filtering_behavior, result.tcp_filtering_behavior);
    result.port_parity_preservation =
        classify_port_parity(result.local_endpoint, result.udp_public_endpoint, result.tcp_public_endpoint);

    return result;
}

} // namespace natcli
