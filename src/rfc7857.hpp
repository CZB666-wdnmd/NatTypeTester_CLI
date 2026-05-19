#pragma once

#include "rfc5382.hpp"
#include "stun.hpp"

#include <optional>

namespace natcli {

struct Rfc7857Result {
    MappingBehavior udp_mapping_behavior{MappingBehavior::Unknown};
    FilteringBehavior udp_filtering_behavior{FilteringBehavior::Unknown};
    FilteringBehavior tcp_filtering_behavior{FilteringBehavior::Unknown};
    std::optional<IpEndpoint> local_endpoint;
    std::optional<IpEndpoint> udp_public_endpoint;
    std::optional<IpEndpoint> tcp_public_endpoint;
    ProbeStatus eim_protocol_independence{ProbeStatus::Unknown};
    ProbeStatus eif_protocol_independence{ProbeStatus::Unknown};
    ProbeStatus port_parity_preservation{ProbeStatus::Unknown};
};

ProbeStatus classify_rfc7857_eim_protocol_independence(const std::optional<IpEndpoint>& udp_public,
                                                       const std::optional<IpEndpoint>& tcp_public);
ProbeStatus classify_rfc7857_eif_protocol_independence(const std::optional<bool>& tcp_mapping_allows_udp,
                                                       const std::optional<bool>& udp_mapping_allows_tcp);

Rfc7857Result run_rfc7857_tests(const RequestOptions& options,
                                const IpEndpoint& stun_server,
                                const IpEndpoint& primary_server,
                                const IpEndpoint& secondary_server,
                                const std::optional<IpEndpoint>& local_bind);

} // namespace natcli
