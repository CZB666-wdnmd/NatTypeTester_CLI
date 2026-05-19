#pragma once

#include "stun.hpp"

#include <optional>

namespace natcli {

enum class Rfc4787TestType {
    All,
    Mapping,
    Filtering,
    PortAllocation,
    Icmp,
    Fragmentation,
};

struct Rfc4787Result {
    BindingTestResult binding_test_result{BindingTestResult::Unknown};
    MappingBehavior mapping_behavior{MappingBehavior::Unknown};
    FilteringBehavior filtering_behavior{FilteringBehavior::Unknown};
    std::optional<IpEndpoint> public_endpoint;
    std::optional<IpEndpoint> local_endpoint;
    ProbeStatus port_range_preservation{ProbeStatus::Unknown};
    ProbeStatus port_parity_preservation{ProbeStatus::Unknown};
    ProbeStatus icmp_error_handling{ProbeStatus::Unknown};
    ProbeStatus udp_hairpinning{ProbeStatus::Unknown};
    ProbeStatus tcp_hairpinning{ProbeStatus::Unknown};
    ProbeStatus icmp_hairpinning{ProbeStatus::Unknown};
    ProbeStatus outbound_fragmentation{ProbeStatus::Unknown};
    ProbeStatus inbound_fragmentation{ProbeStatus::Unknown};
};

Rfc4787Result run_rfc4787_tests(const RequestOptions& options,
                                Rfc4787TestType test_type,
                                const IpEndpoint& stun_server,
                                const IpEndpoint& primary_server,
                                const IpEndpoint& secondary_server,
                                const std::optional<IpEndpoint>& local_bind);

} // namespace natcli
