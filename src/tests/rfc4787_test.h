#pragma once

#include "nat_test_base.h"
#include "../utils/stun.hpp"

#include <optional>

namespace natcli {

enum class Rfc4787TestType {
    All,
    Mapping,
    Filtering,
    PortAllocation,
    Icmp,
    Fragmentation,
    Determinism,
    PortOverloading,
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
    ProbeStatus udp_hairpinning_source_address{ProbeStatus::Unknown};
    ProbeStatus tcp_hairpinning{ProbeStatus::Unknown};
    ProbeStatus icmp_hairpinning{ProbeStatus::Unknown};
    ProbeStatus outbound_fragmentation{ProbeStatus::Unknown};
    ProbeStatus outbound_df_fragmentation_error{ProbeStatus::Unknown};
    ProbeStatus inbound_fragmentation{ProbeStatus::Unknown};
    ProbeStatus out_of_order_fragmentation{ProbeStatus::Unknown};
};

// Determinism check result (multi-round consistency test)
struct DeterminismCheckResult {
    ProbeStatus mapping_consistent{ProbeStatus::Unknown};
    ProbeStatus filtering_consistent{ProbeStatus::Unknown};
    ProbeStatus port_range_consistent{ProbeStatus::Unknown};
    ProbeStatus port_parity_consistent{ProbeStatus::Unknown};
    int rounds{3};
};

Rfc4787Result run_rfc4787_tests(const RequestOptions& options,
                                Rfc4787TestType test_type,
                                const IpEndpoint& stun_server,
                                const IpEndpoint& primary_server,
                                const IpEndpoint& secondary_server,
                                const std::optional<IpEndpoint>& local_bind);

DeterminismCheckResult run_determinism_check(const RequestOptions& options,
                                             const IpEndpoint& server,
                                             const std::optional<IpEndpoint>& local_bind,
                                             int rounds = 3);

ProbeStatus run_port_overloading_test(const RequestOptions& options,
                                      const IpEndpoint& stun_server,
                                      const IpEndpoint& primary_server,
                                      const IpEndpoint& secondary_server,
                                      const std::optional<IpEndpoint>& local_bind);

class Rfc4787Test : public INatTest {
public:
    std::string_view commandName() const override { return "rfc4787"; }

    void parseArgs(const std::map<std::string, std::string>& options) override;
    int runTest() override;
    void printHelp() const override;

private:
    RequestOptions options_;
    IpEndpoint stun_server_{};
    IpEndpoint primary_server_{};
    IpEndpoint secondary_server_{};
    Rfc4787TestType test_type_{Rfc4787TestType::All};
    std::optional<IpEndpoint> local_bind_;
};

} // namespace natcli
