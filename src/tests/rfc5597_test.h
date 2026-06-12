#pragma once

#include "nat_test_base.h"
#include "../utils/stun.hpp"

#include <optional>

namespace natcli {

/// RFC 5597 DCCP NAT traversal test type selector.
enum class Rfc5597TestType {
    All,
    ServiceCode,       // REQ-11/12/13: Service Code & Checksum integrity
    Mapping,           // EIM / ADM
    Filtering,         // EIF / ADF
    SimultaneousOpen,  // DCCP simultaneous open
    UnexpectedSync,    // Unexpected DCCP-Sync (Type 8)
    PortOverloading,   // Port overloading defect test
    Hairpinning,       // DCCP hairpinning
    Icmp,              // ICMP error forwarding & mapping persistence
};

/// Results for REQ-11/12/13: Service Code, CsCov, Checksum tests.
struct DccpIntegrityResult {
    ProbeStatus reachable{ProbeStatus::Unknown};      // REQ-13: Service Code preserved
    ProbeStatus cscov_preserved{ProbeStatus::Unknown}; // REQ-12: CsCov preserved
    ProbeStatus checksum_valid{ProbeStatus::Unknown};  // REQ-11: Checksum valid
    std::optional<IpEndpoint> mapped_endpoint;
    std::uint8_t returned_cscov{0};
    bool returned_valid_csum{false};
};

/// Results for Mapping / Filtering tests.
struct DccpMappingFilteringResult {
    MappingBehavior mapping_behavior{MappingBehavior::Unknown};
    FilteringBehavior filtering_behavior{FilteringBehavior::Unknown};
    std::optional<IpEndpoint> primary_mapped;
    std::optional<IpEndpoint> secondary_mapped;
};

/// Results for Simultaneous Open test.
struct DccpSimOpenResult {
    ProbeStatus received{ProbeStatus::Unknown};
};

/// Results for Unexpected Sync test.
struct DccpUnexpectedSyncResult {
    ProbeStatus blocked{ProbeStatus::Unknown};  // Pass = dropped/blocked (safe), Fail = forwarded
};

/// Results for Port Overloading test.
struct DccpPortOverloadingResult {
    ProbeStatus overloaded{ProbeStatus::Unknown}; // Pass = no overloading, Fail = same mapped port
    std::optional<IpEndpoint> mapped_x;
    std::optional<IpEndpoint> mapped_y;
};

/// Results for Hairpinning test.
struct DccpHairpinningResult {
    ProbeStatus hairpinning{ProbeStatus::Unknown};
};

/// Results for ICMP error test.
struct DccpIcmpResult {
    ProbeStatus icmp_forwarded{ProbeStatus::Unknown};
    ProbeStatus mapping_survives{ProbeStatus::Unknown};
};

/// Aggregate RFC 5597 DCCP test result.
struct Rfc5597Result {
    DccpIntegrityResult integrity;
    DccpMappingFilteringResult map_filter;
    DccpSimOpenResult sim_open;
    DccpUnexpectedSyncResult unexpected_sync;
    DccpPortOverloadingResult port_overloading;
    DccpHairpinningResult hairpinning;
    DccpIcmpResult icmp;
};

class Rfc5597Test : public INatTest {
public:
    std::string_view commandName() const override { return "rfc5597"; }

    void parseArgs(const std::map<std::string, std::string>& options) override;
    int runTest() override;
    void printHelp() const override;

private:
    RequestOptions options_;
    IpEndpoint stun_server_{};
    IpEndpoint primary_server_{};
    IpEndpoint secondary_server_{};
    Rfc5597TestType test_type_{Rfc5597TestType::All};
    std::optional<IpEndpoint> local_bind_;
};

} // namespace natcli
