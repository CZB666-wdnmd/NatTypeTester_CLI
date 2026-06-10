#pragma once

#include "nat_test_base.h"
#include "../utils/stun.hpp"

#include <optional>

namespace natcli {

// Stun5389NatBehaviorDiscovery — RFC 5780 NAT behavior discovery protocol
class Stun5389NatBehaviorDiscovery {
public:
    explicit Stun5389NatBehaviorDiscovery(IpEndpoint server);

    StunDiscoveryAction create_query();
    StunDiscoveryAction create_binding_test();
    StunDiscoveryAction create_mapping_behavior_test();
    StunDiscoveryAction create_filtering_behavior_test();
    std::optional<StunDiscoveryAction> got_response(const std::optional<StunResponse>& response);

    StunResult5389 result;

private:
    enum class Scope {
        BindingOnly,
        Mapping,
        Filtering,
        Full,
    };

    enum class Phase {
        BindingTest,
        FilteringTest2,
        FilteringTest3,
        MappingTest2,
        MappingTest3,
        Done,
    };

    std::optional<StunDiscoveryAction> handle_binding_test(const std::optional<StunResponse>& response);
    StunDiscoveryAction transition_to_filtering_test2();
    std::optional<StunDiscoveryAction> handle_filtering_test2(const std::optional<StunResponse>& response);
    std::optional<StunDiscoveryAction> handle_filtering_test3(const std::optional<StunResponse>& response);
    std::optional<StunDiscoveryAction> transition_after_filtering();
    std::optional<StunDiscoveryAction> transition_to_mapping_or_done();
    std::optional<StunDiscoveryAction> handle_mapping_test2(const std::optional<StunResponse>& response);
    std::optional<StunDiscoveryAction> handle_mapping_test3(const std::optional<StunResponse>& response);
    static StunDiscoveryAction create_binding_request(const IpEndpoint& send_to);
    bool has_valid_other_address(const std::optional<IpEndpoint>& other) const;

    IpEndpoint server_;
    Scope scope_{Scope::Full};
    Phase phase_{Phase::Done};
    std::optional<IpEndpoint> mapping_test2_public_endpoint_;
};

class Rfc5780Test : public INatTest {
public:
    std::string_view commandName() const override { return "rfc5780"; }

    void parseArgs(const std::map<std::string, std::string>& options) override;
    int runTest() override;
    void printHelp() const override;

private:
    RequestOptions options_;
    std::string stun_host_;
    IpEndpoint stun_server_{};
    StunTestType test_type_{StunTestType::Combining};
    std::optional<IpEndpoint> local_bind_;
};

} // namespace natcli
