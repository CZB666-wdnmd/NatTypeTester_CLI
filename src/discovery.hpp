#pragma once

#include "stun.hpp"

#include <optional>

namespace natcli {

class Stun3489NatTypeDiscovery {
public:
    explicit Stun3489NatTypeDiscovery(IpEndpoint server);

    StunDiscoveryAction create_query();
    std::optional<StunDiscoveryAction> got_response(const std::optional<StunResponse>& response);

    ClassicStunResult result;

private:
    enum class Phase {
        Test1,
        Test2,
        Test1_2,
        Test3,
        Done,
    };

    std::optional<StunDiscoveryAction> handle_test1(const std::optional<StunResponse>& response);
    std::optional<StunDiscoveryAction> handle_test2(const std::optional<StunResponse>& response);
    std::optional<StunDiscoveryAction> handle_test1_2(const std::optional<StunResponse>& response);
    std::optional<StunDiscoveryAction> handle_test3(const std::optional<StunResponse>& response);
    static StunDiscoveryAction create_classic_binding_request(const IpEndpoint& send_to);

    IpEndpoint server_;
    Phase phase_{Phase::Done};
    std::optional<IpEndpoint> changed_address_;
    std::optional<IpEndpoint> mapped_address1_;
    std::optional<IpEndpoint> test1_remote_;
};

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

ClassicStunResult run_rfc3489_test(const RequestOptions& options,
                                   const IpEndpoint& server,
                                   const std::optional<IpEndpoint>& local_bind);
StunResult5389 run_rfc5780_test(const RequestOptions& options,
                                StunTestType test_type,
                                const IpEndpoint& server,
                                const std::optional<IpEndpoint>& local_bind);

} // namespace natcli
