#include "discovery.hpp"

#include <stdexcept>

namespace natcli {

namespace {
constexpr std::uint32_t kClassicStunMagicCookie = 0x00000000u;
}

Stun3489NatTypeDiscovery::Stun3489NatTypeDiscovery(IpEndpoint server) : server_(std::move(server)) {}

StunDiscoveryAction Stun3489NatTypeDiscovery::create_query() {
    phase_ = Phase::Test1;
    return create_classic_binding_request(server_);
}

std::optional<StunDiscoveryAction> Stun3489NatTypeDiscovery::got_response(const std::optional<StunResponse>& response) {
    switch (phase_) {
    case Phase::Test1:
        return handle_test1(response);
    case Phase::Test2:
        return handle_test2(response);
    case Phase::Test1_2:
        return handle_test1_2(response);
    case Phase::Test3:
        return handle_test3(response);
    case Phase::Done:
    default:
        return std::nullopt;
    }
}

std::optional<StunDiscoveryAction> Stun3489NatTypeDiscovery::handle_test1(const std::optional<StunResponse>& response) {
    if (!response.has_value()) {
        result.nat_type = NatType::UdpBlocked;
        phase_ = Phase::Done;
        return std::nullopt;
    }

    result.local_endpoint = response->local;
    test1_remote_ = response->remote;
    mapped_address1_ = get_mapped_address_attribute(response->message);
    changed_address_ = get_changed_address_attribute(response->message);
    result.public_endpoint = mapped_address1_;

    if (!mapped_address1_.has_value() || !changed_address_.has_value() ||
        same_address(*changed_address_, response->remote) || changed_address_->port == response->remote.port) {
        result.nat_type = NatType::UnsupportedServer;
        phase_ = Phase::Done;
        return std::nullopt;
    }

    phase_ = Phase::Test2;
    return StunDiscoveryAction{natcli::create_binding_request(kClassicStunMagicCookie, true, true), server_};
}

std::optional<StunDiscoveryAction> Stun3489NatTypeDiscovery::handle_test2(const std::optional<StunResponse>& response) {
    if (!test1_remote_.has_value() || !changed_address_.has_value()) {
        throw std::runtime_error("Invalid RFC3489 discovery state");
    }

    std::optional<IpEndpoint> mapped_address2 = response.has_value() ? get_mapped_address_attribute(response->message) : std::nullopt;

    if (response.has_value()) {
        if (same_address(*test1_remote_, response->remote) || test1_remote_->port == response->remote.port) {
            result.nat_type = NatType::UnsupportedServer;
            result.public_endpoint = mapped_address2;
            phase_ = Phase::Done;
            return std::nullopt;
        }
    }

    if (mapped_address1_.has_value() && result.local_endpoint.has_value() && *mapped_address1_ == *result.local_endpoint) {
        if (!response.has_value()) {
            result.nat_type = NatType::SymmetricUdpFirewall;
            result.public_endpoint = mapped_address1_;
        } else {
            result.nat_type = NatType::OpenInternet;
            result.public_endpoint = mapped_address2;
        }
        phase_ = Phase::Done;
        return std::nullopt;
    }

    if (response.has_value()) {
        result.nat_type = NatType::FullCone;
        result.public_endpoint = mapped_address2;
        phase_ = Phase::Done;
        return std::nullopt;
    }

    phase_ = Phase::Test1_2;
    return create_classic_binding_request(*changed_address_);
}

std::optional<StunDiscoveryAction> Stun3489NatTypeDiscovery::handle_test1_2(const std::optional<StunResponse>& response) {
    std::optional<IpEndpoint> mapped_address12 = response.has_value() ? get_mapped_address_attribute(response->message) : std::nullopt;

    if (!mapped_address12.has_value()) {
        result.nat_type = NatType::Unknown;
        phase_ = Phase::Done;
        return std::nullopt;
    }

    if (!mapped_address1_.has_value() || *mapped_address12 != *mapped_address1_) {
        result.nat_type = NatType::Symmetric;
        result.public_endpoint = mapped_address12;
        phase_ = Phase::Done;
        return std::nullopt;
    }

    phase_ = Phase::Test3;
    return StunDiscoveryAction{natcli::create_binding_request(kClassicStunMagicCookie, false, true), server_};
}

std::optional<StunDiscoveryAction> Stun3489NatTypeDiscovery::handle_test3(const std::optional<StunResponse>& response) {
    if (response.has_value()) {
        std::optional<IpEndpoint> mapped_address3 = get_mapped_address_attribute(response->message);
        if (mapped_address3.has_value() && test1_remote_.has_value() && same_address(response->remote, *test1_remote_) &&
            response->remote.port != test1_remote_->port) {
            result.nat_type = NatType::RestrictedCone;
            result.public_endpoint = mapped_address3;
            phase_ = Phase::Done;
            return std::nullopt;
        }
    }

    result.nat_type = NatType::PortRestrictedCone;
    result.public_endpoint = mapped_address1_;
    phase_ = Phase::Done;
    return std::nullopt;
}

StunDiscoveryAction Stun3489NatTypeDiscovery::create_classic_binding_request(const IpEndpoint& send_to) {
    return StunDiscoveryAction{create_binding_request(kClassicStunMagicCookie), send_to};
}

Stun5389NatBehaviorDiscovery::Stun5389NatBehaviorDiscovery(IpEndpoint server) : server_(std::move(server)) {}

StunDiscoveryAction Stun5389NatBehaviorDiscovery::create_query() {
    scope_ = Scope::Full;
    phase_ = Phase::BindingTest;
    return create_binding_request(server_);
}

StunDiscoveryAction Stun5389NatBehaviorDiscovery::create_binding_test() {
    scope_ = Scope::BindingOnly;
    phase_ = Phase::BindingTest;
    return create_binding_request(server_);
}

StunDiscoveryAction Stun5389NatBehaviorDiscovery::create_mapping_behavior_test() {
    scope_ = Scope::Mapping;
    phase_ = Phase::BindingTest;
    return create_binding_request(server_);
}

StunDiscoveryAction Stun5389NatBehaviorDiscovery::create_filtering_behavior_test() {
    scope_ = Scope::Filtering;
    phase_ = Phase::BindingTest;
    return create_binding_request(server_);
}

std::optional<StunDiscoveryAction> Stun5389NatBehaviorDiscovery::got_response(const std::optional<StunResponse>& response) {
    switch (phase_) {
    case Phase::BindingTest:
        return handle_binding_test(response);
    case Phase::FilteringTest2:
        return handle_filtering_test2(response);
    case Phase::FilteringTest3:
        return handle_filtering_test3(response);
    case Phase::MappingTest2:
        return handle_mapping_test2(response);
    case Phase::MappingTest3:
        return handle_mapping_test3(response);
    case Phase::Done:
    default:
        return std::nullopt;
    }
}

std::optional<StunDiscoveryAction> Stun5389NatBehaviorDiscovery::handle_binding_test(const std::optional<StunResponse>& response) {
    std::optional<IpEndpoint> mapped_address = response.has_value() ? get_xor_mapped_address_attribute(response->message) : std::nullopt;
    std::optional<IpEndpoint> other_address = response.has_value() ? get_other_address_attribute(response->message) : std::nullopt;

    if (!response.has_value()) {
        result.binding_test_result = BindingTestResult::Fail;
    } else if (!mapped_address.has_value()) {
        result.binding_test_result = BindingTestResult::UnsupportedServer;
    } else {
        result.binding_test_result = BindingTestResult::Success;
    }

    result.local_endpoint = response.has_value() ? std::optional<IpEndpoint>{response->local} : std::nullopt;
    result.public_endpoint = mapped_address;
    result.other_endpoint = other_address;

    if (scope_ == Scope::BindingOnly || result.binding_test_result != BindingTestResult::Success) {
        phase_ = Phase::Done;
        return std::nullopt;
    }

    if (!has_valid_other_address(result.other_endpoint)) {
        if (scope_ == Scope::Filtering || scope_ == Scope::Full) {
            result.filtering_behavior = FilteringBehavior::UnsupportedServer;
        }
        if (scope_ == Scope::Mapping) {
            result.mapping_behavior = MappingBehavior::UnsupportedServer;
        }
        phase_ = Phase::Done;
        return std::nullopt;
    }

    if (scope_ == Scope::Filtering || scope_ == Scope::Full) {
        return transition_to_filtering_test2();
    }

    if (scope_ == Scope::Mapping) {
        return transition_to_mapping_or_done();
    }

    phase_ = Phase::Done;
    return std::nullopt;
}

StunDiscoveryAction Stun5389NatBehaviorDiscovery::transition_to_filtering_test2() {
    phase_ = Phase::FilteringTest2;
    return StunDiscoveryAction{natcli::create_binding_request(0x2112A442u, true, true), server_};
}

std::optional<StunDiscoveryAction> Stun5389NatBehaviorDiscovery::handle_filtering_test2(const std::optional<StunResponse>& response) {
    if (response.has_value()) {
        result.filtering_behavior = result.other_endpoint.has_value() && response->remote == *result.other_endpoint
                                        ? FilteringBehavior::EndpointIndependent
                                        : FilteringBehavior::UnsupportedServer;
        return transition_after_filtering();
    }

    phase_ = Phase::FilteringTest3;
    return StunDiscoveryAction{natcli::create_binding_request(0x2112A442u, false, true), server_};
}

std::optional<StunDiscoveryAction> Stun5389NatBehaviorDiscovery::handle_filtering_test3(const std::optional<StunResponse>& response) {
    if (!response.has_value()) {
        result.filtering_behavior = FilteringBehavior::AddressAndPortDependent;
    } else if (same_address(response->remote, server_) && response->remote.port != server_.port) {
        result.filtering_behavior = FilteringBehavior::AddressDependent;
    } else {
        result.filtering_behavior = FilteringBehavior::UnsupportedServer;
    }

    return transition_after_filtering();
}

std::optional<StunDiscoveryAction> Stun5389NatBehaviorDiscovery::transition_after_filtering() {
    if (scope_ == Scope::Full && result.filtering_behavior != FilteringBehavior::UnsupportedServer) {
        return transition_to_mapping_or_done();
    }

    phase_ = Phase::Done;
    return std::nullopt;
}

std::optional<StunDiscoveryAction> Stun5389NatBehaviorDiscovery::transition_to_mapping_or_done() {
    if (result.public_endpoint.has_value() && result.local_endpoint.has_value() && *result.public_endpoint == *result.local_endpoint) {
        result.mapping_behavior = MappingBehavior::Direct;
        phase_ = Phase::Done;
        return std::nullopt;
    }

    phase_ = Phase::MappingTest2;
    IpEndpoint target = *result.other_endpoint;
    target.port = server_.port;
    return create_binding_request(target);
}

std::optional<StunDiscoveryAction> Stun5389NatBehaviorDiscovery::handle_mapping_test2(const std::optional<StunResponse>& response) {
    std::optional<IpEndpoint> mapped_address = response.has_value() ? get_xor_mapped_address_attribute(response->message) : std::nullopt;

    if (!mapped_address.has_value()) {
        result.mapping_behavior = MappingBehavior::Fail;
        phase_ = Phase::Done;
        return std::nullopt;
    }

    if (result.public_endpoint.has_value() && *mapped_address == *result.public_endpoint) {
        result.mapping_behavior = MappingBehavior::EndpointIndependent;
        phase_ = Phase::Done;
        return std::nullopt;
    }

    mapping_test2_public_endpoint_ = mapped_address;
    phase_ = Phase::MappingTest3;
    return create_binding_request(*result.other_endpoint);
}

std::optional<StunDiscoveryAction> Stun5389NatBehaviorDiscovery::handle_mapping_test3(const std::optional<StunResponse>& response) {
    std::optional<IpEndpoint> mapped_address = response.has_value() ? get_xor_mapped_address_attribute(response->message) : std::nullopt;

    if (!mapped_address.has_value()) {
        result.mapping_behavior = MappingBehavior::Fail;
    } else {
        result.mapping_behavior = mapping_test2_public_endpoint_.has_value() && *mapped_address == *mapping_test2_public_endpoint_
                                      ? MappingBehavior::AddressDependent
                                      : MappingBehavior::AddressAndPortDependent;
    }

    phase_ = Phase::Done;
    return std::nullopt;
}

StunDiscoveryAction Stun5389NatBehaviorDiscovery::create_binding_request(const IpEndpoint& send_to) {
    return StunDiscoveryAction{natcli::create_binding_request(0x2112A442u), send_to};
}

bool Stun5389NatBehaviorDiscovery::has_valid_other_address(const std::optional<IpEndpoint>& other) const {
    return other.has_value() && !same_address(*other, server_) && other->port != server_.port;
}

ClassicStunResult run_rfc3489_test(const RequestOptions& options,
                                   const IpEndpoint& server,
                                   const std::optional<IpEndpoint>& local_bind) {
    if (options.transport != TransportType::Udp) {
        throw std::runtime_error("RFC3489 testing requires UDP transport.");
    }

    UdpSession session(server, local_bind, options.timeout);
    Stun3489NatTypeDiscovery discovery(server);
    std::optional<StunDiscoveryAction> action = discovery.create_query();
    while (action.has_value()) {
        action = discovery.got_response(session.request(*action));
    }
    return discovery.result;
}

StunResult5389 run_rfc5780_test(const RequestOptions& options,
                                StunTestType test_type,
                                const IpEndpoint& server,
                                const std::optional<IpEndpoint>& local_bind) {
    Stun5389NatBehaviorDiscovery discovery(server);
    std::optional<StunDiscoveryAction> action;

    switch (test_type) {
    case StunTestType::Binding:
        action = discovery.create_binding_test();
        break;
    case StunTestType::Mapping:
        action = discovery.create_mapping_behavior_test();
        break;
    case StunTestType::Filtering:
        if (options.transport != TransportType::Udp) {
            throw std::runtime_error("Filtering test applies only to UDP.");
        }
        action = discovery.create_filtering_behavior_test();
        break;
    case StunTestType::Combining:
    default:
        action = discovery.create_query();
        break;
    }

    if (options.transport == TransportType::Udp) {
        UdpSession session(server, local_bind, options.timeout);
        while (action.has_value()) {
            action = discovery.got_response(session.request(*action));
        }
    } else {
        TcpSession session(options.server_name, local_bind, options.timeout, options.transport == TransportType::Tls,
                           options.skip_certificate_validation);
        while (action.has_value()) {
            action = discovery.got_response(session.request(*action));
        }
        if (test_type == StunTestType::Combining) {
            discovery.result.filtering_behavior = FilteringBehavior::None;
        }
    }

    return discovery.result;
}

} // namespace natcli
