#include "rfc5780_test.h"
#include "../utils/stun_utils.h"
#include "../utils/net_utils.h"

#include <sys/socket.h>

#include <chrono>
#include <iostream>
#include <optional>
#include <stdexcept>

namespace natcli {
namespace {

std::string require_option(const std::map<std::string, std::string>& options, const std::string& name) {
    auto it = options.find(name);
    if (it == options.end()) {
        throw std::runtime_error("Missing required option: " + name);
    }
    return it->second;
}

std::optional<std::string> find_option(const std::map<std::string, std::string>& options, const std::string& name) {
    auto it = options.find(name);
    if (it == options.end()) {
        return std::nullopt;
    }
    return it->second;
}

TransportType parse_transport(const std::map<std::string, std::string>& options) {
    std::string value = find_option(options, "--transport").value_or("udp");
    if (value == "udp") {
        return TransportType::Udp;
    }
    if (value == "tcp") {
        return TransportType::Tcp;
    }
    if (value == "tls") {
        return TransportType::Tls;
    }
    throw std::runtime_error("Unsupported transport: " + value);
}

bool parse_bool_option(const std::map<std::string, std::string>& options, const std::string& name, bool default_value = false) {
    std::optional<std::string> value = find_option(options, name);
    if (!value.has_value()) {
        return default_value;
    }
    if (*value == "1" || *value == "true") {
        return true;
    }
    if (*value == "0" || *value == "false") {
        return false;
    }
    throw std::runtime_error("Unsupported boolean option value for " + name + ": " + *value);
}

StunTestType parse_stun_test_type(const std::map<std::string, std::string>& options) {
    std::string value = find_option(options, "--test-type").value_or("combining");
    if (value == "combining") {
        return StunTestType::Combining;
    }
    if (value == "binding") {
        return StunTestType::Binding;
    }
    if (value == "mapping") {
        return StunTestType::Mapping;
    }
    if (value == "filtering") {
        return StunTestType::Filtering;
    }
    throw std::runtime_error("Unsupported test type: " + value);
}

std::optional<IpEndpoint> parse_local_bind(const std::map<std::string, std::string>& options, int family, int socket_type) {
    std::optional<std::string> local = find_option(options, "--local");
    if (!local.has_value()) {
        return std::nullopt;
    }
    auto [host, port] = split_host_port(*local, 0);
    return resolve_endpoint(host, port, socket_type, family);
}

void print_row(const std::string& key, const std::string& value) {
    std::cout << key << ": " << value << '\n';
}

std::string endpoint_or_dash(const std::optional<IpEndpoint>& endpoint) {
    return endpoint.has_value() ? to_string(*endpoint) : "-";
}

} // namespace

// ====================================================================
// Stun5389NatBehaviorDiscovery — RFC 5780 NAT behavior discovery protocol
// ====================================================================

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

// ====================================================================
// run_rfc5780_test — orchestrates the RFC 5780 protocol
// ====================================================================

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
    case StunTestType::TcpFiltering:
    case StunTestType::ProtocolCorrelation:
        throw std::runtime_error("Selected test type requires the custom RFC 5382/7857 server mode.");
    case StunTestType::Combining:
    default:
        if (options.transport != TransportType::Udp) {
            action = discovery.create_mapping_behavior_test();
        } else {
            action = discovery.create_query();
        }
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

// ====================================================================
// Rfc5780Test — CLI test wrapper
// ====================================================================

void Rfc5780Test::parseArgs(const std::map<std::string, std::string>& options) {
    constexpr std::uint16_t default_port = 3478;
    auto [host, port] = split_host_port(require_option(options, "--stun_server"), default_port);
    stun_host_ = host;
    stun_server_ = resolve_endpoint(host, port, SOCK_DGRAM);
    options_.server_name = stun_host_;
    options_.transport = parse_transport(options);
    options_.skip_certificate_validation = parse_bool_option(options, "--skip-cert", false);

    if (std::optional<std::string> timeout = find_option(options, "--timeout-ms"); timeout.has_value()) {
        options_.timeout = std::chrono::milliseconds(std::stoi(*timeout));
    }

    test_type_ = parse_stun_test_type(options);
    local_bind_ = parse_local_bind(options, stun_server_.family,
                                   options_.transport == TransportType::Udp ? SOCK_DGRAM : SOCK_STREAM);
}

int Rfc5780Test::runTest() {
    StunResult5389 result = run_rfc5780_test(options_, test_type_, stun_server_, local_bind_);

    if (test_type_ == StunTestType::Combining || test_type_ == StunTestType::Binding) {
        print_row("BindingTest", to_string(result.binding_test_result));
    }
    if (test_type_ == StunTestType::Combining || test_type_ == StunTestType::Mapping) {
        print_row("MappingBehavior", to_string(result.mapping_behavior));
    }
    if (test_type_ == StunTestType::Filtering ||
        (test_type_ == StunTestType::Combining && options_.transport == TransportType::Udp)) {
        print_row("FilteringBehavior", to_string(result.filtering_behavior));
    }
    print_row("PublicEnd", endpoint_or_dash(result.public_endpoint));
    print_row("LocalEnd", endpoint_or_dash(result.local_endpoint));
    print_row("OtherEnd", endpoint_or_dash(result.other_endpoint));
    return 0;
}

void Rfc5780Test::printHelp() const {
    std::cout << "  nat_type_tester_cli rfc5780 --stun_server host[:port] [--local host[:port]] [--transport udp|tcp|tls]\n"
              << "                               [--test-type combining|binding|mapping|filtering] [--skip-cert 0|1] [--timeout-ms 3000]\n";
}

} // namespace natcli
