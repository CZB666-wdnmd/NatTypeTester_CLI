#include "rfc3489_test.h"
#include "../utils/net_utils.h"

#include <sys/socket.h>

#include <chrono>
#include <iostream>
#include <optional>
#include <stdexcept>

namespace natcli {

namespace {

constexpr std::uint32_t kClassicStunMagicCookie = 0x00000000u;

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
// Stun3489NatTypeDiscovery — RFC 3489 NAT type discovery protocol
// ====================================================================

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
    // Fix 1.1: Separate Timeout (no response) from missing MAPPED-ADDRESS attribute
    if (!response.has_value()) {
        // Case A: Network timeout or target host unreachable
        result.nat_type = NatType::Unknown;
        phase_ = Phase::Done;
        return std::nullopt;
    }

    // Case B: Response arrived but missing MAPPED-ADDRESS attribute
    std::optional<IpEndpoint> mapped_address12 = get_mapped_address_attribute(response->message);

    if (!mapped_address12.has_value()) {
        // Server responded but without the required attribute — possibly a server-side issue
        result.nat_type = NatType::UnsupportedServer;
        phase_ = Phase::Done;
        return std::nullopt;
    }

    // Case C: Normal flow — Symmetric NAT detection
    if (!mapped_address1_.has_value() || *mapped_address12 != *mapped_address1_) {
        result.nat_type = NatType::Symmetric;
        result.public_endpoint = mapped_address12;
        phase_ = Phase::Done;
        return std::nullopt;
    }

    // Case D: Mapping consistent — proceed to Test III
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

// ====================================================================
// run_rfc3489_test — orchestrates the RFC 3489 protocol
// ====================================================================

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

// ====================================================================
// Rfc3489Test — CLI test wrapper
// ====================================================================

void Rfc3489Test::parseArgs(const std::map<std::string, std::string>& options) {
    constexpr std::uint16_t default_port = 3478;
    auto [host, port] = split_host_port(require_option(options, "--stun_server"), default_port);
    stun_host_ = host;
    stun_server_ = resolve_endpoint(host, port, SOCK_DGRAM);
    options_.server_name = stun_host_;
    options_.transport = TransportType::Udp;

    if (std::optional<std::string> timeout = find_option(options, "--timeout-ms"); timeout.has_value()) {
        options_.timeout = std::chrono::milliseconds(std::stoi(*timeout));
    }

    local_bind_ = parse_local_bind(options, stun_server_.family, SOCK_DGRAM);
}

int Rfc3489Test::runTest() {
    ClassicStunResult result = run_rfc3489_test(options_, stun_server_, local_bind_);
    print_row("NatType", to_string(result.nat_type));
    print_row("PublicEnd", endpoint_or_dash(result.public_endpoint));
    print_row("LocalEnd", endpoint_or_dash(result.local_endpoint));
    return 0;
}

void Rfc3489Test::printHelp() const {
    std::cout << "  nat_type_tester_cli rfc3489 --stun_server host[:port] [--local host[:port]] [--timeout-ms 3000]\n";
}

} // namespace natcli
