#include "discovery.hpp"

#include <sys/socket.h>

#include <array>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <optional>
#include <vector>

using namespace natcli;

namespace {

IpEndpoint endpoint(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d, std::uint16_t port) {
    IpEndpoint value;
    value.family = AF_INET;
    value.address_length = 4;
    value.address = {a, b, c, d};
    value.port = port;
    return value;
}

StunMessage response_message(std::optional<IpEndpoint> mapped,
                             std::optional<IpEndpoint> other,
                             bool use_xor_mapped = false,
                             std::uint32_t cookie = 0x2112A442u,
                             std::array<std::uint8_t, 12> txid = {}) {
    StunMessage message;
    message.type = 0x0101;
    message.magic_cookie = cookie;
    message.transaction_id = txid;

    auto encode_address = [&](std::uint16_t type, const IpEndpoint& value, bool xor_mapped) {
        StunAttribute attribute;
        attribute.type = type;
        attribute.value = {0x00, 0x01, 0x00, 0x00};
        std::uint16_t port = value.port;
        std::array<std::uint8_t, 4> bytes{value.address[0], value.address[1], value.address[2], value.address[3]};
        if (xor_mapped) {
            port ^= static_cast<std::uint16_t>(cookie >> 16);
            for (std::size_t index = 0; index < 4; ++index) {
                bytes[index] ^= static_cast<std::uint8_t>((cookie >> (24 - index * 8)) & 0xFFu);
            }
        }
        attribute.value[2] = static_cast<std::uint8_t>((port >> 8) & 0xFFu);
        attribute.value[3] = static_cast<std::uint8_t>(port & 0xFFu);
        attribute.value.insert(attribute.value.end(), bytes.begin(), bytes.end());
        message.attributes.push_back(std::move(attribute));
    };

    if (mapped.has_value()) {
        encode_address(use_xor_mapped ? 0x0020 : 0x0001, *mapped, use_xor_mapped);
    }
    if (other.has_value()) {
        encode_address(use_xor_mapped ? 0x802C : 0x0005, *other, false);
    }
    return message;
}

StunResponse response(const StunMessage& message, const IpEndpoint& remote, const IpEndpoint& local) {
    return StunResponse{message, remote, local};
}

void expect(bool condition) {
    if (!condition) {
        throw std::runtime_error("test assertion failed");
    }
}

void test_xor_mapped_parsing() {
    std::array<std::uint8_t, 12> txid{0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae};
    StunMessage message = response_message(endpoint(192, 0, 2, 1, 32853), std::nullopt, true, 0x2112A442u, txid);
    std::optional<IpEndpoint> parsed = get_xor_mapped_address_attribute(message);
    expect(parsed.has_value());
    expect(*parsed == endpoint(192, 0, 2, 1, 32853));
}

void test_rfc3489_open_internet() {
    const IpEndpoint local = endpoint(1, 1, 1, 1, 114);
    const IpEndpoint server = endpoint(2, 2, 2, 2, 1919);
    const IpEndpoint changed = endpoint(3, 3, 3, 3, 23333);

    Stun3489NatTypeDiscovery session(server);
    std::optional<StunDiscoveryAction> action = session.create_query();
    expect(action.has_value());
    action = session.got_response(response(response_message(local, changed, false, 0), server, local));
    expect(action.has_value());
    action = session.got_response(response(response_message(local, std::nullopt, false, 0), changed, local));
    expect(!action.has_value());
    expect(session.result.nat_type == NatType::OpenInternet);
}

void test_rfc3489_symmetric() {
    const IpEndpoint local = endpoint(127, 0, 0, 1, 114);
    const IpEndpoint mapped1 = endpoint(1, 1, 1, 1, 114);
    const IpEndpoint mapped2 = endpoint(1, 1, 1, 1, 514);
    const IpEndpoint server = endpoint(2, 2, 2, 2, 1919);
    const IpEndpoint changed = endpoint(3, 3, 3, 3, 23333);

    Stun3489NatTypeDiscovery session(server);
    std::optional<StunDiscoveryAction> action = session.create_query();
    expect(action.has_value());
    action = session.got_response(response(response_message(mapped1, changed, false, 0), server, local));
    expect(action.has_value());
    action = session.got_response(std::nullopt);
    expect(action.has_value());
    action = session.got_response(response(response_message(mapped2, std::nullopt, false, 0), changed, local));
    expect(!action.has_value());
    expect(session.result.nat_type == NatType::Symmetric);
}

void test_rfc5389_mapping_endpoint_independent() {
    const IpEndpoint local = endpoint(127, 0, 0, 1, 114);
    const IpEndpoint mapped = endpoint(1, 1, 1, 1, 114);
    const IpEndpoint server = endpoint(2, 2, 2, 2, 1919);
    const IpEndpoint other = endpoint(3, 3, 3, 3, 23333);
    const IpEndpoint same_other_ip = endpoint(3, 3, 3, 3, 1919);

    Stun5389NatBehaviorDiscovery session(server);
    std::optional<StunDiscoveryAction> action = session.create_mapping_behavior_test();
    expect(action.has_value());
    action = session.got_response(response(response_message(mapped, other, true), server, local));
    expect(action.has_value());
    action = session.got_response(response(response_message(mapped, other, true), same_other_ip, local));
    expect(!action.has_value());
    expect(session.result.binding_test_result == BindingTestResult::Success);
    expect(session.result.mapping_behavior == MappingBehavior::EndpointIndependent);
}

void test_rfc5389_filtering_address_dependent() {
    const IpEndpoint local = endpoint(127, 0, 0, 1, 114);
    const IpEndpoint mapped = endpoint(1, 1, 1, 1, 114);
    const IpEndpoint server = endpoint(2, 2, 2, 2, 1919);
    const IpEndpoint other = endpoint(3, 3, 3, 3, 23333);
    const IpEndpoint same_ip_different_port = endpoint(2, 2, 2, 2, 810);

    Stun5389NatBehaviorDiscovery session(server);
    std::optional<StunDiscoveryAction> action = session.create_filtering_behavior_test();
    expect(action.has_value());
    action = session.got_response(response(response_message(mapped, other, true), server, local));
    expect(action.has_value());
    action = session.got_response(std::nullopt);
    expect(action.has_value());
    action = session.got_response(response(response_message(mapped, other, true), same_ip_different_port, local));
    expect(!action.has_value());
    expect(session.result.filtering_behavior == FilteringBehavior::AddressDependent);
}

} // namespace

int main() {
    try {
        test_xor_mapped_parsing();
        test_rfc3489_open_internet();
        test_rfc3489_symmetric();
        test_rfc5389_mapping_endpoint_independent();
        test_rfc5389_filtering_address_dependent();
        std::cout << "All nat_type_tester_cli_tests passed\n";
        return 0;
    } catch (const std::exception& exception) {
        std::cerr << exception.what() << '\n';
        return 1;
    }
}
