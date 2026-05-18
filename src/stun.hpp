#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace natcli {

enum class NatType {
    Unknown,
    UnsupportedServer,
    UdpBlocked,
    OpenInternet,
    SymmetricUdpFirewall,
    FullCone,
    RestrictedCone,
    PortRestrictedCone,
    Symmetric,
};

enum class BindingTestResult {
    Unknown,
    UnsupportedServer,
    Success,
    Fail,
};

enum class MappingBehavior {
    Unknown,
    UnsupportedServer,
    Direct,
    EndpointIndependent,
    AddressDependent,
    AddressAndPortDependent,
    Fail,
};

enum class FilteringBehavior {
    Unknown,
    UnsupportedServer,
    EndpointIndependent,
    AddressDependent,
    AddressAndPortDependent,
    None,
};

enum class TransportType {
    Udp,
    Tcp,
    Tls,
};

enum class StunTestType {
    Combining,
    Binding,
    Mapping,
    Filtering,
    TcpFiltering,
    ProtocolCorrelation,
};

struct IpEndpoint {
    int family{};
    std::array<std::uint8_t, 16> address{};
    std::size_t address_length{};
    std::uint16_t port{};
};

struct StunAttribute {
    std::uint16_t type{};
    std::vector<std::uint8_t> value;
};

struct StunMessage {
    std::uint16_t type{0x0001};
    std::uint32_t magic_cookie{0x2112A442u};
    std::array<std::uint8_t, 12> transaction_id{};
    std::vector<StunAttribute> attributes;
};

struct StunResponse {
    StunMessage message;
    IpEndpoint remote;
    IpEndpoint local;
};

struct StunDiscoveryAction {
    StunMessage message;
    IpEndpoint send_to;
};

struct ClassicStunResult {
    NatType nat_type{NatType::Unknown};
    std::optional<IpEndpoint> public_endpoint;
    std::optional<IpEndpoint> local_endpoint;
};

struct StunResult5389 {
    BindingTestResult binding_test_result{BindingTestResult::Unknown};
    MappingBehavior mapping_behavior{MappingBehavior::Unknown};
    FilteringBehavior filtering_behavior{FilteringBehavior::Unknown};
    std::optional<IpEndpoint> public_endpoint;
    std::optional<IpEndpoint> local_endpoint;
    std::optional<IpEndpoint> other_endpoint;
};

struct RequestOptions {
    TransportType transport{TransportType::Udp};
    std::string server_name;
    bool skip_certificate_validation{false};
    std::chrono::milliseconds timeout{3000};
};

bool operator==(const IpEndpoint& left, const IpEndpoint& right);
bool same_address(const IpEndpoint& left, const IpEndpoint& right);
std::string to_string(const IpEndpoint& endpoint);
std::string to_string(NatType value);
std::string to_string(BindingTestResult value);
std::string to_string(MappingBehavior value);
std::string to_string(FilteringBehavior value);
std::string to_string(TransportType value);
std::string to_string(StunTestType value);

IpEndpoint parse_endpoint_literal(std::string_view input, std::uint16_t default_port);
std::pair<std::string, std::uint16_t> split_host_port(std::string_view input, std::uint16_t default_port);
IpEndpoint resolve_endpoint(const std::string& host, std::uint16_t port, int socktype, int family = 0);
IpEndpoint wildcard_endpoint(int family, std::uint16_t port = 0);

StunMessage create_binding_request(std::uint32_t magic_cookie, bool change_ip = false, bool change_port = false);
std::vector<std::uint8_t> serialize(const StunMessage& message);
bool parse_message(const std::uint8_t* data, std::size_t size, StunMessage& message);
std::optional<IpEndpoint> get_mapped_address_attribute(const StunMessage& message);
std::optional<IpEndpoint> get_changed_address_attribute(const StunMessage& message);
std::optional<IpEndpoint> get_xor_mapped_address_attribute(const StunMessage& message);
std::optional<IpEndpoint> get_other_address_attribute(const StunMessage& message);

class UdpSession {
public:
    UdpSession(const IpEndpoint& server, const std::optional<IpEndpoint>& local_bind, std::chrono::milliseconds timeout);
    ~UdpSession();

    std::optional<StunResponse> request(const StunDiscoveryAction& action);

private:
    int socket_{-1};
    std::chrono::milliseconds timeout_{};
};

class TcpSession {
public:
    TcpSession(const std::string& server_name,
               const std::optional<IpEndpoint>& local_bind,
               std::chrono::milliseconds timeout,
               bool use_tls,
               bool skip_certificate_validation);
    std::optional<StunResponse> request(const StunDiscoveryAction& action);

private:
    std::optional<IpEndpoint> local_bind_;
    std::chrono::milliseconds timeout_{};
    std::string server_name_;
    bool use_tls_{false};
    bool skip_certificate_validation_{false};
};

} // namespace natcli
