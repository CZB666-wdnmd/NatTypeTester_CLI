#pragma once

#include "nat_test_base.h"
#include "../utils/stun.hpp"

#include <optional>

namespace natcli {

enum class Rfc5508TestType {
    All,
    Mapping,
    Filtering,
};

struct Rfc5508Result {
    MappingBehavior mapping_behavior{MappingBehavior::Unknown};
    FilteringBehavior filtering_behavior{FilteringBehavior::Unknown};
    ProbeStatus icmp_error_payload_validation{ProbeStatus::Unknown};
    ProbeStatus outbound_icmp_error{ProbeStatus::Unknown};
    ProbeStatus icmp_hairpin_query{ProbeStatus::Unknown};
    ProbeStatus icmp_hairpin_error{ProbeStatus::Unknown};
    bool malformed_server_outer_checksum_forwarded{false};
    bool malformed_server_inner_ip_checksum_forwarded{false};
    bool malformed_server_bad_udp_checksum_forwarded{false};
    bool malformed_client_outer_checksum_forwarded{false};
    bool malformed_client_inner_ip_checksum_forwarded{false};
    bool malformed_client_bad_udp_checksum_forwarded{false};
    std::optional<IpEndpoint> local_endpoint;
    std::optional<IpEndpoint> public_endpoint;
    std::optional<std::uint16_t> local_query;
    std::optional<std::uint16_t> public_query;
};

Rfc5508Result run_rfc5508_tests(const RequestOptions& options,
                                Rfc5508TestType test_type,
                                const IpEndpoint& primary_server,
                                const IpEndpoint& secondary_server,
                                const std::optional<IpEndpoint>& local_bind);

ProbeStatus run_icmp_hairpinning_probe(int raw_fd,
                                       int raw_send_fd,
                                       const IpEndpoint& primary_server,
                                       const IpEndpoint& local_endpoint,
                                       const IpEndpoint& public_endpoint,
                                       std::uint16_t public_query_id,
                                       std::chrono::milliseconds timeout);

class Rfc5508Test : public INatTest {
public:
    std::string_view commandName() const override { return "rfc5508"; }

    void parseArgs(const std::map<std::string, std::string>& options) override;
    int runTest() override;
    void printHelp() const override;

private:
    RequestOptions options_;
    IpEndpoint stun_server_{};
    IpEndpoint primary_server_{};
    IpEndpoint secondary_server_{};
    std::string test_type_str_{"all"};
    std::optional<IpEndpoint> local_bind_;
};

} // namespace natcli
