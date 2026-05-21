#pragma once

#include "stun.hpp"

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

} // namespace natcli
