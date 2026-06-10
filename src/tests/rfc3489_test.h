#pragma once

#include "nat_test_base.h"
#include "../utils/stun.hpp"

#include <optional>

namespace natcli {

// Stun3489NatTypeDiscovery — RFC 3489 NAT type discovery protocol
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

ClassicStunResult run_rfc3489_test(const RequestOptions& options,
                                   const IpEndpoint& server,
                                   const std::optional<IpEndpoint>& local_bind);

class Rfc3489Test : public INatTest {
public:
    std::string_view commandName() const override { return "rfc3489"; }

    void parseArgs(const std::map<std::string, std::string>& options) override;
    int runTest() override;
    void printHelp() const override;

private:
    RequestOptions options_;
    std::string stun_host_;
    IpEndpoint stun_server_{};
    std::optional<IpEndpoint> local_bind_;
};

} // namespace natcli
