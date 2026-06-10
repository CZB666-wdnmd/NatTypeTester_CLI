#pragma once

#include "nat_test_base.h"
#include "../utils/hairpin_utils.h"

#include <optional>

namespace natcli {

class Rfc5382Test : public INatTest {
public:
    std::string_view commandName() const override { return "rfc5382"; }

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
