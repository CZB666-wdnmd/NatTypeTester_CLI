#pragma once

#include "nat_test_base.h"

#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace natcli {

/// Factory/registry that maps command names to INatTest implementations.
class TestDispatcher {
public:
    /// Register a test implementation.
    void registerTest(std::unique_ptr<INatTest> test);

    /// Dispatch based on parsed command name and options.
    /// Returns the test's runTest() result, or -1 if command not found.
    int dispatch(const std::string& command, const std::map<std::string, std::string>& options);

    /// Print help for a specific command, or all commands if command is empty.
    void printHelp(const std::string& command = "") const;

    /// Print global usage banner.
    static void printBanner();

private:
    std::vector<std::unique_ptr<INatTest>> tests_;
};

} // namespace natcli
