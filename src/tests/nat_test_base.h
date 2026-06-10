#pragma once

#include <map>
#include <string>
#include <string_view>

namespace natcli {

/// Abstract base class for all NAT test implementations.
/// Each RFC test module inherits from this and implements its specific test logic.
class INatTest {
public:
    virtual ~INatTest() = default;

    /// Returns the command name (e.g. "rfc3489", "rfc5780", etc.)
    virtual std::string_view commandName() const = 0;

    /// Parse command-line options specific to this test.
    /// @param options key-value map of --option -> value
    virtual void parseArgs(const std::map<std::string, std::string>& options) = 0;

    /// Execute the test and print results to stdout.
    /// @return 0 on success, non-zero on error
    virtual int runTest() = 0;

    /// Print help/usage for this test.
    virtual void printHelp() const {}
};

} // namespace natcli
