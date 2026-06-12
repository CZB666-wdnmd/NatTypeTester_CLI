#include "test_dispatcher.h"

#include <iostream>
#include <stdexcept>

namespace natcli {

void TestDispatcher::registerTest(std::unique_ptr<INatTest> test) {
    tests_.push_back(std::move(test));
}

int TestDispatcher::dispatch(const std::string& command, const std::map<std::string, std::string>& options) {
    for (auto& test : tests_) {
        if (test->commandName() == command) {
            test->parseArgs(options);
            return test->runTest();
        }
    }
    std::cerr << "Error: Unknown subcommand: " << command << '\n';
    printHelp();
    return -1;
}

void TestDispatcher::printHelp(const std::string& command) const {
    if (!command.empty()) {
        for (auto& test : tests_) {
            if (test->commandName() == command) {
                test->printHelp();
                return;
            }
        }
    }
    printBanner();
    for (auto& test : tests_) {
        test->printHelp();
    }
}

void TestDispatcher::printBanner() {
    std::cout
        << "NatTypeTester standalone C++ CLI\n"
        << "================================\n"
        << "Comprehensive NAT type detection covering RFC 3489 / 5780 / 4787 / 5382 / 5508 / 7857 / 5597\n"
        << "Usage:\n";
}

} // namespace natcli
