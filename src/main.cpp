#include "tests/nat_test_base.h"
#include "tests/test_dispatcher.h"
#include "tests/rfc3489_test.h"
#include "tests/rfc5780_test.h"
#include "tests/rfc4787_test.h"
#include "tests/rfc5382_test.h"
#include "tests/rfc5508_test.h"
#include "tests/rfc7857_test.h"

#include <sys/socket.h>
#include <unistd.h>

#include <cstdlib>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {

struct ParsedArguments {
    std::string command;
    std::map<std::string, std::string> options;
};

[[noreturn]] void fail(const std::string& message) {
    throw std::runtime_error(message);
}

bool run_shell_command(const std::string& command) {
    return std::system(command.c_str()) == 0;
}

bool command_exists(const std::string& command) {
    return run_shell_command("command -v " + command + " >/dev/null 2>&1");
}

bool ensure_iptables_icmp_notrack() {
    if (!command_exists("iptables")) {
        return false;
    }
    bool ok = true;
    if (!run_shell_command("iptables -t raw -C OUTPUT -p icmp -j CT --notrack >/dev/null 2>&1")) {
        if (!run_shell_command("iptables -t raw -I OUTPUT -p icmp -j CT --notrack >/dev/null 2>&1")) {
            ok = false;
        }
    }
    if (!run_shell_command("iptables -t raw -C PREROUTING -p icmp -j CT --notrack >/dev/null 2>&1")) {
        if (!run_shell_command("iptables -t raw -I PREROUTING -p icmp -j CT --notrack >/dev/null 2>&1")) {
            ok = false;
        }
    }
    return ok;
}

bool ensure_nftables_icmp_notrack() {
    if (!command_exists("nft")) {
        return false;
    }
    bool ok = true;
    if (!run_shell_command("nft list table ip raw >/dev/null 2>&1") &&
        !run_shell_command("nft add table ip raw >/dev/null 2>&1")) {
        ok = false;
    }
    if (!run_shell_command("nft list chain ip raw prerouting >/dev/null 2>&1") &&
        !run_shell_command("nft add chain ip raw prerouting '{ type filter hook prerouting priority raw; }' >/dev/null 2>&1")) {
        ok = false;
    }
    if (!run_shell_command("nft list chain ip raw output >/dev/null 2>&1") &&
        !run_shell_command("nft add chain ip raw output '{ type filter hook output priority raw; }' >/dev/null 2>&1")) {
        ok = false;
    }
    if (!run_shell_command(
            "nft list chain ip raw output 2>/dev/null | grep -Eq '^[[:space:]]*ip protocol icmp notrack([[:space:]].*)?$'")) {
        if (!run_shell_command("nft add rule ip raw output ip protocol icmp notrack >/dev/null 2>&1")) {
            ok = false;
        }
    }
    if (!run_shell_command(
            "nft list chain ip raw prerouting 2>/dev/null | grep -Eq '^[[:space:]]*ip protocol icmp notrack([[:space:]].*)?$'")) {
        if (!run_shell_command("nft add rule ip raw prerouting ip protocol icmp notrack >/dev/null 2>&1")) {
            ok = false;
        }
    }
    return ok;
}

bool command_needs_icmp_notrack(const std::string& command) {
    return command == "rfc4787" || command == "rfc5382" || command == "rfc5508" || command == "rfc7857";
}

void ensure_icmp_conntrack_bypass_if_needed(const std::string& command, bool use_stderr = false) {
    if (!command_needs_icmp_notrack(command)) {
        return;
    }
    bool configured = ensure_iptables_icmp_notrack();
    if (!configured) {
        configured = ensure_nftables_icmp_notrack();
    }
    if (geteuid() != 0) {
        std::cerr << "Warning: ICMP notrack rules not configured (run as root). Raw ICMP probes may be dropped as INVALID.\n";
    } else {
        std::cerr << "Warning: Failed to configure ICMP notrack rules via iptables/nft. Raw ICMP probes may be dropped as INVALID.\n";
    }
}

ParsedArguments parse_arguments(int argc, char** argv) {
    if (argc < 2) {
        fail("Expected subcommand: rfc3489, rfc5780, rfc4787, rfc5382, rfc5508, or rfc7857");
    }

    ParsedArguments result;
    if (std::string_view(argv[1]) == "--help" || std::string_view(argv[1]) == "-h") {
        result.command = "help";
        result.options["--help"] = "true";
        return result;
    }
    result.command = argv[1];

    for (int index = 2; index < argc; ++index) {
        std::string token = argv[index];
        if (token == "--help" || token == "-h") {
            result.options[token] = "true";
            continue;
        }
        // --json is a standalone flag (no value)
        if (token == "--json") {
            result.options[token] = "1";
            continue;
        }
        if (!token.starts_with("--")) {
            fail("Unexpected argument: " + token);
        }
        if (index + 1 >= argc) {
            fail("Missing value for option: " + token);
        }
        result.options[token] = argv[++index];
    }

    return result;
}

natcli::TestDispatcher create_dispatcher() {
    natcli::TestDispatcher dispatcher;
    dispatcher.registerTest(std::make_unique<natcli::Rfc3489Test>());
    dispatcher.registerTest(std::make_unique<natcli::Rfc5780Test>());
    dispatcher.registerTest(std::make_unique<natcli::Rfc4787Test>());
    dispatcher.registerTest(std::make_unique<natcli::Rfc5382Test>());
    dispatcher.registerTest(std::make_unique<natcli::Rfc5508Test>());
    dispatcher.registerTest(std::make_unique<natcli::Rfc7857Test>());
    return dispatcher;
}

} // namespace

int main(int argc, char** argv) {
    try {
        ParsedArguments args = parse_arguments(argc, argv);

        natcli::TestDispatcher dispatcher = create_dispatcher();

        if (args.command == "help" || args.options.contains("--help") || args.options.contains("-h")) {
            dispatcher.printHelp();
            return 0;
        }

        if (args.command != "rfc3489" && args.command != "rfc5780" && args.command != "rfc4787" &&
            args.command != "rfc5508" &&
            args.command != "rfc5382" && args.command != "rfc7857") {
            fail("Unknown subcommand: " + args.command);
        }

        bool json_mode = args.options.contains("--json");
        ensure_icmp_conntrack_bypass_if_needed(args.command, json_mode);

        int result = dispatcher.dispatch(args.command, args.options);
        if (result < 0) {
            return 1;
        }
        return result;
    } catch (const std::exception& exception) {
        std::cerr << "Error: " << exception.what() << '\n';
        natcli::TestDispatcher::printBanner();
        return 1;
    }
}
