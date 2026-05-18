#include "discovery.hpp"

#include <sys/socket.h>

#include <iostream>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using natcli::IpEndpoint;
using natcli::RequestOptions;
using natcli::StunTestType;
using natcli::TransportType;

struct ParsedArguments {
    std::string command;
    std::map<std::string, std::string> options;
};

[[noreturn]] void fail(const std::string& message) {
    throw std::runtime_error(message);
}

ParsedArguments parse_arguments(int argc, char** argv) {
    if (argc < 2) {
        fail("Expected subcommand: rfc3489 or rfc5780");
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

void print_help() {
    std::cout
        << "NatTypeTester standalone C++ CLI\n\n"
        << "Usage:\n"
        << "  nat_type_tester_cli rfc3489 --server host[:port] [--local host[:port]] [--timeout-ms 3000]\n"
        << "  nat_type_tester_cli rfc5780 --server host[:port] [--local host[:port]] [--transport udp|tcp|tls]\n"
        << "                               [--test-type combining|binding|mapping|filtering|protocol-correlation] [--skip-cert] [--timeout-ms 3000]\n";
}

std::string require_option(const ParsedArguments& args, const std::string& name) {
    auto it = args.options.find(name);
    if (it == args.options.end()) {
        fail("Missing required option: " + name);
    }
    return it->second;
}

std::optional<std::string> find_option(const ParsedArguments& args, const std::string& name) {
    auto it = args.options.find(name);
    if (it == args.options.end()) {
        return std::nullopt;
    }
    return it->second;
}

TransportType parse_transport(const ParsedArguments& args) {
    std::string value = find_option(args, "--transport").value_or("udp");
    if (value == "udp") {
        return TransportType::Udp;
    }
    if (value == "tcp") {
        return TransportType::Tcp;
    }
    if (value == "tls") {
        return TransportType::Tls;
    }
    fail("Unsupported transport: " + value);
}

StunTestType parse_test_type(const ParsedArguments& args) {
    std::string value = find_option(args, "--test-type").value_or("combining");
    if (value == "combining") {
        return StunTestType::Combining;
    }
    if (value == "binding") {
        return StunTestType::Binding;
    }
    if (value == "mapping") {
        return StunTestType::Mapping;
    }
    if (value == "filtering") {
        return StunTestType::Filtering;
    }
    if (value == "protocol-correlation") { 
        return StunTestType::ProtocolCorrelation;
    }
    fail("Unsupported test type: " + value);
}

std::optional<IpEndpoint> parse_local_bind(const ParsedArguments& args, int family) {
    std::optional<std::string> local = find_option(args, "--local");
    if (!local.has_value()) {
        return std::nullopt;
    }
    auto [host, port] = natcli::split_host_port(*local, 0);
    return natcli::resolve_endpoint(host, port, SOCK_STREAM, family);
}

void print_row(const std::string& key, const std::string& value) {
    std::cout << key << ": " << value << '\n';
}

std::string endpoint_or_dash(const std::optional<IpEndpoint>& endpoint) {
    return endpoint.has_value() ? natcli::to_string(*endpoint) : "-";
}

} // namespace

int main(int argc, char** argv) {
    try {
        ParsedArguments args = parse_arguments(argc, argv);
        if (args.command == "help" || args.options.contains("--help") || args.options.contains("-h")) {
            print_help();
            return 0;
        }

        if (args.command != "rfc3489" && args.command != "rfc5780") {
            fail("Unknown subcommand: " + args.command);
        }

        constexpr std::uint16_t default_port = 3478;
        auto [server_host, server_port] = natcli::split_host_port(require_option(args, "--server"), default_port);
        TransportType transport = args.command == "rfc3489" ? TransportType::Udp : parse_transport(args);
        int socket_type = transport == TransportType::Udp ? SOCK_DGRAM : SOCK_STREAM;
        IpEndpoint server = natcli::resolve_endpoint(server_host, server_port, socket_type);
        std::optional<IpEndpoint> local_bind = parse_local_bind(args, server.family);

        RequestOptions options;
        options.transport = transport;
        options.server_name = server_host;
        options.skip_certificate_validation = args.options.contains("--skip-cert");
        if (std::optional<std::string> timeout = find_option(args, "--timeout-ms"); timeout.has_value()) {
            options.timeout = std::chrono::milliseconds(std::stoi(*timeout));
        }

        if (args.command == "rfc3489") {
            natcli::ClassicStunResult result = natcli::run_rfc3489_test(options, server, local_bind);
            print_row("NatType", natcli::to_string(result.nat_type));
            print_row("PublicEnd", endpoint_or_dash(result.public_endpoint));
            print_row("LocalEnd", endpoint_or_dash(result.local_endpoint));
            return 0;
        }

        StunTestType test_type = parse_test_type(args);
        if (test_type == StunTestType::ProtocolCorrelation) {
            // 第一步：使用 UDP 进行绑定测试
            RequestOptions udp_options = options;
            udp_options.transport = TransportType::Udp;
            natcli::StunResult5389 udp_result = natcli::run_rfc5780_test(udp_options, StunTestType::Binding, server, local_bind);

            if (!udp_result.local_endpoint.has_value() || !udp_result.public_endpoint.has_value()) {
                fail("UDP Binding failed, cannot proceed with protocol correlation test.");
            }

            // 第二步：使用完全相同的 Local IP 和 Port，发起 TCP 绑定测试
            natcli::IpEndpoint shared_local = *udp_result.local_endpoint;
            RequestOptions tcp_options = options;
            tcp_options.transport = TransportType::Tcp;
            natcli::StunResult5389 tcp_result = natcli::run_rfc5780_test(tcp_options, StunTestType::Binding, server, shared_local);

            print_row("UDP LocalEnd", endpoint_or_dash(udp_result.local_endpoint));
            print_row("UDP PublicEnd", endpoint_or_dash(udp_result.public_endpoint));
            print_row("TCP LocalEnd", endpoint_or_dash(tcp_result.local_endpoint));
            print_row("TCP PublicEnd", endpoint_or_dash(tcp_result.public_endpoint));

            if (tcp_result.public_endpoint.has_value()) {
                if (*udp_result.public_endpoint == *tcp_result.public_endpoint) {
                    print_row("ProtocolCorrelation", "Independent (RFC 5382 Req 2 Supported)");
                } else if (udp_result.public_endpoint->address == tcp_result.public_endpoint->address) {
                    print_row("ProtocolCorrelation", "Address-Independent, Port-Dependent");
                } else {
                    print_row("ProtocolCorrelation", "Dependent (RFC 5382 Req 2 Unsupported)");
                }
            } else {
                print_row("ProtocolCorrelation", "Unknown (TCP Binding Failed)");
            }
            return 0;
        }

        natcli::StunResult5389 result = natcli::run_rfc5780_test(options, test_type, server, local_bind);

        if (test_type == StunTestType::Combining || test_type == StunTestType::Binding) {
            print_row("BindingTest", natcli::to_string(result.binding_test_result));
        }
        if (test_type == StunTestType::Combining || test_type == StunTestType::Mapping) {
            print_row("MappingBehavior", natcli::to_string(result.mapping_behavior));
        }
        if (test_type == StunTestType::Filtering ||
            (test_type == StunTestType::Combining && transport == TransportType::Udp)) {
            print_row("FilteringBehavior", natcli::to_string(result.filtering_behavior));
        }
        print_row("PublicEnd", endpoint_or_dash(result.public_endpoint));
        print_row("LocalEnd", endpoint_or_dash(result.local_endpoint));
        print_row("OtherEnd", endpoint_or_dash(result.other_endpoint));
        return 0;
    } catch (const std::exception& exception) {
        std::cerr << "Error: " << exception.what() << '\n';
        print_help();
        return 1;
    }
}
