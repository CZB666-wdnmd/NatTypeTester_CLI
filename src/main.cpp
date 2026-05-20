#include "discovery.hpp"
#include "rfc4787.hpp"
#include "rfc5382.hpp"
#include "rfc7857.hpp"

#include <sys/socket.h>

#include <iostream>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {

using natcli::BindingTestResult;
using natcli::IpEndpoint;
using natcli::MappingBehavior;
using natcli::ProbeStatus;
using natcli::RequestOptions;
using natcli::Rfc4787TestType;
using natcli::StunTestType;
using natcli::TransportType;

enum class Rfc5382TestType {
    All,
    Mapping,
    Filtering,
    SimultaneousOpen,
    UnexpectedSyn,
    Icmp,
};

struct ParsedArguments {
    std::string command;
    std::map<std::string, std::string> options;
};

[[noreturn]] void fail(const std::string& message) {
    throw std::runtime_error(message);
}

ParsedArguments parse_arguments(int argc, char** argv) {
    if (argc < 2) {
        fail("Expected subcommand: rfc3489, rfc5780, rfc4787, rfc5382, or rfc7857");
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
        << "NatTypeTester standalone C++ CLI\n"
        << "================================\n"
        << "一个多协议 NAT 行为与穿透特性测试工具，支持 RFC 3489 / 5780 / 4787 / 5382 / 7857。\n\n"
        << "Usage:\n"
        << "  nat_type_tester_cli rfc3489 --stun_server host[:port] [--local host[:port]] [--timeout-ms 3000]\n"
        << "  nat_type_tester_cli rfc5780 --stun_server host[:port] [--local host[:port]] [--transport udp|tcp|tls]\n"
        << "                               [--test-type combining|binding|mapping|filtering] [--skip-cert 0|1] [--timeout-ms 3000]\n"
        << "  nat_type_tester_cli rfc4787 --stun_server host[:port] --primary_server host[:port] --secondary_server host[:port]\n"
        << "                               [--local host[:port]] [--test-type all|mapping|filtering|port-allocation|icmp|fragmentation] [--timeout-ms 3000]\n"
        << "  nat_type_tester_cli rfc5382 --stun_server host[:port] --primary_server host[:port] --secondary_server host[:port]\n"
        << "                               [--local host[:port]] [--test-type all|mapping|filtering|simultaneous-open|unexpected-syn|icmp] [--timeout-ms 3000]\n"
        << "  nat_type_tester_cli rfc7857 --stun_server host[:port] --primary_server host[:port] --secondary_server host[:port]\n"
        << "                               [--local host[:port]] [--timeout-ms 3000]\n\n";
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

bool parse_bool_option(const ParsedArguments& args, const std::string& name, bool default_value = false) {
    std::optional<std::string> value = find_option(args, name);
    if (!value.has_value()) {
        return default_value;
    }
    if (*value == "1" || *value == "true") {
        return true;
    }
    if (*value == "0" || *value == "false") {
        return false;
    }
    fail("Unsupported boolean option value for " + name + ": " + *value);
}

StunTestType parse_stun_test_type(const ParsedArguments& args) {
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
    fail("Unsupported test type: " + value);
}

Rfc4787TestType parse_rfc4787_test_type(const ParsedArguments& args) {
    std::string value = find_option(args, "--test-type").value_or("all");
    if (value == "all") {
        return Rfc4787TestType::All;
    }
    if (value == "mapping") {
        return Rfc4787TestType::Mapping;
    }
    if (value == "filtering") {
        return Rfc4787TestType::Filtering;
    }
    if (value == "port-allocation") {
        return Rfc4787TestType::PortAllocation;
    }
    if (value == "icmp") {
        return Rfc4787TestType::Icmp;
    }
    if (value == "fragmentation") {
        return Rfc4787TestType::Fragmentation;
    }
    fail("Unsupported RFC4787 test type: " + value);
}

Rfc5382TestType parse_rfc5382_test_type(const ParsedArguments& args) {
    std::string value = find_option(args, "--test-type").value_or("all");
    if (value == "all") {
        return Rfc5382TestType::All;
    }
    if (value == "mapping") {
        return Rfc5382TestType::Mapping;
    }
    if (value == "filtering") {
        return Rfc5382TestType::Filtering;
    }
    if (value == "simultaneous-open") {
        return Rfc5382TestType::SimultaneousOpen;
    }
    if (value == "unexpected-syn") {
        return Rfc5382TestType::UnexpectedSyn;
    }
    if (value == "icmp") {
        return Rfc5382TestType::Icmp;
    }
    fail("Unsupported RFC5382 test type: " + value);
}

std::optional<IpEndpoint> parse_local_bind(const ParsedArguments& args, int family, int socket_type) {
    std::optional<std::string> local = find_option(args, "--local");
    if (!local.has_value()) {
        return std::nullopt;
    }
    auto [host, port] = natcli::split_host_port(*local, 0);
    return natcli::resolve_endpoint(host, port, socket_type, family);
}

void print_row(const std::string& key, const std::string& value) {
    std::cout << key << ": " << value << '\n';
}

std::string endpoint_or_dash(const std::optional<IpEndpoint>& endpoint) {
    return endpoint.has_value() ? natcli::to_string(*endpoint) : "-";
}

void print_mapping_if_available(MappingBehavior behavior) {
    if (behavior != MappingBehavior::Unknown) {
        print_row("MappingBehavior", natcli::to_string(behavior));
    }
}

void print_binding_if_available(BindingTestResult result) {
    if (result != BindingTestResult::Unknown) {
        print_row("BindingTest", natcli::to_string(result));
    }
}

void print_probe_if_available(const std::string& name, ProbeStatus status) {
    if (status != ProbeStatus::Unknown) {
        print_row(name, natcli::to_string(status));
    }
}

} // namespace

int main(int argc, char** argv) {
    try {
        ParsedArguments args = parse_arguments(argc, argv);
        if (args.command == "help" || args.options.contains("--help") || args.options.contains("-h")) {
            print_help();
            return 0;
        }

        if (args.command != "rfc3489" && args.command != "rfc5780" && args.command != "rfc4787" &&
            args.command != "rfc5382" && args.command != "rfc7857") {
            fail("Unknown subcommand: " + args.command);
        }

        constexpr std::uint16_t default_port = 3478;
        auto [stun_host, stun_port] = natcli::split_host_port(require_option(args, "--stun_server"), default_port);
        IpEndpoint stun_server = natcli::resolve_endpoint(stun_host, stun_port, SOCK_DGRAM);

        RequestOptions options;
        options.transport = TransportType::Udp;
        options.server_name = stun_host;
        options.skip_certificate_validation = parse_bool_option(args, "--skip-cert", false);
        if (std::optional<std::string> timeout = find_option(args, "--timeout-ms"); timeout.has_value()) {
            options.timeout = std::chrono::milliseconds(std::stoi(*timeout));
        }

        if (args.command == "rfc3489") {
            std::optional<IpEndpoint> local_bind = parse_local_bind(args, stun_server.family, SOCK_DGRAM);
            natcli::ClassicStunResult result = natcli::run_rfc3489_test(options, stun_server, local_bind);
            print_row("NatType", natcli::to_string(result.nat_type));
            print_row("PublicEnd", endpoint_or_dash(result.public_endpoint));
            print_row("LocalEnd", endpoint_or_dash(result.local_endpoint));
            return 0;
        }

        if (args.command == "rfc5780") {
            options.transport = parse_transport(args);
            std::optional<IpEndpoint> local_bind = parse_local_bind(
                args, stun_server.family, options.transport == TransportType::Udp ? SOCK_DGRAM : SOCK_STREAM);
            StunTestType test_type = parse_stun_test_type(args);
            natcli::StunResult5389 result = natcli::run_rfc5780_test(options, test_type, stun_server, local_bind);

            if (test_type == StunTestType::Combining || test_type == StunTestType::Binding) {
                print_row("BindingTest", natcli::to_string(result.binding_test_result));
            }
            if (test_type == StunTestType::Combining || test_type == StunTestType::Mapping) {
                print_row("MappingBehavior", natcli::to_string(result.mapping_behavior));
            }
            if (test_type == StunTestType::Filtering ||
                (test_type == StunTestType::Combining && options.transport == TransportType::Udp)) {
                print_row("FilteringBehavior", natcli::to_string(result.filtering_behavior));
            }
            print_row("PublicEnd", endpoint_or_dash(result.public_endpoint));
            print_row("LocalEnd", endpoint_or_dash(result.local_endpoint));
            print_row("OtherEnd", endpoint_or_dash(result.other_endpoint));
            return 0;
        }

        auto [primary_host, primary_port] = natcli::split_host_port(require_option(args, "--primary_server"), default_port);
        auto [secondary_host, secondary_port] =
            natcli::split_host_port(require_option(args, "--secondary_server"), default_port);
        IpEndpoint primary_server = natcli::resolve_endpoint(primary_host, primary_port, SOCK_STREAM, stun_server.family);
        IpEndpoint secondary_server =
            natcli::resolve_endpoint(secondary_host, secondary_port, SOCK_STREAM, stun_server.family);
        std::optional<IpEndpoint> local_bind = parse_local_bind(args, stun_server.family, SOCK_STREAM);

        if (args.command == "rfc4787") {
            std::optional<IpEndpoint> udp_local_bind = parse_local_bind(args, stun_server.family, SOCK_DGRAM);
            Rfc4787TestType test_type = parse_rfc4787_test_type(args);
            natcli::Rfc4787Result result =
                natcli::run_rfc4787_tests(options, test_type, stun_server, primary_server, secondary_server, udp_local_bind);
            print_binding_if_available(result.binding_test_result);
            print_mapping_if_available(result.mapping_behavior);
            if (result.filtering_behavior != natcli::FilteringBehavior::Unknown) {
                print_row("FilteringBehavior", natcli::to_string(result.filtering_behavior));
            }
            print_probe_if_available("PortRangePreservation", result.port_range_preservation);
            print_probe_if_available("PortParityPreservation", result.port_parity_preservation);
            print_probe_if_available("IcmpErrorHandling", result.icmp_error_handling);
            print_probe_if_available("UdpHairpinning", result.udp_hairpinning);
            print_probe_if_available("UdpHairpinningSourceAddress", result.udp_hairpinning_source_address);
            print_probe_if_available("OutboundFragmentation", result.outbound_fragmentation);
            print_probe_if_available("OutboundDfFragmentationError", result.outbound_df_fragmentation_error);
            print_probe_if_available("InboundFragmentation", result.inbound_fragmentation);
            print_probe_if_available("OutOfOrderFragmentation", result.out_of_order_fragmentation);
            print_row("PublicEnd", endpoint_or_dash(result.public_endpoint));
            print_row("LocalEnd", endpoint_or_dash(result.local_endpoint));
            return 0;
        }

        if (args.command == "rfc5382") {
            Rfc5382TestType test_type = parse_rfc5382_test_type(args);
            natcli::StunResult5389 mapping_result =
                natcli::run_rfc5780_test(options, StunTestType::Mapping, stun_server, local_bind);
            natcli::Rfc5382TcpResult server_result =
                natcli::run_rfc5382_tests(options, stun_server, primary_server, secondary_server, local_bind);

            if (test_type == Rfc5382TestType::All || test_type == Rfc5382TestType::Mapping) {
                print_row("MappingBehavior", natcli::to_string(mapping_result.mapping_behavior));
                print_row("UdpPublicEnd", endpoint_or_dash(mapping_result.public_endpoint));
            }
            if (test_type == Rfc5382TestType::All || test_type == Rfc5382TestType::Filtering) {
                print_row("FilteringBehavior", natcli::to_string(server_result.filtering_behavior));
                print_row("TcpPublicEnd", endpoint_or_dash(server_result.tcp_public_endpoint));
            }
            if (test_type == Rfc5382TestType::All || test_type == Rfc5382TestType::SimultaneousOpen) {
                print_row("TcpSimultaneousOpen", natcli::to_string(server_result.simultaneous_open));
            }
            if (test_type == Rfc5382TestType::All || test_type == Rfc5382TestType::UnexpectedSyn) {
                print_row("UnexpectedSynHandling", natcli::to_string(server_result.unexpected_syn));
            }
            if (test_type == Rfc5382TestType::All || test_type == Rfc5382TestType::Icmp) {
                print_row("IcmpErrorHandling", natcli::to_string(server_result.icmp_error_handling));
                print_row("TcpHairpinning", natcli::to_string(server_result.tcp_hairpinning));
                print_row("TcpHairpinningSourceAddress", natcli::to_string(server_result.tcp_hairpinning_source_address));
            }
            print_row("LocalEnd", endpoint_or_dash(server_result.local_endpoint));
            return 0;
        }

        natcli::Rfc7857Result result =
            natcli::run_rfc7857_tests(options, stun_server, primary_server, secondary_server, local_bind);
        print_row("UdpMappingBehavior", natcli::to_string(result.udp_mapping_behavior));
        print_row("UdpFilteringBehavior", natcli::to_string(result.udp_filtering_behavior));
        print_row("TcpFilteringBehavior", natcli::to_string(result.tcp_filtering_behavior));
        print_row("EimProtocolIndependence", natcli::to_string(result.eim_protocol_independence));
        print_row("EifProtocolIndependence", natcli::to_string(result.eif_protocol_independence));
        print_row("PortParityPreservation", natcli::to_string(result.port_parity_preservation));
        print_row("UdpHairpinning", natcli::to_string(result.udp_hairpinning));
        print_row("TcpHairpinning", natcli::to_string(result.tcp_hairpinning));
        print_row("IcmpHairpinning", natcli::to_string(result.icmp_hairpinning));
        print_row("Section9PortRandomization", natcli::to_string(result.section9_port_randomization));
        print_row("Section9PublicPorts", result.section9_public_ports.empty() ? "-" : result.section9_public_ports);
        print_row("Section10Ipv4IdPreservation", natcli::to_string(result.section10_ipv4_id_preservation));
        print_row("UdpPublicEnd", endpoint_or_dash(result.udp_public_endpoint));
        print_row("TcpPublicEnd", endpoint_or_dash(result.tcp_public_endpoint));
        print_row("LocalEnd", endpoint_or_dash(result.local_endpoint));
        return 0;
    } catch (const std::exception& exception) {
        std::cerr << "Error: " << exception.what() << '\n';
        print_help();
        return 1;
    }
}
