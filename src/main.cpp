#include "discovery.hpp"

#include <sys/socket.h>

#include <iostream>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>

namespace {

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

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
        << "                               [--test-type combining|binding|mapping|filtering] [--skip-cert] [--timeout-ms 3000]\n";
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

void run_rfc5382_tcp_test(const std::string& server_ip, std::uint16_t server_port, const std::optional<IpEndpoint>& local_bind) {
    int opt = 1;

    // --- 步骤 1：创建 Listen Socket ---
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    sockaddr_storage local_sa{};
    socklen_t local_len = sizeof(sockaddr_in);
    if (local_bind.has_value()) {
        auto addr_st = natcli::to_sockaddr(*local_bind);
        local_sa = addr_st.storage;
        local_len = addr_st.length;
    } else {
        auto* sa = reinterpret_cast<sockaddr_in*>(&local_sa);
        sa->sin_family = AF_INET;
        sa->sin_addr.s_addr = INADDR_ANY;
        sa->sin_port = 0;
    }

    if (bind(listen_fd, reinterpret_cast<sockaddr*>(&local_sa), local_len) < 0) {
        fail("Failed to bind Listen Socket: " + std::string(strerror(errno)));
    }
    listen(listen_fd, 5);

    // 获取系统分配的真实本地端口
    IpEndpoint real_local = natcli::socket_local_endpoint(listen_fd);

    // --- 步骤 2：创建 Outbound Socket (复用相同的本地端口) ---
    int out_fd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(out_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(out_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    auto bind_addr = natcli::to_sockaddr(real_local);
    if (bind(out_fd, reinterpret_cast<sockaddr*>(&bind_addr.storage), bind_addr.length) < 0) {
        fail("Failed to bind Outbound Socket to reused port: " + std::string(strerror(errno)));
    }

    // --- 步骤 3：连接到服务端 IP1 ---
    IpEndpoint server_ep = natcli::resolve_endpoint(server_ip, server_port, SOCK_STREAM, AF_INET);
    auto server_sa = natcli::to_sockaddr(server_ep);

    if (connect(out_fd, reinterpret_cast<sockaddr*>(&server_sa.storage), server_sa.length) < 0) {
        fail("Failed to connect to custom TCP server: " + std::string(strerror(errno)));
    }

    // --- 步骤 4：请求 NAT 映射信息 ---
    std::string req = "BIND\n";
    send(out_fd, req.data(), req.size(), 0);

    char buf[1024];
    int n = recv(out_fd, buf, sizeof(buf) - 1, 0);
    if (n <= 0) fail("Failed to receive BIND response");
    buf[n] = 0;

    char pip[64], palt[64];
    int pport = 0;
    std::string pub_ip = "-";
    std::string pub_port = "-";
    std::string alt_ip = "-";

    if (sscanf(buf, "MAPPED %63s %d ALT %63s", pip, &pport, palt) == 3) {
        pub_ip = pip;
        pub_port = std::to_string(pport);
        alt_ip = palt;
    } else {
        fail("Invalid response from server: " + std::string(buf));
    }

    // --- 步骤 5：请求服务器用备用 IP 测试入站连接 ---
    req = "TEST_FILTER\n";
    send(out_fd, req.data(), req.size(), 0);

    // --- 步骤 6：等待入站连接 ---
    pollfd pfd{listen_fd, POLLIN, 0};
    int pr = poll(&pfd, 1, 4000); // 4秒超时

    std::string filtering_result = "AddressDependent (or PortDependent)";
    if (pr > 0 && (pfd.revents & POLLIN)) {
        int incoming = accept(listen_fd, nullptr, nullptr);
        if (incoming >= 0) {
            int in_n = recv(incoming, buf, sizeof(buf) - 1, 0);
            if (in_n > 0) {
                buf[in_n] = 0;
                if (std::string(buf).find("EIF_OK") != std::string::npos) {
                    filtering_result = "EndpointIndependent (Full Cone TCP)";
                }
            }
            close(incoming);
        }
    }

    close(out_fd);
    close(listen_fd);

    // --- 打印结果 ---
    print_row("TcpFilteringBehavior", filtering_result);
    print_row("PublicEnd", pub_ip + ":" + pub_port);
    print_row("LocalEnd", natcli::to_string(real_local));
    print_row("ServerAltIp", alt_ip);
}

} // namespace

int main(int argc, char** argv) {
    try {
        ParsedArguments args = parse_arguments(argc, argv);
        if (args.command == "help" || args.options.contains("--help") || args.options.contains("-h")) {
            print_help();
            return 0;
        }

        if (args.command != "rfc3489" && args.command != "rfc5780" && args.command != "rfc5382") {
            fail("Unknown subcommand: " + args.command);
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

        if (args.command == "rfc5382") {
            run_rfc5382_tcp_test(server_host, server_port, local_bind);
            return 0;
        }

        StunTestType test_type = parse_test_type(args);
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
