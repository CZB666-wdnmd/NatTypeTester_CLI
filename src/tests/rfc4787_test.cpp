#include "rfc4787_test.h"
#include "../utils/hairpin_utils.h"
#include "../utils/stun_utils.h"
#include "../utils/net_utils.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/errqueue.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace natcli {
namespace {

// ---- Test wrapper helpers ----

std::string require_option(const std::map<std::string, std::string>& options, const std::string& name) {
    auto it = options.find(name);
    if (it == options.end()) {
        throw std::runtime_error("Missing required option: " + name);
    }
    return it->second;
}

std::optional<std::string> find_option(const std::map<std::string, std::string>& options, const std::string& name) {
    auto it = options.find(name);
    if (it == options.end()) {
        return std::nullopt;
    }
    return it->second;
}

Rfc4787TestType parse_rfc4787_test_type(const std::map<std::string, std::string>& options) {
    std::string value = find_option(options, "--test-type").value_or("all");
    if (value == "all") return Rfc4787TestType::All;
    if (value == "mapping") return Rfc4787TestType::Mapping;
    if (value == "filtering") return Rfc4787TestType::Filtering;
    if (value == "port-allocation") return Rfc4787TestType::PortAllocation;
    if (value == "icmp") return Rfc4787TestType::Icmp;
    if (value == "fragmentation") return Rfc4787TestType::Fragmentation;
    if (value == "determinism") return Rfc4787TestType::Determinism;
    if (value == "port-overloading") return Rfc4787TestType::PortOverloading;
    throw std::runtime_error("Unsupported RFC4787 test type: " + value);
}

std::optional<IpEndpoint> parse_local_bind(const std::map<std::string, std::string>& options, int family, int socket_type) {
    std::optional<std::string> local = find_option(options, "--local");
    if (!local.has_value()) return std::nullopt;
    auto [host, port] = split_host_port(*local, 0);
    return resolve_endpoint(host, port, socket_type, family);
}

void print_row(const std::string& key, const std::string& value) {
    std::cout << key << ": " << value << '\n';
}

std::string endpoint_or_dash(const std::optional<IpEndpoint>& endpoint) {
    return endpoint.has_value() ? to_string(*endpoint) : "-";
}

void print_binding_if_available(BindingTestResult r) {
    if (r != BindingTestResult::Unknown) print_row("BindingTest", to_string(r));
}

void print_mapping_if_available(MappingBehavior b) {
    if (b != MappingBehavior::Unknown) print_row("MappingBehavior", to_string(b));
}

void print_probe_if_available(const std::string& name, ProbeStatus s) {
    if (s != ProbeStatus::Unknown) print_row(name, to_string(s));
}

// ---- RFC4787 business logic helpers ----

ProbeStatus evaluate_port_range(const std::optional<IpEndpoint>& local, const std::optional<IpEndpoint>& mapped) {
    if (!local.has_value() || !mapped.has_value()) {
        return ProbeStatus::Inconclusive;
    }
    const bool local_well_known = local->port <= 1023;
    const bool mapped_well_known = mapped->port <= 1023;
    return local_well_known == mapped_well_known ? ProbeStatus::Pass : ProbeStatus::Fail;
}

// ==== 替换：全新的10次严格奇偶性测试函数 ====
ProbeStatus run_port_parity_test(const RequestOptions& options,
                                 const IpEndpoint& stun_server,
                                 const std::optional<IpEndpoint>& local_bind) {
    int even_tested = 0;
    int odd_tested = 0;
    int parity_preserved_count = 0;

    IpEndpoint base_bind = local_bind.value_or(wildcard_endpoint(stun_server.family));
    bool use_sequential = (base_bind.port != 0);

    // 如果是随机端口(0)给它最多尝试50次，如果是固定基准端口顺序分配最多尝试20次
    int max_attempts = use_sequential ? 20 : 50;
    uint16_t current_port = base_bind.port;

    for (int i = 0; i < max_attempts && (even_tested < 5 || odd_tested < 5); ++i) {
        IpEndpoint bind_ep = base_bind;
        if (use_sequential) {
            bind_ep.port = current_port++;
        } else {
            bind_ep.port = 0; // 0代表由OS随机分配临时端口
        }

        // 发起独立的 Binding 测试来探测映射后的公网端口
        StunResult5389 res = run_rfc5780_test(options, StunTestType::Binding, stun_server, bind_ep);
        if (res.binding_test_result != BindingTestResult::Success || 
            !res.local_endpoint.has_value() || 
            !res.public_endpoint.has_value()) {
            continue;
        }

        uint16_t l_port = res.local_endpoint->port;
        uint16_t p_port = res.public_endpoint->port;
        bool is_even = (l_port % 2 == 0);

        if (is_even && even_tested < 5) {
            even_tested++;
            if (p_port % 2 == 0) parity_preserved_count++;
        } else if (!is_even && odd_tested < 5) {
            odd_tested++;
            if (p_port % 2 != 0) parity_preserved_count++;
        }
    }

    // 如果所在的系统非常奇葩，无法分配出5个偶数/奇数端口
    if (even_tested < 5 || odd_tested < 5) {
        return ProbeStatus::Inconclusive;
    }

    // 只有 10 次的奇偶性全部分配对应（偶对应偶，奇对应奇），才算严格 Pass
    return (parity_preserved_count == 10) ? ProbeStatus::Pass : ProbeStatus::Fail;
}

ProbeStatus run_udp_echo_probe(const IpEndpoint& target,
                               const std::optional<IpEndpoint>& local_bind,
                               std::chrono::milliseconds timeout,
                               std::size_t payload_size) {
    int socket_fd = socket(target.family, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd < 0) {
        return ProbeStatus::Inconclusive;
    }

    ProbeStatus result = ProbeStatus::Fail;
    try {
        if (local_bind.has_value()) {
            SocketAddress local = to_sockaddr(*local_bind);
            if (bind(socket_fd, reinterpret_cast<sockaddr*>(&local.storage), local.length) != 0) {
                close(socket_fd);
                return ProbeStatus::Inconclusive;
            }
        }

        SocketAddress remote = to_sockaddr(target);
        std::vector<std::uint8_t> payload(payload_size, 0x7A);
        ssize_t sent = sendto(socket_fd,
                              payload.data(),
                              payload.size(),
                              0,
                              reinterpret_cast<sockaddr*>(&remote.storage),
                              remote.length);
        if (sent != static_cast<ssize_t>(payload.size())) {
            close(socket_fd);
            return ProbeStatus::Fail;
        }

        if (!wait_for_readable(socket_fd, timeout)) {
            close(socket_fd);
            return ProbeStatus::Fail;
        }

        std::vector<std::uint8_t> received(payload_size + 64, 0);
        ssize_t received_size = recv(socket_fd, received.data(), received.size(), 0);
        if (received_size == static_cast<ssize_t>(payload.size()) &&
            std::equal(payload.begin(), payload.end(), received.begin())) {
            result = ProbeStatus::Pass;
        }
        close(socket_fd);
        return result;
    } catch (...) {
        close(socket_fd);
        return ProbeStatus::Inconclusive;
    }
}

std::optional<IpEndpoint> parse_endpoint_line(const std::string& line, int family) {
    std::istringstream stream(line);
    std::string host;
    std::uint16_t port = 0;
    if (!(stream >> host >> port)) {
        return std::nullopt;
    }
    return resolve_endpoint(host, port, SOCK_DGRAM, family);
}

std::optional<std::string> exchange_udp_server_command(int socket_fd,
                                                       const IpEndpoint& server,
                                                       std::string_view command,
                                                       std::chrono::milliseconds timeout) {
    SocketAddress remote = to_sockaddr(server);
    const ssize_t sent = sendto(socket_fd,
                                command.data(),
                                command.size(),
                                0,
                                reinterpret_cast<sockaddr*>(&remote.storage),
                                remote.length);
    if (sent != static_cast<ssize_t>(command.size())) {
        return std::nullopt;
    }
    if (!wait_for_readable(socket_fd, timeout)) {
        return std::nullopt;
    }
    std::array<char, 512> buffer{};
    ssize_t received = recv(socket_fd, buffer.data(), buffer.size() - 1, 0);
    if (received <= 0) {
        return std::nullopt;
    }
    buffer[static_cast<std::size_t>(received)] = '\0';
    return std::string(buffer.data());
}

ProbeStatus run_udp_df_fragmentation_probe(const IpEndpoint& target,
                                           const std::optional<IpEndpoint>& local_bind,
                                           std::chrono::milliseconds timeout) {
    if (target.family != AF_INET) {
        return ProbeStatus::Inconclusive;
    }
    int socket_fd = socket(target.family, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd < 0) {
        return ProbeStatus::Inconclusive;
    }
    try {
        set_reuse_options(socket_fd);
        int enable = 1;
        setsockopt(socket_fd, SOL_IP, IP_RECVERR, &enable, sizeof(enable));
        int pmtu_mode = IP_PMTUDISC_DO;
        setsockopt(socket_fd, SOL_IP, IP_MTU_DISCOVER, &pmtu_mode, sizeof(pmtu_mode));
        if (local_bind.has_value()) {
            SocketAddress local = to_sockaddr(*local_bind);
            if (bind(socket_fd, reinterpret_cast<sockaddr*>(&local.storage), local.length) != 0) {
                close(socket_fd);
                return ProbeStatus::Inconclusive;
            }
        }

        SocketAddress remote = to_sockaddr(target);
        if (connect(socket_fd, reinterpret_cast<sockaddr*>(&remote.storage), remote.length) != 0) {
            close(socket_fd);
            return ProbeStatus::Inconclusive;
        }

        std::vector<std::uint8_t> payload(2000, 0x5A);
        const ssize_t sent = send(socket_fd, payload.data(), payload.size(), 0);
        if (sent < 0 && errno == EMSGSIZE) {
            close(socket_fd);
            return ProbeStatus::Pass;
        }
        if (sent != static_cast<ssize_t>(payload.size())) {
            close(socket_fd);
            return ProbeStatus::Fail;
        }

        pollfd descriptor{socket_fd, POLLERR, 0};
        const int rc = poll(&descriptor, 1, static_cast<int>(timeout.count()));
        if (rc <= 0 || (descriptor.revents & POLLERR) == 0) {
            close(socket_fd);
            return ProbeStatus::Fail;
        }

        std::array<std::uint8_t, 256> data{};
        std::array<std::uint8_t, 512> control{};
        iovec io{data.data(), data.size()};
        msghdr msg{};
        msg.msg_iov = &io;
        msg.msg_iovlen = 1;
        msg.msg_control = control.data();
        msg.msg_controllen = control.size();
        if (recvmsg(socket_fd, &msg, MSG_ERRQUEUE) < 0) {
            close(socket_fd);
            return ProbeStatus::Fail;
        }

        for (cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
            if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVERR) {
                const auto* error = reinterpret_cast<const sock_extended_err*>(CMSG_DATA(cmsg));
                if (error != nullptr &&
                    error->ee_origin == SO_EE_ORIGIN_ICMP &&
                    error->ee_type == ICMP_DEST_UNREACH &&
                    error->ee_code == ICMP_FRAG_NEEDED) {
                    close(socket_fd);
                    return ProbeStatus::Pass;
                }
            }
        }

        close(socket_fd);
        return ProbeStatus::Fail;
    } catch (...) {
        close(socket_fd);
        return ProbeStatus::Inconclusive;
    }
}

ProbeStatus run_udp_out_of_order_fragment_probe(const IpEndpoint& primary_server,
                                                const std::optional<IpEndpoint>& local_bind,
                                                std::chrono::milliseconds timeout) {
    constexpr std::string_view kOutOfOrderFragmentPayload = "RFC4787-OOO-FRAGMENT\n";
    int socket_fd = socket(primary_server.family, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd < 0) {
        return ProbeStatus::Inconclusive;
    }
    try {
        set_reuse_options(socket_fd);
        IpEndpoint local = local_bind.value_or(wildcard_endpoint(primary_server.family));
        local.port = 0;
        SocketAddress local_address = to_sockaddr(local);
        if (bind(socket_fd, reinterpret_cast<sockaddr*>(&local_address.storage), local_address.length) != 0) {
            close(socket_fd);
            return ProbeStatus::Inconclusive;
        }

        std::optional<std::string> mapping_line = exchange_udp_server_command(socket_fd, primary_server, "M\n", timeout);
        if (!mapping_line.has_value()) {
            close(socket_fd);
            return ProbeStatus::Inconclusive;
        }
        if (!parse_endpoint_line(*mapping_line, primary_server.family).has_value()) {
            close(socket_fd);
            return ProbeStatus::Inconclusive;
        }

        SocketAddress remote = to_sockaddr(primary_server);
        const ssize_t sent = sendto(socket_fd, "O\n", 2, 0, reinterpret_cast<sockaddr*>(&remote.storage), remote.length);
        if (sent != 2) {
            close(socket_fd);
            return ProbeStatus::Fail;
        }

        const auto deadline = std::chrono::steady_clock::now() + timeout;
        bool send_acknowledged = false;
        bool fragmented_payload_received = false;
        while (std::chrono::steady_clock::now() < deadline && (!send_acknowledged || !fragmented_payload_received)) {
            const auto now = std::chrono::steady_clock::now();
            const auto remaining =
                std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
            if (!wait_for_readable(socket_fd, remaining)) {
                break;
            }
            std::array<char, 512> buffer{};
            ssize_t received = recv(socket_fd, buffer.data(), buffer.size(), 0);
            if (received <= 0) {
                continue;
            }
            std::string_view payload(buffer.data(), static_cast<std::size_t>(received));
            if (payload == "O=1\n") {
                send_acknowledged = true;
                continue;
            }
            if (payload == kOutOfOrderFragmentPayload) {
                fragmented_payload_received = true;
            }
        }

        close(socket_fd);
        return (send_acknowledged && fragmented_payload_received) ? ProbeStatus::Pass : ProbeStatus::Fail;
    } catch (...) {
        close(socket_fd);
        return ProbeStatus::Inconclusive;
    }
}

} // namespace

void Rfc4787Test::parseArgs(const std::map<std::string, std::string>& options) {
    constexpr std::uint16_t default_port = 3478;
    auto [stun_host, stun_port] = split_host_port(require_option(options, "--stun_server"), default_port);
    stun_server_ = resolve_endpoint(stun_host, stun_port, SOCK_DGRAM);
    options_.server_name = stun_host;

    std::optional<std::string> primary_opt = find_option(options, "--primary_server");
    std::optional<std::string> secondary_opt = find_option(options, "--secondary_server");

    if (primary_opt.has_value() && secondary_opt.has_value()) {
        // Both manually specified -- use user-provided configuration
        auto [primary_host, primary_port] = split_host_port(*primary_opt, default_port);
        auto [secondary_host, secondary_port] = split_host_port(*secondary_opt, default_port);
        primary_server_ = resolve_endpoint(primary_host, primary_port, SOCK_STREAM, stun_server_.family);
        secondary_server_ = resolve_endpoint(secondary_host, secondary_port, SOCK_STREAM, stun_server_.family);
    } else if (!primary_opt.has_value() && !secondary_opt.has_value()) {
        // Neither specified -- dynamically discover from STUN server via "C" command
        CustomServerConfig config = discover_custom_servers(stun_server_, stun_server_.family);
        primary_server_ = config.primary;
        secondary_server_ = config.secondary;
    } else {
        throw std::runtime_error("错误：--primary_server 和 --secondary_server 必须同时指定或同时省略。");
    }

    if (std::optional<std::string> timeout = find_option(options, "--timeout-ms"); timeout.has_value()) {
        options_.timeout = std::chrono::milliseconds(std::stoi(*timeout));
    }

    test_type_ = parse_rfc4787_test_type(options);
    local_bind_ = parse_local_bind(options, stun_server_.family, SOCK_DGRAM);
}

int Rfc4787Test::runTest() {
    Rfc4787Result result = run_rfc4787_tests(options_, test_type_, stun_server_, primary_server_, secondary_server_, local_bind_);
    print_binding_if_available(result.binding_test_result);
    print_mapping_if_available(result.mapping_behavior);
    if (result.filtering_behavior != FilteringBehavior::Unknown) {
        print_row("FilteringBehavior", to_string(result.filtering_behavior));
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

    // Determinism test (multi-round consistency)
    if (test_type_ == Rfc4787TestType::Determinism || test_type_ == Rfc4787TestType::All) {
        DeterminismCheckResult det = run_determinism_check(options_, stun_server_, local_bind_, 3);
        print_probe_if_available("DeterminismMappingConsistent", det.mapping_consistent);
        print_probe_if_available("DeterminismFilteringConsistent", det.filtering_consistent);
        print_probe_if_available("DeterminismPortRangeConsistent", det.port_range_consistent);
        print_probe_if_available("DeterminismPortParityConsistent", det.port_parity_consistent);
    }

    // Port Overloading test
    if (test_type_ == Rfc4787TestType::PortOverloading || test_type_ == Rfc4787TestType::All) {
        ProbeStatus overloading = run_port_overloading_test(options_, stun_server_,
                                                             primary_server_, secondary_server_, local_bind_);
        print_probe_if_available("PortOverloading", overloading);
    }

    print_row("PublicEnd", endpoint_or_dash(result.public_endpoint));
    print_row("LocalEnd", endpoint_or_dash(result.local_endpoint));
    return 0;
}

void Rfc4787Test::printHelp() const {
    std::cout << "  nat_type_tester_cli rfc4787 --stun_server host[:port] [--primary_server host[:port]] [--secondary_server host[:port]]\n"
              << "                               [--local host[:port]] [--test-type all|mapping|filtering|port-allocation|icmp|fragmentation|determinism|port-overloading] [--timeout-ms 3000]\n"
              << "                               (If --primary_server and --secondary_server are omitted, they will be auto-discovered from the STUN server via \"C\" command.)\n";
}

Rfc4787Result run_rfc4787_tests(const RequestOptions& options,
                                Rfc4787TestType test_type,
                                const IpEndpoint& stun_server,
                                const IpEndpoint& primary_server,
                                const IpEndpoint& secondary_server,
                                const std::optional<IpEndpoint>& local_bind) {
    RequestOptions udp_options = options;
    udp_options.transport = TransportType::Udp;

    Rfc4787Result result;
    const bool run_all = test_type == Rfc4787TestType::All;

    const bool need_binding = run_all || test_type == Rfc4787TestType::PortAllocation || test_type == Rfc4787TestType::Icmp;
    if (need_binding) {
        StunResult5389 binding = run_rfc5780_test(udp_options, StunTestType::Binding, stun_server, local_bind);
        result.binding_test_result = binding.binding_test_result;
        result.public_endpoint = binding.public_endpoint;
        result.local_endpoint = binding.local_endpoint;
    }

    if (run_all || test_type == Rfc4787TestType::Mapping) {
        result.mapping_behavior = run_rfc5780_test(udp_options, StunTestType::Mapping, stun_server, local_bind).mapping_behavior;
    }
    if (run_all || test_type == Rfc4787TestType::Filtering) {
        result.filtering_behavior = run_rfc5780_test(udp_options, StunTestType::Filtering, stun_server, local_bind).filtering_behavior;
    }

    if (run_all || test_type == Rfc4787TestType::PortAllocation) {
        result.port_range_preservation = evaluate_port_range(result.local_endpoint, result.public_endpoint);
        result.port_parity_preservation = run_port_parity_test(options, stun_server, local_bind);
    }

    if (run_all || test_type == Rfc4787TestType::Icmp) {
        result.icmp_error_handling = run_udp_icmp_error_handling_test(options, primary_server, local_bind);
        UdpHairpinningResult hairpinning = run_udp_hairpinning_checks(options, stun_server, local_bind);
        result.udp_hairpinning = hairpinning.connectivity;
        result.udp_hairpinning_source_address = hairpinning.source_address_match;
    }

    if (run_all || test_type == Rfc4787TestType::Fragmentation) {
        constexpr std::size_t payload_size = 2000;
        result.outbound_fragmentation = run_udp_echo_probe(primary_server, local_bind, options.timeout, payload_size);
        result.outbound_df_fragmentation_error = run_udp_df_fragmentation_probe(primary_server, local_bind, options.timeout);
        result.inbound_fragmentation = run_udp_echo_probe(secondary_server, local_bind, options.timeout, payload_size);
        result.out_of_order_fragmentation =
            run_udp_out_of_order_fragment_probe(primary_server, local_bind, options.timeout);
    }

    if (run_all || test_type == Rfc4787TestType::Determinism) {
        DeterminismCheckResult det = run_determinism_check(options, stun_server, local_bind, 3);
        (void)det; // Determinism results are printed by the caller (runTest / print)
    }

    if (run_all || test_type == Rfc4787TestType::PortOverloading) {
        (void)run_port_overloading_test(options, stun_server, primary_server, secondary_server, local_bind);
    }

    return result;
}

// ---- Determinism Check (RFC 4787 REQ-11) ----
DeterminismCheckResult run_determinism_check(const RequestOptions& options,
                                             const IpEndpoint& server,
                                             const std::optional<IpEndpoint>& local_bind,
                                             int rounds) {
    DeterminismCheckResult result;
    result.rounds = rounds;
    if (rounds < 2) rounds = 2;

    // First round as baseline
    StunResult5389 baseline = run_rfc5780_test(options, StunTestType::Combining, server, local_bind);
    ProbeStatus baseline_range = evaluate_port_range(baseline.local_endpoint, baseline.public_endpoint);

    result.mapping_consistent = ProbeStatus::Pass;
    result.filtering_consistent = ProbeStatus::Pass;
    result.port_range_consistent = ProbeStatus::Pass;
    
    // 我们赋予一致性检测同样的严格标准，直接运行10轮测试，结果与 PortParityPreservation 统一
    result.port_parity_consistent = run_port_parity_test(options, server, local_bind);

    for (int i = 0; i < rounds - 1; ++i) {
        StunResult5389 round = run_rfc5780_test(options, StunTestType::Combining, server, local_bind);
        if (round.mapping_behavior != baseline.mapping_behavior) result.mapping_consistent = ProbeStatus::Fail;
        if (round.filtering_behavior != baseline.filtering_behavior) result.filtering_consistent = ProbeStatus::Fail;
        ProbeStatus r_range = evaluate_port_range(round.local_endpoint, round.public_endpoint);
        if (r_range != baseline_range) result.port_range_consistent = ProbeStatus::Fail;
    }
    return result;
}

// ---- Port Overloading Test (RFC 4787 REQ-3) ----
ProbeStatus run_port_overloading_test(const RequestOptions& options,
                                      const IpEndpoint& stun_server,
                                      const IpEndpoint& primary_server,
                                      const IpEndpoint& secondary_server,
                                      const std::optional<IpEndpoint>& local_bind) {
    int sock1 = socket(stun_server.family, SOCK_DGRAM, IPPROTO_UDP);
    int sock2 = socket(stun_server.family, SOCK_DGRAM, IPPROTO_UDP);
    if (sock1 < 0 || sock2 < 0) {
        if (sock1 >= 0) close(sock1);
        if (sock2 >= 0) close(sock2);
        return ProbeStatus::Inconclusive;
    }
    set_reuse_options(sock1);
    set_reuse_options(sock2);
    IpEndpoint bind_addr = local_bind.value_or(wildcard_endpoint(stun_server.family));
    bind_socket(sock1, bind_addr);
    bind_socket(sock2, bind_addr);

    // Get NAT-assigned external endpoints for both sockets
    StunMessage req = create_binding_request(0x2112A442u);
    std::vector<std::uint8_t> payload = serialize(req);

    auto do_request = [&](int fd, const IpEndpoint& target) -> std::optional<IpEndpoint> {
        SocketAddress remote = to_sockaddr(target);
        sendto(fd, payload.data(), payload.size(), 0,
               reinterpret_cast<sockaddr*>(&remote.storage), remote.length);
        if (!wait_for_readable(fd, options.timeout)) return std::nullopt;
        std::array<std::uint8_t, 2048> buf{};
        sockaddr_storage from{};
        socklen_t from_len = sizeof(from);
        ssize_t r = recvfrom(fd, buf.data(), buf.size(), 0,
                             reinterpret_cast<sockaddr*>(&from), &from_len);
        if (r <= 0) return std::nullopt;
        StunMessage msg;
        if (!parse_message(buf.data(), static_cast<std::size_t>(r), msg)) return std::nullopt;
        return get_xor_mapped_address_attribute(msg);
    };

    auto map1 = do_request(sock1, primary_server);
    auto map2 = do_request(sock2, secondary_server);
    close(sock1);
    close(sock2);

    if (!map1.has_value() || !map2.has_value()) return ProbeStatus::Inconclusive;

    bool same_external = (map1->port == map2->port) && same_address(*map1, *map2);
    return same_external ? ProbeStatus::Fail : ProbeStatus::Pass;
}

} // namespace natcli
