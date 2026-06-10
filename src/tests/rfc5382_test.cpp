#include "rfc5382_test.h"
#include "../utils/hairpin_utils.h"
#include "../utils/stun_utils.h"
#include "../utils/net_utils.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace natcli {
namespace {

// ---- Constants ----

constexpr std::string_view kUdpMappingRequest = "M\n";
constexpr std::string_view kRfc7857UdpProbePayload = "RFC7857-UDP-PROBE\n";
constexpr char kProbeResultFlagKey = 'R';
constexpr std::string_view kHairpinUdpPayload = "RFC-HAIRPIN-UDP\n";
constexpr std::string_view kHairpinIcmpPayload = "RFC-HAIRPIN-ICMP\n";

// ---- Test wrapper helpers ----

std::string require_option(const std::map<std::string, std::string>& options, const std::string& name) {
    auto it = options.find(name);
    if (it == options.end()) throw std::runtime_error("Missing required option: " + name);
    return it->second;
}

std::optional<std::string> find_option(const std::map<std::string, std::string>& options, const std::string& name) {
    auto it = options.find(name);
    if (it == options.end()) return std::nullopt;
    return it->second;
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

// ---- RFC5382 business logic helpers ----

std::pair<bool, bool> parse_filter_line(const std::string& line) {
    std::istringstream stream(line);
    std::string p_field;
    std::string s_field;
    if (!(stream >> p_field >> s_field)) {
        throw std::runtime_error("Invalid filtering response");
    }
    auto parse_flag = [](const std::string& field, const char key) -> bool {
        constexpr std::size_t FLAG_FIELD_SIZE = 3;
        if (field.size() != FLAG_FIELD_SIZE || field[0] != key || field[1] != '=') {
            throw std::runtime_error(std::string("Invalid filtering response field: expected '")
                                     + key + "=<0|1>', got: '" + field + "'");
        }
        const char value = field[2];
        if (value == '1') return true;
        if (value == '0') return false;
        throw std::runtime_error(std::string("Invalid flag value for '")
                                 + key + "': expected '0' or '1', got: '" + value + "'");
    };
    return {parse_flag(p_field, 'P'), parse_flag(s_field, 'S')};
}

std::pair<bool, bool> parse_syn_line(const std::string& line) {
    std::istringstream stream(line);
    std::string immediate_field;
    std::string delayed_field;
    if (!(stream >> immediate_field >> delayed_field)) {
        throw std::runtime_error("Invalid SYN probe response");
    }
    auto parse_flag = [](const std::string& field, const char key) -> bool {
        constexpr std::size_t SYN_FLAG_FIELD_SIZE = 3;
        if (field.size() != SYN_FLAG_FIELD_SIZE || field[0] != key || field[1] != '=') {
            throw std::runtime_error(std::string("Invalid SYN probe response field: expected '")
                                     + key + "=<0|1>', got: '" + field + "'");
        }
        const char value = field[2];
        if (value == '1') return true;
        if (value == '0') return false;
        throw std::runtime_error(std::string("Invalid SYN flag value for '")
                                 + key + "': expected '0' or '1', got: '" + value + "'");
    };
    return {parse_flag(immediate_field, 'I'), parse_flag(delayed_field, 'D')};
}

std::optional<IpEndpoint> request_stun_udp_mapping(int socket_fd,
                                                   const IpEndpoint& stun_server,
                                                   std::chrono::milliseconds timeout) {
    StunMessage request = create_binding_request(0x2112A442u);
    std::vector<std::uint8_t> payload = serialize(request);
    SocketAddress remote = to_sockaddr(stun_server);
    ssize_t sent = sendto(socket_fd,
                          payload.data(),
                          payload.size(),
                          0,
                          reinterpret_cast<sockaddr*>(&remote.storage),
                          remote.length);
    if (sent != static_cast<ssize_t>(payload.size())) {
        return std::nullopt;
    }
    if (!wait_for_readable(socket_fd, timeout)) {
        return std::nullopt;
    }

    std::array<std::uint8_t, 2048> buffer{};
    ssize_t received = recv(socket_fd, buffer.data(), buffer.size(), 0);
    if (received <= 0) {
        return std::nullopt;
    }

    StunMessage response;
    if (!parse_message(buffer.data(), static_cast<std::size_t>(received), response) ||
        response.magic_cookie != request.magic_cookie || response.transaction_id != request.transaction_id) {
        return std::nullopt;
    }

    if (std::optional<IpEndpoint> xor_mapped = get_xor_mapped_address_attribute(response); xor_mapped.has_value()) {
        return xor_mapped;
    }
    return get_mapped_address_attribute(response);
}

std::optional<IpEndpoint> request_stun_tcp_mapping(const IpEndpoint& local_bind,
                                                   const IpEndpoint& stun_server,
                                                   std::chrono::milliseconds timeout,
                                                   std::optional<IpEndpoint>* local_endpoint) {
    int socket_fd = socket(stun_server.family, SOCK_STREAM, IPPROTO_TCP);
    if (socket_fd < 0) {
        return std::nullopt;
    }

    try {
        set_reuse_options(socket_fd);
        bind_socket(socket_fd, local_bind);
        connect_with_timeout(socket_fd, stun_server, timeout);
        *local_endpoint = socket_local_endpoint(socket_fd);

        StunMessage request = create_binding_request(0x2112A442u);
        std::vector<std::uint8_t> payload = serialize(request);
        std::size_t offset = 0;
        while (offset < payload.size()) {
            ssize_t written = send(socket_fd, payload.data() + offset, payload.size() - offset, 0);
            if (written <= 0) {
                close(socket_fd);
                return std::nullopt;
            }
            offset += static_cast<std::size_t>(written);
        }

        std::vector<std::uint8_t> buffer(65536);
        std::size_t received_total = 0;
        while (wait_for_readable(socket_fd, timeout)) {
            ssize_t received = recv(socket_fd, buffer.data() + received_total, buffer.size() - received_total, 0);
            if (received <= 0) {
                break;
            }
            received_total += static_cast<std::size_t>(received);
            StunMessage response;
            if (parse_message(buffer.data(), received_total, response) &&
                response.magic_cookie == request.magic_cookie &&
                response.transaction_id == request.transaction_id) {
                close(socket_fd);
                if (std::optional<IpEndpoint> xor_mapped = get_xor_mapped_address_attribute(response); xor_mapped.has_value()) {
                    return xor_mapped;
                }
                return get_mapped_address_attribute(response);
            }
            if (received_total == buffer.size()) {
                break;
            }
        }
        close(socket_fd);
        return std::nullopt;
    } catch (...) {
        close(socket_fd);
        return std::nullopt;
    }
}

UdpHairpinningResult run_udp_hairpin_probe(const IpEndpoint& stun_server,
                                           const std::optional<IpEndpoint>& local_bind,
                                           std::chrono::milliseconds timeout,
                                           std::optional<IpEndpoint>* public_endpoint) {
    UdpHairpinningResult result;
    int receiver = socket(stun_server.family, SOCK_DGRAM, IPPROTO_UDP);
    int sender = socket(stun_server.family, SOCK_DGRAM, IPPROTO_UDP);
    if (receiver < 0 || sender < 0) {
        if (receiver >= 0) {
            close(receiver);
        }
        if (sender >= 0) {
            close(sender);
        }
        result.connectivity = ProbeStatus::Inconclusive;
        result.source_address_match = ProbeStatus::Inconclusive;
        return result;
    }

    try {
        set_reuse_options(receiver);
        set_reuse_options(sender);
        const IpEndpoint receiver_bind = local_bind.value_or(wildcard_endpoint(stun_server.family));
        bind_socket(receiver, receiver_bind);

        IpEndpoint sender_bind = receiver_bind;
        sender_bind.port = 0;
        bind_socket(sender, sender_bind);

        *public_endpoint = request_stun_udp_mapping(receiver, stun_server, timeout);
        if (!public_endpoint->has_value()) {
            close(receiver);
            close(sender);
            result.connectivity = ProbeStatus::Inconclusive;
            result.source_address_match = ProbeStatus::Inconclusive;
            return result;
        }

        SocketAddress public_receiver = to_sockaddr(**public_endpoint);
        ssize_t sent = sendto(sender,
                              kHairpinUdpPayload.data(),
                              kHairpinUdpPayload.size(),
                              0,
                              reinterpret_cast<sockaddr*>(&public_receiver.storage),
                              public_receiver.length);
        if (sent != static_cast<ssize_t>(kHairpinUdpPayload.size())) {
            close(receiver);
            close(sender);
            result.connectivity = ProbeStatus::Fail;
            result.source_address_match = ProbeStatus::Fail;
            return result;
        }
        if (!wait_for_readable(receiver, timeout)) {
            close(receiver);
            close(sender);
            result.connectivity = ProbeStatus::Fail;
            result.source_address_match = ProbeStatus::Fail;
            return result;
        }

        std::array<char, 256> buffer{};
        sockaddr_storage source{};
        socklen_t source_length = sizeof(source);
        ssize_t received =
            recvfrom(receiver, buffer.data(), buffer.size(), 0, reinterpret_cast<sockaddr*>(&source), &source_length);
        close(receiver);
        close(sender);
        if (received != static_cast<ssize_t>(kHairpinUdpPayload.size())) {
            result.connectivity = ProbeStatus::Fail;
            result.source_address_match = ProbeStatus::Fail;
            return result;
        }
        const std::string_view received_payload(buffer.data(), static_cast<std::size_t>(received));
        result.connectivity = received_payload == kHairpinUdpPayload ? ProbeStatus::Pass : ProbeStatus::Fail;
        const IpEndpoint source_endpoint = from_sockaddr(reinterpret_cast<sockaddr*>(&source), source_length);
        result.source_address_match = same_endpoint_address(source_endpoint, **public_endpoint) ? ProbeStatus::Pass
                                                                                                 : ProbeStatus::Fail;
        return result;
    } catch (...) {
        close(receiver);
        close(sender);
        result.connectivity = ProbeStatus::Inconclusive;
        result.source_address_match = ProbeStatus::Inconclusive;
        return result;
    }
}

TcpHairpinningResult run_tcp_hairpin_probe(const IpEndpoint& stun_server,
                                           const std::optional<IpEndpoint>& local_bind,
                                           std::chrono::milliseconds timeout) {
    TcpHairpinningResult result;
    std::optional<IpEndpoint> mapped_public;
    std::optional<IpEndpoint> mapped_local;
    IpEndpoint mapping_bind = local_bind.value_or(wildcard_endpoint(stun_server.family));
    mapping_bind.port = 0;
    mapped_public = request_stun_tcp_mapping(mapping_bind, stun_server, timeout, &mapped_local);
    if (!mapped_public.has_value() || !mapped_local.has_value()) {
        result.connectivity = ProbeStatus::Inconclusive;
        result.source_address_match = ProbeStatus::Inconclusive;
        return result;
    }

    int listener = socket(stun_server.family, SOCK_STREAM, IPPROTO_TCP);
    if (listener < 0) {
        result.connectivity = ProbeStatus::Inconclusive;
        result.source_address_match = ProbeStatus::Inconclusive;
        return result;
    }

    try {
        set_reuse_options(listener);
        bind_socket(listener, *mapped_local);
        if (listen(listener, 1) != 0) {
            close(listener);
            result.connectivity = ProbeStatus::Inconclusive;
            result.source_address_match = ProbeStatus::Inconclusive;
            return result;
        }

        int connector = socket(stun_server.family, SOCK_STREAM, IPPROTO_TCP);
        if (connector < 0) {
            close(listener);
            result.connectivity = ProbeStatus::Inconclusive;
            result.source_address_match = ProbeStatus::Inconclusive;
            return result;
        }
        set_reuse_options(connector);
        IpEndpoint connector_bind = local_bind.value_or(wildcard_endpoint(stun_server.family));
        connector_bind.port = 0;
        bind_socket(connector, connector_bind);

        result.connectivity = ProbeStatus::Fail;
        result.source_address_match = ProbeStatus::Fail;
        try {
            connect_with_timeout(connector, *mapped_public, timeout);
            if (wait_for_readable(listener, timeout)) {
                sockaddr_storage incoming{};
                socklen_t length = sizeof(incoming);
                int accepted = accept(listener, reinterpret_cast<sockaddr*>(&incoming), &length);
                if (accepted >= 0) {
                    result.connectivity = ProbeStatus::Pass;
                    const IpEndpoint source_endpoint = from_sockaddr(reinterpret_cast<sockaddr*>(&incoming), length);
                    result.source_address_match =
                        same_endpoint_address(source_endpoint, *mapped_public) ? ProbeStatus::Pass : ProbeStatus::Fail;
                    close(accepted);
                }
            }
        } catch (...) {
            result.connectivity = ProbeStatus::Fail;
            result.source_address_match = ProbeStatus::Fail;
        }

        close(connector);
        close(listener);
        return result;
    } catch (...) {
        close(listener);
        result.connectivity = ProbeStatus::Inconclusive;
        result.source_address_match = ProbeStatus::Inconclusive;
        return result;
    }
}

ProbeStatus run_udp_icmp_mapping_validation(const IpEndpoint& stun_server,
                                            const std::optional<IpEndpoint>& local_bind,
                                            std::chrono::milliseconds timeout) {
    int socket_fd = socket(stun_server.family, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd < 0) {
        return ProbeStatus::Inconclusive;
    }
    try {
        set_reuse_options(socket_fd);
        IpEndpoint local = local_bind.value_or(wildcard_endpoint(stun_server.family));
        local.port = 0;
        bind_socket(socket_fd, local);
        std::optional<IpEndpoint> mapped_before = request_stun_udp_mapping(socket_fd, stun_server, timeout);
        if (!mapped_before.has_value()) {
            close(socket_fd);
            return ProbeStatus::Inconclusive;
        }

        auto run_single_error_probe = [&](std::uint16_t port_offset) -> bool {
            IpEndpoint target = *mapped_before;
            target.port = static_cast<std::uint16_t>(target.port + port_offset);
            if (target.port == mapped_before->port) {
                target.port = static_cast<std::uint16_t>(target.port + 1);
            }
            SocketAddress destination = to_sockaddr(target);
            if (connect(socket_fd, reinterpret_cast<sockaddr*>(&destination.storage), destination.length) != 0) {
                return false;
            }
            const ssize_t sent = send(socket_fd, kHairpinIcmpPayload.data(), kHairpinIcmpPayload.size(), 0);
            if (sent != static_cast<ssize_t>(kHairpinIcmpPayload.size())) {
                return false;
            }
            const bool observed_error = wait_for_error(socket_fd, timeout);
            const bool disconnected = disconnect_udp_socket(socket_fd);
            return observed_error && disconnected;
        };

        const bool unreachable_error = run_single_error_probe(1);
        const bool second_unreachable_error = run_single_error_probe(2);
        std::optional<IpEndpoint> mapped_after = request_stun_udp_mapping(socket_fd, stun_server, timeout);
        close(socket_fd);

        if (!unreachable_error || !second_unreachable_error) {
            return ProbeStatus::Fail;
        }
        if (!mapped_after.has_value() || *mapped_after != *mapped_before) {
            return ProbeStatus::Fail;
        }
        return ProbeStatus::Pass;
    } catch (...) {
        close(socket_fd);
        return ProbeStatus::Inconclusive;
    }
}

ProbeStatus run_tcp_icmp_mapping_validation(const IpEndpoint& stun_server,
                                            const IpEndpoint& primary_server,
                                            const std::optional<IpEndpoint>& local_bind,
                                            std::chrono::milliseconds timeout) {
    int control = socket(primary_server.family, SOCK_STREAM, IPPROTO_TCP);
    if (control < 0) {
        return ProbeStatus::Inconclusive;
    }

    try {
        set_reuse_options(control);
        bind_socket(control, local_bind.value_or(wildcard_endpoint(primary_server.family)));
        connect_with_timeout(control, primary_server, timeout);
        send_all(control, "M\n");
        std::optional<IpEndpoint> mapped_before = parse_endpoint_line(recv_line(control, timeout), primary_server.family);
        if (!mapped_before.has_value()) {
            close(control);
            return ProbeStatus::Inconclusive;
        }

        IpEndpoint local_tcp = socket_local_endpoint(control);
        IpEndpoint local_ip_only = local_tcp;
        local_ip_only.port = 0;
        ProbeStatus icmp_status = run_udp_icmp_mapping_validation(stun_server, local_ip_only, timeout);
        if (icmp_status != ProbeStatus::Pass) {
            close(control);
            return icmp_status == ProbeStatus::Fail ? ProbeStatus::Fail : ProbeStatus::Inconclusive;
        }

        send_all(control, "M\n");
        std::optional<IpEndpoint> mapped_after = parse_endpoint_line(recv_line(control, timeout), primary_server.family);
        close(control);
        if (!mapped_after.has_value() || *mapped_after != *mapped_before) {
            return ProbeStatus::Fail;
        }
        return ProbeStatus::Pass;
    } catch (...) {
        close(control);
        return ProbeStatus::Inconclusive;
    }
}

ProbeStatus run_server_assisted_udp_icmp_test(const IpEndpoint& primary_server,
                                              const std::optional<IpEndpoint>& local_bind,
                                              std::chrono::milliseconds timeout) {
    int socket_fd = socket(primary_server.family, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd < 0) {
        return ProbeStatus::Inconclusive;
    }
    try {
        set_reuse_options(socket_fd);
        IpEndpoint local = local_bind.value_or(wildcard_endpoint(primary_server.family));
        local.port = 0;
        bind_socket(socket_fd, local);

        SocketAddress remote = to_sockaddr(primary_server);

        auto exchange = [&](std::string_view req) -> std::string {
            sendto(socket_fd, req.data(), req.size(), 0, reinterpret_cast<sockaddr*>(&remote.storage), remote.length);
            if (!wait_for_readable(socket_fd, timeout)) return "";
            std::array<char, 256> buf{};
            ssize_t rx = recv(socket_fd, buf.data(), buf.size() - 1, 0);
            if (rx <= 0) return "";
            buf[static_cast<std::size_t>(rx)] = '\0';
            return std::string(buf.data());
        };

        // 1. Get baseline mapping
        std::string baseline = exchange("M\n");
        std::optional<IpEndpoint> mapped_before = parse_endpoint_line(baseline, primary_server.family);
        if (!mapped_before.has_value()) { close(socket_fd); return ProbeStatus::Inconclusive; }

        // 2. Send I command to have server inject ICMP error packet
        std::string icmp_resp = exchange("I\n");
        if (icmp_resp != "I=1\n") { close(socket_fd); return ProbeStatus::Fail; }

        // 3. Wait for NAT processing
        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        // 4. Re-verify mapping, testing REQ-12
        std::string after = exchange("M\n");
        if (after.empty()) {
            close(socket_fd);
            return ProbeStatus::Fail;
        }

        std::optional<IpEndpoint> mapped_after = parse_endpoint_line(after, primary_server.family);
        close(socket_fd);

        if (!mapped_after.has_value() || *mapped_after != *mapped_before) {
            return ProbeStatus::Fail;
        }
        return ProbeStatus::Pass;
    } catch (...) {
        close(socket_fd);
        return ProbeStatus::Inconclusive;
    }
}

ProbeStatus run_server_assisted_tcp_icmp_test(const IpEndpoint& primary_server,
                                              const std::optional<IpEndpoint>& local_bind,
                                              std::chrono::milliseconds timeout) {
    int control = socket(primary_server.family, SOCK_STREAM, IPPROTO_TCP);
    if (control < 0) {
        return ProbeStatus::Inconclusive;
    }

    try {
        set_reuse_options(control);
        bind_socket(control, local_bind.value_or(wildcard_endpoint(primary_server.family)));
        connect_with_timeout(control, primary_server, timeout);

        // 1. Get baseline mapping
        send_all(control, "M\n");
        std::optional<IpEndpoint> mapped_before = parse_endpoint_line(recv_line(control, timeout), primary_server.family);
        if (!mapped_before.has_value()) { close(control); return ProbeStatus::Inconclusive; }

        // 2. Trigger server to send ICMP error with TCP 5-tuple
        send_all(control, "I\n");
        std::string i_resp = recv_line(control, timeout);
        if (i_resp != "I=1") { close(control); return ProbeStatus::Fail; }

        // 3. Wait for NAT processing
        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        // 4. Verify TCP connection still alive, testing REQ-10
        std::optional<IpEndpoint> mapped_after;
        try {
            send_all(control, "M\n");
            mapped_after = parse_endpoint_line(recv_line(control, timeout), primary_server.family);
        } catch (...) {
            close(control);
            return ProbeStatus::Fail;
        }

        close(control);
        if (!mapped_after.has_value() || *mapped_after != *mapped_before) {
            return ProbeStatus::Fail;
        }
        return ProbeStatus::Pass;
    } catch (...) {
        close(control);
        return ProbeStatus::Fail;
    }
}

std::string request_tcp_command(const IpEndpoint& local,
                                const IpEndpoint& server,
                                std::string_view command,
                                std::chrono::milliseconds timeout) {
    int control = socket(server.family, SOCK_STREAM, IPPROTO_TCP);
    if (control < 0) {
        throw system_error("socket failed");
    }
    try {
        set_reuse_options(control);

        // Configure SO_LINGER to send RST on close, skipping TIME_WAIT
        linger sl{1, 0};
        setsockopt(control, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));

        bind_socket(control, local);
        connect_with_timeout(control, server, timeout);
        send_all(control, command);
        std::string line = recv_line(control, timeout);
        close(control);
        return line;
    } catch (...) {
        close(control);
        throw;
    }
}

std::optional<IpEndpoint> request_udp_mapping(const IpEndpoint& local, const IpEndpoint& server, std::chrono::milliseconds timeout) {
    int socket_fd = socket(server.family, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd < 0) {
        throw system_error("socket failed");
    }

    try {
        set_reuse_options(socket_fd);
        bind_socket(socket_fd, local);
        SocketAddress remote = to_sockaddr(server);
        ssize_t sent = sendto(socket_fd, kUdpMappingRequest.data(), kUdpMappingRequest.size(), 0,
                              reinterpret_cast<sockaddr*>(&remote.storage), remote.length);
        if (sent <= 0) {
            throw system_error("sendto failed");
        }
        if (!wait_for_readable(socket_fd, timeout)) {
            close(socket_fd);
            return std::nullopt;
        }
        std::array<char, 256> buffer{};
        ssize_t received = recv(socket_fd, buffer.data(), buffer.size() - 1, 0);
        if (received <= 0) {
            close(socket_fd);
            return std::nullopt;
        }
        buffer[static_cast<std::size_t>(received)] = '\0';
        close(socket_fd);
        return parse_endpoint_line(std::string(buffer.data()), server.family);
    } catch (...) {
        close(socket_fd);
        throw;
    }
}

std::optional<bool> probe_tcp_mapping_allows_udp(const IpEndpoint& local,
                                                 const IpEndpoint& server,
                                                 std::chrono::milliseconds timeout) {
    int socket_fd = socket(server.family, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd < 0) {
        throw system_error("socket failed");
    }

    try {
        set_reuse_options(socket_fd);
        bind_socket(socket_fd, local);
        const bool server_probe_sent =
            parse_flag_response(request_tcp_command(local, server, "U\n", timeout), kProbeResultFlagKey);
        if (!server_probe_sent) {
            close(socket_fd);
            return std::nullopt;
        }

        if (!wait_for_readable(socket_fd, timeout)) {
            close(socket_fd);
            return false;
        }

        std::array<char, 256> buffer{};
        ssize_t received = recv(socket_fd, buffer.data(), buffer.size(), 0);
        close(socket_fd);
        if (received <= 0) {
            return false;
        }
        const std::string_view received_payload(buffer.data(), static_cast<std::size_t>(received));
        return received_payload == kRfc7857UdpProbePayload;
    } catch (...) {
        close(socket_fd);
        throw;
    }
}

std::optional<bool> probe_udp_mapping_allows_tcp(const IpEndpoint& local,
                                                 const IpEndpoint& server,
                                                 std::chrono::milliseconds timeout) {
    int udp_socket = socket(server.family, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_socket < 0) {
        throw system_error("socket failed");
    }

    try {
        set_reuse_options(udp_socket);
        bind_socket(udp_socket, local);

        SocketAddress remote = to_sockaddr(server);
        ssize_t sent = sendto(udp_socket, kUdpMappingRequest.data(), kUdpMappingRequest.size(), 0,
                              reinterpret_cast<sockaddr*>(&remote.storage), remote.length);
        if (sent <= 0) {
            throw system_error("sendto failed");
        }
        if (!wait_for_readable(udp_socket, timeout)) {
            close(udp_socket);
            return std::nullopt;
        }
        std::array<char, 256> buffer{};
        ssize_t received = recv(udp_socket, buffer.data(), buffer.size() - 1, 0);
        if (received <= 0) {
            close(udp_socket);
            return std::nullopt;
        }
        buffer[static_cast<std::size_t>(received)] = '\0';
        std::optional<IpEndpoint> udp_public = parse_endpoint_line(std::string(buffer.data()), server.family);
        if (!udp_public.has_value()) {
            close(udp_socket);
            return std::nullopt;
        }

        const std::string command = "C " + to_string(*udp_public) + "\n";
        const bool tcp_probe_connected =
            parse_flag_response(request_tcp_command(local, server, command, timeout), kProbeResultFlagKey);
        close(udp_socket);
        return tcp_probe_connected;
    } catch (...) {
        close(udp_socket);
        throw;
    }
}

} // namespace

// ---- RFC5382 wrapper functions (natcli scope) ----

ProbeStatus run_udp_hairpinning_test(const RequestOptions& options,
                                     const IpEndpoint& stun_server,
                                     const std::optional<IpEndpoint>& local_bind) {
    return run_udp_hairpinning_checks(options, stun_server, local_bind).connectivity;
}

UdpHairpinningResult run_udp_hairpinning_checks(const RequestOptions& options,
                                                const IpEndpoint& stun_server,
                                                const std::optional<IpEndpoint>& local_bind) {
    std::optional<IpEndpoint> udp_public_endpoint;
    return run_udp_hairpin_probe(stun_server, local_bind, options.timeout, &udp_public_endpoint);
}

ProbeStatus run_tcp_hairpinning_test(const RequestOptions& options,
                                     const IpEndpoint& stun_server,
                                     const std::optional<IpEndpoint>& local_bind) {
    return run_tcp_hairpinning_checks(options, stun_server, local_bind).connectivity;
}

TcpHairpinningResult run_tcp_hairpinning_checks(const RequestOptions& options,
                                                const IpEndpoint& stun_server,
                                                const std::optional<IpEndpoint>& local_bind) {
    return run_tcp_hairpin_probe(stun_server, local_bind, options.timeout);
}

ProbeStatus run_udp_icmp_error_handling_test(const RequestOptions& options,
                                             const IpEndpoint& primary_server,
                                             const std::optional<IpEndpoint>& local_bind) {
    return run_server_assisted_udp_icmp_test(primary_server, local_bind, options.timeout);
}

ProbeStatus run_tcp_icmp_error_handling_test(const RequestOptions& options,
                                             const IpEndpoint& primary_server,
                                             const std::optional<IpEndpoint>& local_bind) {
    return run_server_assisted_tcp_icmp_test(primary_server, local_bind, options.timeout);
}

ProbeStatus run_rfc7857_cross_protocol_icmp_error_test(const RequestOptions& options,
                                              const IpEndpoint& stun_server,
                                              const IpEndpoint& primary_server,
                                              const std::optional<IpEndpoint>& local_bind) {
    ProbeStatus udp_status = run_udp_icmp_error_handling_test(options, primary_server, local_bind);
    ProbeStatus tcp_status = run_tcp_icmp_error_handling_test(options, primary_server, local_bind);
    return merge_probe_status(udp_status, tcp_status);
}

// ---- Rfc5382Test class methods ----

void Rfc5382Test::parseArgs(const std::map<std::string, std::string>& options) {
    constexpr std::uint16_t default_port = 3478;
    auto [stun_host, stun_port] = split_host_port(require_option(options, "--stun_server"), default_port);
    stun_server_ = resolve_endpoint(stun_host, stun_port, SOCK_DGRAM);
    options_.server_name = stun_host;

    auto [primary_host, primary_port] = split_host_port(require_option(options, "--primary_server"), default_port);
    auto [secondary_host, secondary_port] = split_host_port(require_option(options, "--secondary_server"), default_port);
    primary_server_ = resolve_endpoint(primary_host, primary_port, SOCK_STREAM, stun_server_.family);
    secondary_server_ = resolve_endpoint(secondary_host, secondary_port, SOCK_STREAM, stun_server_.family);

    if (std::optional<std::string> timeout = find_option(options, "--timeout-ms"); timeout.has_value()) {
        options_.timeout = std::chrono::milliseconds(std::stoi(*timeout));
    }

    test_type_str_ = find_option(options, "--test-type").value_or("all");
    local_bind_ = parse_local_bind(options, stun_server_.family, SOCK_STREAM);
}

int Rfc5382Test::runTest() {
    StunResult5389 mapping_result = run_rfc5780_test(options_, StunTestType::Mapping, stun_server_, local_bind_);
    Rfc5382TcpResult server_result = run_rfc5382_tests(options_, stun_server_, primary_server_, secondary_server_, local_bind_);

    const std::string& tt = test_type_str_;
    bool all = (tt == "all");
    bool mapping = all || (tt == "mapping");
    bool filtering = all || (tt == "filtering");
    bool simopen = all || (tt == "simultaneous-open");
    bool unexpected = all || (tt == "unexpected-syn");
    bool icmp = all || (tt == "icmp");

    if (mapping) {
        print_row("MappingBehavior", to_string(mapping_result.mapping_behavior));
        print_row("UdpPublicEnd", endpoint_or_dash(mapping_result.public_endpoint));
    }
    if (filtering) {
        print_row("FilteringBehavior", to_string(server_result.filtering_behavior));
        print_row("TcpPublicEnd", endpoint_or_dash(server_result.tcp_public_endpoint));
    }
    if (simopen) {
        print_row("TcpSimultaneousOpen", to_string(server_result.simultaneous_open));
    }
    if (unexpected) {
        print_row("UnexpectedSynHandling", to_string(server_result.unexpected_syn));
    }
    if (icmp) {
        print_row("IcmpErrorHandling", to_string(server_result.icmp_error_handling));
        print_row("TcpHairpinning", to_string(server_result.tcp_hairpinning));
        print_row("TcpHairpinningSourceAddress", to_string(server_result.tcp_hairpinning_source_address));
    }
    print_row("LocalEnd", endpoint_or_dash(server_result.local_endpoint));
    return 0;
}

void Rfc5382Test::printHelp() const {
    std::cout << "  nat_type_tester_cli rfc5382 --stun_server host[:port] --primary_server host[:port] --secondary_server host[:port]\n"
              << "                               [--local host[:port]] [--test-type all|mapping|filtering|simultaneous-open|unexpected-syn|icmp] [--timeout-ms 3000]\n";
}

Rfc5382TcpResult run_rfc5382_tests(const RequestOptions& options,
                                   const IpEndpoint& stun_server,
                                   const IpEndpoint& primary_server,
                                   const IpEndpoint& secondary_server,
                                   const std::optional<IpEndpoint>& local_bind) {
    if (primary_server.family != secondary_server.family) {
        throw std::runtime_error("Primary and secondary server must use the same IP family.");
    }

    int listener = socket(primary_server.family, SOCK_STREAM, IPPROTO_TCP);
    if (listener < 0) {
        throw system_error("socket failed");
    }

    Rfc5382TcpResult result;
    try {
        set_reuse_options(listener);
        bind_socket(listener, local_bind.value_or(wildcard_endpoint(primary_server.family)));
        if (listen(listener, 8) != 0) {
            throw system_error("listen failed");
        }
        result.local_endpoint = socket_local_endpoint(listener);
        IpEndpoint control_local = select_control_local_endpoint(*result.local_endpoint, primary_server);
        result.local_endpoint = control_local;

        result.tcp_public_endpoint =
            parse_endpoint_line(request_tcp_command(control_local, primary_server, "M\n", options.timeout), primary_server.family);

        if (result.local_endpoint.has_value()) {
            result.udp_public_endpoint = request_udp_mapping(*result.local_endpoint, primary_server, options.timeout);
        }

        auto [primary_ok, secondary_ok] = parse_filter_line(
            request_tcp_command(control_local, primary_server, "F\n", options.timeout));
        result.primary_probe_success = primary_ok;
        result.secondary_probe_success = secondary_ok;
        if (secondary_ok) {
            result.filtering_behavior = FilteringBehavior::EndpointIndependent;
        } else if (primary_ok) {
            result.filtering_behavior = FilteringBehavior::AddressDependent;
        } else {
            result.filtering_behavior = FilteringBehavior::AddressAndPortDependent;
        }
        auto [immediate_ok, delayed_ok] =
            parse_syn_line(request_tcp_command(control_local, primary_server, "S\n", options.timeout));
        result.simultaneous_open = immediate_ok ? ProbeStatus::Pass : ProbeStatus::Fail;
        result.unexpected_syn = delayed_ok ? ProbeStatus::Pass : ProbeStatus::Fail;
        result.icmp_error_handling = run_tcp_icmp_error_handling_test(options, primary_server, local_bind);
        TcpHairpinningResult tcp_hairpinning = run_tcp_hairpinning_checks(options, stun_server, local_bind);
        result.tcp_hairpinning = tcp_hairpinning.connectivity;
        result.tcp_hairpinning_source_address = tcp_hairpinning.source_address_match;
        if (result.local_endpoint.has_value()) {
            result.tcp_mapping_allows_udp =
                probe_tcp_mapping_allows_udp(*result.local_endpoint, primary_server, options.timeout);
            result.udp_mapping_allows_tcp =
                probe_udp_mapping_allows_tcp(*result.local_endpoint, primary_server, options.timeout);
        }

        constexpr int max_drain_accepts = 4;
        for (int index = 0; index < max_drain_accepts; ++index) {
            if (!wait_for_readable(listener, std::chrono::milliseconds(100))) {
                break;
            }
            sockaddr_storage incoming{};
            socklen_t length = sizeof(incoming);
            int accepted = accept(listener, reinterpret_cast<sockaddr*>(&incoming), &length);
            if (accepted >= 0) {
                close(accepted);
            }
        }

        close(listener);
        return result;
    } catch (...) {
        close(listener);
        throw;
    }
}

} // namespace natcli
