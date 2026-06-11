#pragma once

#include "stun.hpp"

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace natcli {

// ---- Socket address helpers ----

struct SocketAddress {
    sockaddr_storage storage{};
    socklen_t length{};
};

SocketAddress to_sockaddr(const IpEndpoint& endpoint);
IpEndpoint from_sockaddr(const sockaddr* address, socklen_t length);
IpEndpoint socket_local_endpoint(int socket_fd);

// ---- Error helpers ----

std::runtime_error system_error(const std::string& message);

// ---- Socket option helpers ----

void set_reuse_options(int socket_fd);
void set_socket_timeouts(int socket_fd, std::chrono::milliseconds timeout);
void bind_socket(int socket_fd, const IpEndpoint& endpoint);
void connect_with_timeout(int socket_fd, const IpEndpoint& remote, std::chrono::milliseconds timeout);

// ---- I/O helpers ----

bool wait_for_readable(int socket_fd, std::chrono::milliseconds timeout);
bool wait_for_error(int socket_fd, std::chrono::milliseconds timeout);
void send_all(int socket_fd, std::string_view payload);
std::string recv_line(int socket_fd, std::chrono::milliseconds timeout);

// ---- Socket state helpers ----

bool disconnect_udp_socket(int socket_fd);
bool is_wildcard_endpoint_address(const IpEndpoint& endpoint);
bool can_connect_udp_from_local_address(const IpEndpoint& local, const IpEndpoint& remote);
IpEndpoint infer_local_source_for_remote(const IpEndpoint& remote);
IpEndpoint select_control_local_endpoint(const IpEndpoint& local, const IpEndpoint& remote);

// ---- Endpoint comparison helpers ----

bool same_endpoint_address(const IpEndpoint& left, const IpEndpoint& right);
ProbeStatus merge_probe_status(ProbeStatus left, ProbeStatus right);

// ---- Checksum helpers ----

std::uint16_t calculate_checksum(const void* data, std::size_t len);
std::uint16_t calculate_udp_checksum_ipv4(const iphdr& ip_header,
                                          const udphdr& udp_header,
                                          const std::uint8_t* payload,
                                          std::size_t payload_len);

// ---- Protocol line parsing helpers ----

std::optional<IpEndpoint> parse_endpoint_line(const std::string& line, int family);
bool parse_flag_response(const std::string& response, char key);

// ---- Custom server topology discovery (C command) ----

struct CustomServerConfig {
    IpEndpoint primary;
    IpEndpoint secondary;
};

/// Discover custom server topology by sending "C" command to the STUN server.
/// Returns the parsed PRIMARY and SECONDARY endpoints.
/// Throws std::runtime_error on timeout or malformed response.
CustomServerConfig discover_custom_servers(const IpEndpoint& stun_server,
                                           int family,
                                           std::chrono::milliseconds timeout = std::chrono::milliseconds(2000),
                                           int max_retries = 3);

} // namespace natcli
