#pragma once

#include "stun.hpp"
#include "net_utils.h"

// STUN core utilities header.
//
// All STUN core declarations are made available through the included headers.
//
// From stun.hpp:
//   - Enums: NatType, BindingTestResult, MappingBehavior, FilteringBehavior,
//            ProbeStatus, TransportType, StunTestType
//   - Structs: IpEndpoint, StunAttribute, StunMessage, StunResponse,
//              StunDiscoveryAction, ClassicStunResult, StunResult5389,
//              RequestOptions
//   - Functions:
//       operator==(const IpEndpoint&, const IpEndpoint&)
//       same_address(const IpEndpoint&, const IpEndpoint&)
//       to_string(const IpEndpoint&)
//       to_string(NatType)
//       to_string(BindingTestResult)
//       to_string(MappingBehavior)
//       to_string(FilteringBehavior)
//       to_string(ProbeStatus)
//       to_string(TransportType)
//       to_string(StunTestType)
//       split_host_port, parse_endpoint_literal, resolve_endpoint,
//       wildcard_endpoint
//       create_binding_request, serialize, parse_message
//       get_mapped_address_attribute, get_changed_address_attribute,
//       get_xor_mapped_address_attribute, get_other_address_attribute
//   - Classes: UdpSession, TcpSession
//
// From utils/net_utils.h:
//   - SocketAddress, to_sockaddr, from_sockaddr, socket_local_endpoint
//   - system_error, set_reuse_options, set_socket_timeouts, bind_socket,
//     connect_with_timeout, wait_for_readable

// Cross-module shared STUN test functions (used by multiple RFC test modules)
namespace natcli {
StunResult5389 run_rfc5780_test(const RequestOptions& options,
                                StunTestType test_type,
                                const IpEndpoint& server,
                                const std::optional<IpEndpoint>& local_bind);
} // namespace natcli