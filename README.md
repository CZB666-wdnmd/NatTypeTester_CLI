# NatTypeTester_CLI

## RFC

- [RFC 3489](https://datatracker.ietf.org/doc/html/rfc3489)
- [RFC 5780](https://datatracker.ietf.org/doc/html/rfc5780)
- [RFC 8489](https://datatracker.ietf.org/doc/html/rfc8489)
- [RFC 5382](https://datatracker.ietf.org/doc/html/rfc5382)
- [RFC 7857](https://datatracker.ietf.org/doc/html/rfc7857)

## Internet Protocol

- [x] IPv4
- [x] IPv6

## Transmission Protocol

- [x] UDP
- [x] TCP
- [x] TLS-over-TCP
- [ ] DTLS-over-UDP

## RFC3489

<details>

![](docs/img/RFC3489.png)

</details>

## RFC5389

### Binding Test

<details>
  <summary>Checking for UDP Connectivity with the STUN Server</summary>

![](docs/img/RFC5780_4.2.png)

</details>

### Mapping Behavior

<details>
  <summary>Determining NAT Mapping Behavior</summary>

![](docs/img/RFC5780_4.3.png)

</details>

### Filtering Behavior

<details>
  <summary>Determining NAT Filtering Behavior</summary>

![](docs/img/RFC5780_4.4.png)

</details>

### Combining Tests

<details>

![](docs/img/RFC5780_4.5.png)

</details>

## CLI Usage

```text
nat_type_tester_cli rfc3489 --stun_server host[:port] [--local host[:port]] [--timeout-ms 3000]
nat_type_tester_cli rfc5780 --stun_server host[:port] [--local host[:port]] [--transport udp|tcp|tls]
                             [--test-type combining|binding|mapping|filtering] [--skip-cert 0|1] [--timeout-ms 3000]
nat_type_tester_cli rfc4787 --stun_server host[:port] --primary_server host[:port] --secondary_server host[:port]
                             [--local host[:port]] [--test-type all|mapping|filtering|port-allocation|icmp|fragmentation] [--timeout-ms 3000]
nat_type_tester_cli rfc5382 --stun_server host[:port] --primary_server host[:port] --secondary_server host[:port]
                             [--local host[:port]] [--test-type all|mapping|filtering|simultaneous-open|unexpected-syn|icmp] [--timeout-ms 3000]
nat_type_tester_cli rfc7857 --stun_server host[:port] --primary_server host[:port] --secondary_server host[:port]
                             [--local host[:port]] [--timeout-ms 3000]
```

## RFC5382 / RFC4787 / RFC7857 server

标准 STUN 服务端通常不支持部分非 STUN 探测，因此仓库提供双 IP 服务端（`src_ser`）。

- 构建服务端：
  - `cmake -S src_ser -B src_ser/build`
  - `cmake --build src_ser/build`
- 启动服务端：
  - `./src_ser/build/nat_type_tester_rfc5382_server --primary 1.2.3.4:3478 --secondary 5.6.7.8:3478`
- 运行客户端测试：
  - `./src/build/nat_type_tester_cli rfc4787 --stun_server stun.example.com:3478 --primary_server 1.2.3.4:3478 --secondary_server 5.6.7.8:3478`
  - `./src/build/nat_type_tester_cli rfc5382 --stun_server stun.example.com:3478 --primary_server 1.2.3.4:3478 --secondary_server 5.6.7.8:3478`
  - `./src/build/nat_type_tester_cli rfc7857 --stun_server stun.example.com:3478 --primary_server 1.2.3.4:3478 --secondary_server 5.6.7.8:3478`
