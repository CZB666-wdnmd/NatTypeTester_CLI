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

## RFC5382 / RFC7857 (TCP Filtering & Protocol Correlation)

标准 STUN 服务端通常不支持 TCP 过滤行为探测，因此仓库新增了一个简易双 IP 服务端（`src_ser`）。

- 构建服务端：
  - `cmake -S src_ser -B src_ser/build`
  - `cmake --build src_ser/build`
- 启动服务端：
  - `./src_ser/build/nat_type_tester_rfc5382_server --primary 1.2.3.4:3478 --secondary 5.6.7.8:3478`
- 运行客户端测试：
  - `./build/nat_type_tester_cli rfc5780 --server 1.2.3.4:3478 --server2 5.6.7.8:3478 --test-type tcp-filtering --transport tcp`
  - `./build/nat_type_tester_cli rfc5780 --server 1.2.3.4:3478 --server2 5.6.7.8:3478 --test-type protocol-correlation --transport tcp`
