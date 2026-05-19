# NatTypeTester_CLI

一个基于 C++ 的 NAT 行为测试命令行工具，覆盖：

- RFC 3489（经典 NAT Type）
- RFC 5780 / RFC 5389 / RFC 8489 体系下的 Binding / Mapping / Filtering 行为探测
- RFC 4787（UDP NAT 行为要求）
- RFC 5382（TCP NAT 行为要求）
- RFC 7857（NAT 行为的一致性与协议独立性）

项目提供两部分：

- `src`：CLI 客户端与测试逻辑
- `src_ser`：用于 RFC4787 / RFC5382 / RFC7857 的双 IP 自定义探测服务端

---

## 1. 支持能力

### 协议支持

- [x] IPv4
- [ ] IPv6（未测试）

### 传输支持

- [x] UDP
- [x] TCP
- [x] TLS-over-TCP
- [ ] DTLS-over-UDP

---

## 2. 构建与测试

### 2.1 构建客户端（`src`）

```bash
cmake -S src -B src/build
cmake --build src/build
```

### 2.2 运行客户端单元测试

```bash
ctest --test-dir src/build --output-on-failure
```

### 2.3 构建 RFC5382 扩展服务端（`src_ser`）

```bash
cmake -S src_ser -B src_ser/build
cmake --build src_ser/build
```

---

## 3. CLI 用法

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

说明：

- `--stun_server` 默认端口 `3478`
- `--local` 可选；用于指定本地绑定地址/端口
- `--timeout-ms` 默认 `3000`
- `rfc5780 --transport tls` 时，可用 `--skip-cert 1` 跳过证书校验（测试环境用）

---

## 4. 测试前置条件

### 4.1 仅 STUN 即可的测试

- `rfc3489`
- `rfc5780`

只需要一个支持相应属性的 STUN 服务。

### 4.2 需要双 IP 自定义服务端的测试

- `rfc4787`
- `rfc5382`
- `rfc7857`

原因：这三类测试包含“非标准 STUN 回路”与“主动回连探测”，普通公网 STUN 服务器不提供该能力。

启动方式示例：

```bash
./src_ser/build/nat_type_tester_rfc5382_server \
  --primary 1.2.3.4:3478 \
  --secondary 5.6.7.8:3478
```

再执行客户端：

```bash
./src/build/nat_type_tester_cli rfc5382 \
  --stun_server stun.example.com:3478 \
  --primary_server 1.2.3.4:3478 \
  --secondary_server 5.6.7.8:3478
```

要求：

- `primary` 与 `secondary` 必须是同地址族（同为 IPv4 或同为 IPv6）
- 服务端两个地址都要可达

---

## 5. 测试原理（按子命令）

## 5.1 `rfc3489`：经典 NAT Type 分类

实现是 RFC3489 的状态机流程（Test I / II / I(2) / III）：

1. Test I：普通 Binding 请求，拿到 `MappedAddress` 和 `ChangedAddress`
2. Test II：带 change-ip + change-port 的请求
3. 若 Test II 失败，继续对 ChangedAddress 做 Test I(2)
4. 再按响应路径进入 Test III

最终归类为：

- `OpenInternet`
- `SymmetricUdpFirewall`
- `FullCone`
- `RestrictedCone`
- `PortRestrictedCone`
- `Symmetric`
- 或 `UdpBlocked` / `UnsupportedServer` / `Unknown`

> 注意：RFC3489 的“锥形 NAT 类型”属于历史分类，现代 NAT 行为建议结合 RFC5780/4787/5382 结果一起看。

## 5.2 `rfc5780`：Binding / Mapping / Filtering 行为

### Binding（连通性）

发送标准 Binding 请求：

- 收到并成功解析 XOR-MAPPED-ADDRESS → `Success`
- 收到响应但属性不完整 → `UnsupportedServer`
- 超时无响应 → `Fail`

### Mapping（映射行为）

使用 `OTHER-ADDRESS` 引导到不同目标地址/端口进行多轮绑定请求，比较外网映射是否变化：

- `Direct`：外网映射等于本地地址（无 NAT）
- `EndpointIndependent`：目标变化，外网映射不变
- `AddressDependent`：目标 IP 变化时变，端口变化不变
- `AddressAndPortDependent`：目标 IP/端口变化都可能导致映射变化
- `Fail` / `UnsupportedServer`

### Filtering（过滤行为，UDP）

通过 CHANGE-REQUEST 让服务器从不同地址/端口回包，观察 NAT 是否放行：

- `EndpointIndependent`
- `AddressDependent`
- `AddressAndPortDependent`
- `UnsupportedServer`

### Combining

- UDP：一次流程给出 Binding + Mapping + Filtering
- TCP/TLS：实现上只给 Mapping（Filtering 返回 `None`，因为 RFC5780 过滤探测定义在 UDP）

## 5.3 `rfc4787`：UDP NAT 行为要求

`rfc4787` 在实现上复用 RFC5780 的 UDP 能力，再补充 4787 相关探针：

- `mapping`：直接调用 RFC5780 Mapping
- `filtering`：直接调用 RFC5780 Filtering
- `port-allocation`：
  - `PortRangePreservation`：内外端口是否同属于“特权端口(<=1023)/非特权端口”区间
  - `PortParityPreservation`：内外端口奇偶性是否保持
- `fragmentation`：向 `primary/secondary` 发送 2000 字节 UDP 负载并等待回显
  - `OutboundFragmentation` / `InboundFragmentation` 用 Pass/Fail 表示
- `icmp`：当前实现返回 `Inconclusive`

尚未实现的检测:
- [ ] REQ-2：如果 NAT 有多个公网 IP，推荐（RECOMMENDED）使用“成对（Paired）”的 IP 地址池行为。
- [ ] REQ-5：NAT 的 UDP 映射超时时间绝不能（MUST NOT）小于 2 分钟，推荐默认超时时间为 5 分钟或以上。
- [ ] REQ-6：NAT 必须（MUST）在有“出站（Outbound）”流量时刷新超时定时器。
- [ ] REQ-12：接收到 ICMP 错误消息绝不能（MUST NOT）导致 NAT 销毁映射。

## 5.4 `rfc5382`：TCP NAT 行为要求

`rfc5382` 的实现由两部分组成：

1. 使用 `rfc5780 mapping`（UDP）提供映射参考（`UdpPublicEnd`）
2. 通过 `src_ser` 的 TCP 控制命令执行主动探测

服务端控制命令：

- `M`：返回服务器看到的客户端 TCP 公网端点（`TcpPublicEnd`）
- `F`：服务端从 primary/secondary 主动回连客户端，返回 `P=0/1 S=0/1`
- `S`：执行“立即 + 延迟”两次 SYN 回连，返回 `I=0/1 D=0/1`

结果判定：

- `FilteringBehavior`
  - `S=1` → `EndpointIndependent`
  - `P=1,S=0` → `AddressDependent`
  - `P=0,S=0` → `AddressAndPortDependent`
- `TcpSimultaneousOpen`
  - `I=1` → `Pass`，否则 `Fail`
- `UnexpectedSynHandling`
  - `D=1` → `Pass`，否则 `Fail`
- `IcmpErrorHandling`
  - 当前实现返回 `Inconclusive`

尚未实现的检测:
- [ ] REQ-5：对于已建立（Established）的 TCP 连接，NAT 的空闲超时时间不得少于 2 小时 4 分钟。对于过渡状态，超时时间不得少于 4 分钟。
- [ ] REQ-9：NAT 应该翻译 ICMP 目标不可达消息。
- [ ] REQ-10：收到任何类型的 ICMP 消息，NAT 都“绝对不能”终结 TCP 连接或删掉映射。

## 5.5 `rfc7857`：跨协议一致性（UDP + TCP）

`rfc7857` 组合以下结果：

- UDP Mapping：来自 RFC5780 Mapping
- UDP Filtering：来自 RFC5780 Filtering
- TCP Filtering：来自 RFC5382

并计算三项一致性：

- `EimProtocolIndependence`
  - 若 `UdpPublicEnd == TcpPublicEnd` → `Pass`
  - 否则 `Fail`
- `EifProtocolIndependence`
  - UDP/TCP Filtering 都是 `EndpointIndependent` → `Pass`
  - 否则 `Fail`
- `PortParityPreservation`
  - 本地端口与 UDP/TCP 外网端口奇偶都一致 → `Pass`
  - 否则 `Fail`

尚未实现的检测:
- [ ] TCP 会话跟踪
- [ ] EIF 映射刷新与出站错误包

## 5.6 没有计划实现的检测
IP地址池
ALG应用层网关
Hairpinning

---

## 6. 输出字段解释（结果怎么看）

下表是 CLI 常见输出键含义：

- `NatType`：RFC3489 经典 NAT 分类
- `BindingTest`：基础连通性结果（Success/Fail/UnsupportedServer）
- `MappingBehavior`：映射行为
- `FilteringBehavior`：过滤行为
- `PortRangePreservation`：端口区间保持性
- `PortParityPreservation`：端口奇偶保持性
- `OutboundFragmentation` / `InboundFragmentation`：UDP 分片方向性探测
- `TcpSimultaneousOpen`：TCP 同时打开能力
- `UnexpectedSynHandling`：异常/延迟 SYN 处理能力
- `IcmpErrorHandling`：ICMP 错误处理（当前多为 Inconclusive）
- `UdpMappingBehavior` / `UdpFilteringBehavior` / `TcpFilteringBehavior`：RFC7857 汇总字段
- `EimProtocolIndependence`：EIM 跨协议独立性
- `EifProtocolIndependence`：EIF 跨协议独立性
- `PublicEnd` / `UdpPublicEnd` / `TcpPublicEnd`：外网观测端点
- `LocalEnd`：本地使用端点
- `OtherEnd`：STUN 返回的 OTHER-ADDRESS

### 枚举值语义

- `EndpointIndependent`：与目标端无关（最宽松）
- `AddressDependent`：与目标 IP 相关
- `AddressAndPortDependent`：与目标 IP+端口都相关（最严格）
- `Direct`：无 NAT（映射即本地）
- `UnsupportedServer`：服务端能力不足，无法完成该测试
- `Inconclusive`：结论不足（未实现或探测条件不足）

---

## 7. 结果解读建议

1. 不要只看一个字段，至少联合看：
   - `MappingBehavior`
   - `FilteringBehavior`
   - `TcpSimultaneousOpen` / `UnexpectedSynHandling`
2. 若出现 `UnsupportedServer`，优先检查服务端能力，而不是直接判定 NAT 问题。
3. 若出现 `Inconclusive`，表示该项暂不能下结论。
4. 若要做 P2P/打洞可行性评估，重点关注：
   - UDP：`EndpointIndependent` 映射与过滤更友好
   - TCP：`TcpSimultaneousOpen` 是否 `Pass`
   - 跨协议：RFC7857 三项是否稳定

---

## 8. 快速示例

### 8.1 RFC5780（UDP 全量）

```bash
./src/build/nat_type_tester_cli rfc5780 \
  --stun_server stun.example.com:3478 \
  --transport udp \
  --test-type combining
```

### 8.2 RFC5382（需要双 IP 服务端）

```bash
./src/build/nat_type_tester_cli rfc5382 \
  --stun_server stun.example.com:3478 \
  --primary_server 1.2.3.4:3478 \
  --secondary_server 5.6.7.8:3478 \
  --test-type all
```

### 8.3 RFC7857（跨协议一致性）

```bash
./src/build/nat_type_tester_cli rfc7857 \
  --stun_server stun.example.com:3478 \
  --primary_server 1.2.3.4:3478 \
  --secondary_server 5.6.7.8:3478
```
