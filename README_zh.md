# Nowhere

> **独一无二的协议规范 (spec)。**

大多数中继协议无论在何处运行，其形态都千篇一律。Nowhere 则不然。

Nowhere 是一种针对 TCP 和 UDP 的加密中继协议。客户端与 Portal（门户节点）使用相同的共享密钥和精简的 `spec`（协议规范）来生成匹配的身份验证机制与消息布局。该 `spec` 绝不会在连接中传输。只需更改 `spec`，Nowhere 就能在保持原有功能和行为的同时，为该部署采用不同的协议布局。

<div align="center">
<img src="assets/nowhere.png" width="640" alt="Nowhere">
</div>

## 亮点

- **由 `spec` 定义的协议形态。** 身份验证标识、填充数据和帧顺序均由通信双方独立推导得出。`spec` 本身不进行传输，也无需配置注册表或额外的协商过程。
- **单端口支持 TLS/TCP 与 QUIC/UDP。** Portal 可同时监听这两种传输协议，并全程采用 TLS 1.3 及统一的身份验证模型。
- **支持在任一传输层上承载 TCP 和 UDP。** TCP 流量通过专用 TLS 连接或 QUIC 流传输；UDP 流量则根据环境选择：仅有 TCP 可用时使用 UoT（UDP-over-TCP），支持原生 UDP 时则使用 QUIC DATAGRAM。
- **原生支持可观测性与可控性。** EVENT 检查点可暴露连接池、活跃数据流及字节计数等信息；定向速率限制和运行时控制功能则确保了服务对运维人员的友好性。
- **支持集中式管理。** 既可直接运行 Portal，也可通过 OpenCtrl 的 REST API 和 Server-Sent Events (SSE) 管理其生命周期、持久化配置、日志及实时指标。
- **身份验证前的安全加固。** 通过 QUIC 重试机制、受限的预验证准入、带抖动的验证时限以及禁用 0-RTT，减少了在客户端获得信任之前的计算负载与信息暴露风险。

## 传输方式

| 流量类型 | TLS/TCP                   | QUIC/UDP                      |
| -------- | ------------------------- | ----------------------------- |
| TCP      | 专用加密连接              | 双向流 (Bidirectional stream) |
| UDP      | 带长度前缀的 UDP-over-TCP | QUIC DATAGRAM                 |

单个 Portal URL 即可在同一端口上启用 TLS/TCP、QUIC/UDP 或两者兼有。 ## 快速入门

从 [Releases](https://github.com/NodePassProject/Nowhere/releases) 下载 Linux 二进制文件，或者使用稳定的 Rust 工具链从源码运行：

```bash
cargo run --release --locked -- 'portal://change-me@:2077?spec=nightfall'
```

URL 中的用户名即为共享密钥。留空的主机地址（host）表示同时监听 IPv4 和 IPv6；默认的 `net=mix` 模式会在端口 `2077` 上同时启动 TLS/TCP 和 QUIC/UDP 服务。

默认的 `tls=1` 会生成临时的自签名证书。对于长期部署，建议使用 `tls=2` 并指定 PEM 格式的证书和私钥：

```bash
nowhere 'portal://change-me@:2077?spec=nightfall&tls=2&crt=/etc/nowhere/cert.pem&key=/etc/nowhere/key.pem'
```

## 生态系统

- [OpenCtrl](https://github.com/NodePassProject/OpenCtrl)：支持 Portal 生命周期管理、持久化状态、REST/SSE 控制、日志记录及 EVENT 指标监控的管理层。
- [Anywhere](https://github.com/NodePassProject/Anywhere)：支持 TLS/TCP 和 QUIC/UDP 的原生客户端，功能涵盖 TCP 转发、QUIC DATAGRAM 和 UoT。

未来计划集成更多核心组件和客户端。

## 文档

- [配置参考](docs/configuration.md)
- [文档索引](docs/README.md)
- [集成指南](docs/integrations.md)
- [运维指南](docs/operations.md)
- [协议规范](docs/protocol.md)
- [快速入门](docs/quick-start.md)
- [安全模型](docs/security.md)

## 开发

```bash
cargo fmt --all -- --check
cargo test --locked
cargo clippy --all-targets -- -D warnings
cargo build --release --locked
```

Nowhere 使用 Rust 2024 版本（edition）。 ## 贡献

欢迎提交 [Issue](https://github.com/NodePassProject/Nowhere/issues) 和针对性强的 Pull Request。涉及协议变更时，必须在同一提交中更新测试向量与协议规范。

## 许可证

Nowhere 采用 [GNU 通用公共许可证 v3.0 (GPLv3)](LICENSE) 授权。
分发原始或修改后的二进制文件时，必须遵守 GPLv3 关于源代码及声明的相关要求。

---

© 2026 NodePassProject. 保留所有权利。