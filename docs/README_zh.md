# Nowhere 文档

文档按任务分类。如果您要运行参考服务器，请先阅读“快速入门”；如果您要构建兼容客户端，请先阅读“协议规范”。

## 传输映射

`net` 参数用于选择哪些入站传输协议在配置的端口上进行监听。它并不将 Portal 限制为仅支持一种代理载荷类型。

| `net` 值 | 监听器   | TCP 代理路径     | UDP 代理路径             |
| -------- | -------- | ---------------- | ------------------------ |
| `tcp`    | TLS/TCP  | 专用的已认证连接 | 基于专用已认证连接的 UoT |
| `udp`    | QUIC/UDP | 双向 QUIC 流     | QUIC 数据报 (DATAGRAM)   |
| `mix`    | 两者     | 两条路径         | 两条路径                 |

UoT 使用保留的请求目标 `uot.nowhere.invalid:0`，后跟一个目标设置帧（target setup frame）以及长度前缀（length-prefixed）的 UDP 数据包。它是 v1 线路协议的一部分，无需单独的服务器选项。

## 文档

| 文档                         | 范围                                                         |
| ---------------------------- | ------------------------------------------------------------ |
| [配置参考](configuration.md) | URL 格式、查询参数、监听规则、TLS 输入及示例。               |
| [集成指南](integrations.md)  | OpenCtrl 管理与 Anywhere 客户端设置。                        |
| [运维指南](operations.md)    | 日志记录、事件记录、速率限制、运行时控制、关闭及部署惯例。   |
| [协议规范](protocol.md)      | 规范性 v1 线路格式、派生机制、TCP、QUIC 数据报、UoT、限制及一致性检查。 |
| [快速入门](quick-start.md)   | 构建、运行并进行冒烟测试（smoke-check）本地 Portal。         |
| [安全须知](security.md)      | 共享密钥处理、TLS 信任、认证失败行为及暴露风险指导。         |

面向运维人员：

1. [快速入门](quick-start.md)
2. [配置参考](configuration.md)
3. [运维指南](operations.md)
4. [集成指南](integrations.md)
5. [安全须知](security.md)

面向客户端开发者：

1. [协议规范](protocol.md)
2. [配置参考](configuration.md)
3. [集成指南](integrations.md)
4. [安全须知](security.md)

面向发布维护人员：

1. [快速入门](quick-start.md)
2. [运维指南](operations.md)
3. `.github/workflows/release.yml` 中的 GitHub 发布工作流

## 风格规范

本文档在各处使用统一的术语：

- `Portal` 指代本 Rust 服务器。
- `client` 指代发起连接至 Portal 并开启目标数据流（target flows）的对端。
- `shared key` 指代经过百分号解码（percent decoding）后的 URL 用户名部分。
- `effective_spec` 指代应用默认值后解析出的 `spec` 值。
- `effective_alpn` 指代应用默认值后解析出的 `alpn` 值。
- `UoT` 指代通过单个已认证 TLS/TCP 连接承载的 UDP-over-TCP 数据包路径。
- `rate` 指代从客户端到目标（client-to-target）的流量。
- `etar` 指代从目标到客户端（target-to-client）的流量。