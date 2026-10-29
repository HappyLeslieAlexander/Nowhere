# Nowhere 改进计划

> **状态：已执行完毕（2026-10-30）。** 阶段 0–4 全部落地，分六个 commit：
> `8ee6f26`（批次 1：0.1/0.2/0.4/2.1/2.6/1.6）、`25b43b7`（批次 2：0.3/1.1/1.4/1.5）、
> `72260a1`（批次 3：1.2/1.3/2.2/2.3）、`e70d62a`（批次 4：2.4/2.5/3.1/3.2/3.3/3.4）、
> `99e1a07`（阶段 4 工程卫生）、`4e21797`(阶段 4.3 文档)。质量门（fmt / test / clippy -D warnings /
> release build）全绿，测试 373 → 393。
> 唯一未实施项：4.2 的 auth.rs 换用 `hkdf` crate（计划内标注"可选、非缺陷"）与
> diagnostic.rs typed error 重构（计划内标注"较大，可独立 PR"）。
>
> 来源：2026-10-30 全库代码评审（portal / vector / transport / protocol+common / egress+telemetry+toolbox，约 2.7 万行，含 1.1 万行测试）。
> 原则：只列需要改动的事项，每项给出确切位置、问题机制、修复方案与可执行的验收标准。
> 合入门槛（每 PR）：`cargo fmt --all -- --check`、`cargo test --all-targets --locked`、`cargo clippy --all-targets --locked -- -D warnings`、`cargo build --release --locked`。
> 行为变更项（1.2、2.4）必须同步更新对应 docs 并提供配置开关；性能敏感项（morph UDP、rate）对照 docs/testing.md 的性能测量方法做前后对比。

## 总览

| 阶段 | 主题 | 条目 | 预估 |
|---|---|---|---|
| 0 | 正确性与资源安全（P1） | 0.1–0.4 | 3–4 天 |
| 1 | 配额对称与对抗韧性（P2） | 1.1–1.6 | 1.5–2 周 |
| 2 | 可靠性与互操作（P2） | 2.1–2.6 | 1.5 周 |
| 3 | 可运维性（P2/P3） | 3.1–3.4 | 1 周 |
| 4 | 工程卫生（P3） | 搭车清单 | 随相邻 PR |
| 5 | 测试补强 | 随对应修复同 PR | — |

---

## 阶段 0 — 正确性与资源安全（P1）

### 0.1 准入等待队列 lost-wakeup 竞态

- **位置**：`src/portal/admission.rs:49-57`
- **现状**：`acquire()` 先创建 `self.released.notified()`，在 `try_acquire` 返回 `None` 后才 `await`。tokio 的 `Notified` 在首次 poll 前不注册，而 `UnauthenticatedGuard::drop`（`admission.rs:97`）用的是 `notify_waiters()`——它只唤醒**已注册**的 waiter，不存储 permit。若某次 release 恰好落在 `try_acquire` 失败与首次 poll 之间，唤醒永久丢失，该连接一直睡到 park deadline（默认 5s）才被关闭。同仓库 `src/egress/registry.rs:81-83` 已用 `enable()` 规避了同一竞态，属不一致。
- **修复**：
  ```rust
  pub(super) async fn acquire(self: &Arc<Self>, source: IpAddr) -> UnauthenticatedGuard {
      loop {
          let released = self.released.notified();
          tokio::pin!(released);
          released.as_mut().enable();   // 先注册再尝试，锁序不变
          if let Some(guard) = self.try_acquire(source) {
              return guard;
          }
          released.await;
      }
  }
  ```
- **验收**：`src/tests/portal/admission.rs` 新增两组用例：
  1. 确定性回归测试（tests 模块是 `admission` 的子模块，可直接访问私有字段）：持有 1 个 guard → pin 住 `notified()` 并 `enable()` → drop guard → `timeout(100ms)` 内 `notified.await` 必须完成。无 `enable()` 时该 await 永久挂起，即精确固化被修复的语义。
  2. 行为级压测：N=64 个任务并发 `acquire`，M=8 个任务反复 acquire→立即 drop，总时限内所有 waiter 必须最终获得许可（当前实现下偶发超时）。
- **工作量**：S（含测试半天）

### 0.2 Egress QUIC 注册成功后的可失败 `?` 泄漏僵尸注册

- **位置**：`src/egress/connection.rs:53-56`
- **现状**：`registration::register(...)` 成功后连接已进入 Portal 的注册 FIFO；随后 `let limits = crate::transport::transport_flow_control()?;` 读 `NOW_TRANSPORT_MEMORY_PROFILE`，配置非法时 `?` 直接返回。此时 `ConnectionGuard` 尚未建立，`quinn::Connection` 被 drop——quinn drop 不发应用层 CLOSE，Portal 侧要把这条僵尸注册保留到 idle/keepalive 超时（最长 120s），期间被 claim 的 Flow 挂起失败。且该 env 每连接才解析（见 3.1），配错时每 3s 循环注入一条僵尸注册。
- **修复**：把 `transport_flow_control()?` 移到 `register()` **之前**。`set_receive_window`/`set_max_concurrent_bi_streams` 均不可失败，重排后注册成功到 `QuicConnection::new` 之间不存在任何可失败调用；3.1 落地后该调用在启动期完成，构成第二道防线。
- **验收**：
  1. `NOW_TRANSPORT_MEMORY_PROFILE=typo` 启动 Egress：启动期报错退出（3.1 后），绝无运行期注册。
  2. 回归测试：mock 注册成功 + flow-control 解析失败（重排前会走到的路径在重排后不可达），断言 `connection.close` 被调用或该路径从类型上消失（签名重构后编译期保证）。
- **工作量**：S

### 0.3 Vector SOCKS 连接无存活检测，1024 个准入名额可被永久占满

- **位置**：`src/vector/socks/udp.rs:57-66`（association 主循环）、`src/vector/socks/server.rs`（CONNECT 路径）、`src/vector/client/mod.rs:126`、`src/vector/tls.rs:110`
- **现状**：
  - UDP ASSOCIATE 的生命周期只由 control 连接的 EOF/错误终止，主循环 `select!` 无超时分支；客户端静默消失（NAT 超时、断电、RST 丢失）后 association 永久持有 1 个 `socks_client_admission` 许可、1 个 UDP socket 和 per-target 预算。
  - TCP 侧 `relay_tcp` 建立后无任何探活：portal 方向走 `connect_tcp`（`vector/tls.rs:110` 对 `connect_tcp_with_keepalive` 传 `None`，keepalive 参数存在但 Vector 从未使用），本地 leg 也没有 keepalive。两侧同时静默的中继永不回收。
  - 打满 `SOCKS_CLIENT_RESOURCE_LIMIT`（1024）后所有新 SOCKS 连接被静默 drop（`server.rs:72-75`），整机拒绝服务。
- **修复**（设计取舍：TCP 用 keepalive 探活而非 idle kill，合法长闲连接如 SSH 不受影响；UDP association 无存活信号，只能 idle 超时）：
  1. 抽公共 `TcpKeepalive`（复用 `egress/tls.rs` 的 `tcp_keepalive()` 15s/15s 常量，移到 `common`），应用于：SOCKS accept 的 control stream、`connect_tcp_with_keepalive` 的 portal leg（`vector/tls.rs:110` 传 `Some`）、relay 双腿。
  2. association 主循环加空闲 deadline：任何 UDP 包路由/flow 活动即重置，超时关闭。默认 300s，env `NOW_SOCKS_UDP_IDLE`（沿用 `NOW_*` 命名，0 = 禁用）。
- **验收**（`src/tests/vector/socks/udp.rs`）：
  1. `association_closes_after_idle_timeout`：env 设 200ms → associate → 发一个包 → 静默 → 断言 admission 计数回落到基线、UDP socket 已关闭。
  2. `association_survives_active_traffic`：持续流量超过 idle 阈值，association 保持。
  3. keepalive 接线用单元测试断言（三条路径都调用 `set_tcp_keepalive`）。
- **工作量**：M（单独一个 PR，涉及超时语义与 env 设计）

### 0.4 Windows 下 `SO_REUSEADDR` 允许端口劫持

- **位置**：`src/portal/listener.rs:71`、`src/vector/socks/server.rs:53`（全库仅这两处）
- **现状**：Unix 上这是 TIME_WAIT 重绑惯用法；Windows 上等价于允许任意其他进程绑定同一端口（未配合 `SO_EXCLUSIVEADDRUSE`），存在本地端口劫持风险。
- **修复**：两处均 `#[cfg(not(windows))]` 包裹。Windows 不设该选项后默认即排他语义；重启撞 TIME_WAIT 的概率对这两个长驻监听可接受，在 `docs/platforms.md` 注明。
- **验收**：三平台 CI 通过；新增编译期断言（简单 cfg 单测）确认 Windows 目标下函数体不含该调用。
- **工作量**：S

---

## 阶段 1 — 配额对称与对抗韧性（P2）

### 1.1 QUIC Egress 注册补容量上限 / TTL / 主动清理

- **位置**：`src/portal/conn.rs:299`（`registry.register_quic(q.clone())` 无条件入队）；对照 TLS 侧 `conn.rs:142` `reserve_tls()`（pending 上限 `NOW_PORTAL_TLS_IDLE_MAX` 默认 128、范围 128..1023，满员回 `[1]` 拒绝，standby TTL 120s）
- **现状**：QUIC 注册无上限、无 TTL、无拒绝路径。死连接条目只在 `claim()` 扫描时被剔除（`egress/registry.rs:91-97`）——Portal 空闲（无新 Flow 触发 claim）时，已断开 Egress 的 `Arc<QuicConnection>`（含 `UdpState`、reassembler、semaphore 预算）滞留 `VecDeque`；被认证客户端最多可注册 1024 条（受 `connection_admission` 约束），与 TLS 的 128 不一致。
- **修复**：镜像 TLS 语义——(a) 注册前检查 pending 计数（`AtomicUsize`），超限走既有 BUSY 回执（registration.rs 已支持 reply=1）；(b) 条目记录 `registered_at`，`register()`/`claim()` 时顺带剔除 `close_reason().is_some()` 或超 TTL 的条目，Portal runtime 加低频清扫任务（如 30s）兜底。
- **验收**：registry 并发测试扩展——注册 N+1（超上限）最后一条收到 BUSY；关闭一半连接后不产生新 claim，清扫任务把 registry 长度收敛；`close_reason` 条目不再被 claim 命中。
- **工作量**：M。**注意**：与近期提交 `96c21bf`（Skip stale TLS Egress registrations）、`af6ea32`（Prioritize TLS claims over standby expiration）属同一语义域，同一批评审。

### 1.2 morph 准入抗耗散：~80 字节即可占住一个准入槽

- **位置**：`src/portal/conn.rs`（`accept_bootstrap` 的 HMAC 失败路径）、`src/portal/admission.rs:12-13`（全局 256 / 单源 32 硬编码）、`src/portal/runtime/mod.rs:119-135`
- **现状**：morph 模式下，连接发送 ≤80 字节垃圾导致 HMAC 失败（`InvalidData`）或提前 EOF 后走 `pending().await` 静默挂到 deadline——期间 `UnauthenticatedAdmission` 槽位被占用。8 个源 IP × 约 50 conn/s 即可持续饿死所有新 TCP 连接，并连带耗尽与 QUIC 共享的 256 个槽（`quic_loop` `try_acquire` 失败直接 `incoming.ignore()`）。HMAC 失败在密码学上已证明对方不掌握 URL secret，此时保持静默 decoy 的探测对抗价值远低于其占用成本。
- **修复**：
  1. 错误分类处理：`accept_bootstrap` 返回 `InvalidData`（HMAC 确定性失败）→ 立即静默关闭（guard 随 drop 释放槽位）；`UnexpectedEof`/截断（可能是慢客户端或扫描器）→ 保留现状 park。
  2. `MAX_UNAUTHENTICATED_CONNECTIONS` / `MAX_UNAUTHENTICATED_PER_SOURCE` 改为 `portal/config.rs` 经 `read_usize` 读取的配置（env 建议 `NOW_UNAUTH_MAX` / `NOW_UNAUTH_PER_SOURCE`，保留当前默认值）。
  3. per-source 速率限制暂缓（收益边际，先观察 1+2 的效果）。
- **验收**：
  1. 单测：`InvalidData` 路径连接立即关闭且槽位释放（不再等 deadline）；EOF 路径行为不变。
  2. 压测脚本：8 源 × 50 conn/s 垃圾流量持续 5s 期间，合法 Vector 1s 内完成连接。
  3. `docs/security.md` 更新：说明该取舍及与 decoy 设计的关系。
- **工作量**：M。**行为变更**（1），需开关评审。

### 1.3 QUIC 认证前 datagram 洪泛护栏

- **位置**：`src/portal/conn.rs:254-261`
- **现状**：TLS/QUIC 握手已完成但未通过 auth 的客户端，可在 `handshake_timeout` 内持续泵 datagram；服务端每条都要 `decode_udp_frame_owned` + `state.lock()`，只有 `yield_now` 节流。认证后 CPU 放大点，quinn 对 datagram 无流控。
- **修复**：auth 窗口内加每连接字节预算（建议 1 MiB，与 `NOW_QUIC_UDP_QUEUE_BYTES` 量级对齐），超限 `connection.close()`。计数器并入 3.3。
- **验收**：单测——认证前灌 2 MiB datagram，连接提前关闭且不进入 auth 成功路径；正常客户端的 auth 交互（远小于预算）不受影响。
- **工作量**：S

### 1.4 Vector 重连韧性：缓存连接死亡竞态 + 握手风暴

- **位置**：`src/vector/client/quic.rs:51-63`（复用路径）、`:65-92`（新建路径）
- **现状**：复用路径的健康检查（`close_reason().is_none()`）与连接死亡存在竞态，检查通过后连接死亡则 `open_bi` 失败，本次请求直接报 `Transport` 错误，不重试。对 Portal 宕机或 key 错误（`Setup != Ready`）无冷却/负缓存：每个 SOCKS 请求串行排队（quic Mutex）→ DNS + 完整 QUIC 握手 → 失败，持续对 Portal 施加握手压力。
- **修复**：
  1. 复用路径 `open_bi` 返回 `Transport` 类错误时，作废缓存并在**同一请求内**用新连接重试一次。安全性依据：此刻 Flow 尚未建立、未发出任何业务字节，重试幂等。
  2. 连续失败计数 + 冷却：失败后 `next_attempt = now + service_cooldown() × (1 + rand(0..0.5))`（getrandom 已在依赖中），冷却期内请求快速失败并返回明确错误，而非排队握手。
- **验收**：
  1. 单测：注入"第一次 connect 失败/复用连接死亡"，断言请求经透明重试后成功。
  2. 单测：连续失败进入冷却，冷却期内新请求立即返回错误不再发起握手。
- **工作量**：M

### 1.5 UDP 全局预算可被单一 target 独占；预算 < 最大包长时大包永久丢弃

- **位置**：`src/vector/socks/udp.rs:91-97`（预算获取）、`:113`（`mpsc::channel(64)`）、`src/vector/mod.rs:107`（`local_udp_budget` 来自 `NOW_QUIC_UDP_QUEUE_BYTES`，默认 4 MiB）
- **现状**：per-target 队列 64 包 × 单包上限 65535 ≈ 4 MiB，恰好等于默认全局预算——一个高频大包 target 的满队列即可吃光预算，其它 association 的入包全部静默 `continue`。若操作员把预算设为 < 65535（如 4096），`try_acquire_many_owned` 对超预算的大包**永远**失败，静默丢弃且无告警。
- **修复**：
  1. `common/config.rs` 的 `read_quic_udp_queue_bytes` 加下限校验：值 < 65535 时启动报错（说明单包上限依据）。
  2. 每 association 保底：单个 association 在途字节上限取 `max(65535, budget / 4)`，保证 ≥4 个 association 同时活跃时不互相饿死。
  3. 所有丢弃分支（源不匹配、FRAG≠0、port==0、预算耗尽、队列满、admission 耗尽）加计数器（并入 3.3 的 Stats）。
- **验收**：预算设 2×65535，两个 association 各自洪泛不同 target，断言双方均有进展；`NOW_QUIC_UDP_QUEUE_BYTES=4096` 启动报错且错误信息含最小值。
- **工作量**：M

### 1.6 Egress 重连风暴：固定 3s 冷却无抖动

- **位置**：`src/egress/connection.rs:30-33`、`src/egress/tls.rs:65,71,75`
- **现状**：`NOW_SERVICE_COOLDOWN`（默认 3s）为固定值。多 Egress 实例部署时，Portal 重启后所有实例在第 3s 同时重连，恰压在 Portal 恢复初期（`NOW_PORTAL_TLS_IDLE_MAX` 默认 128 会被打满返回 BUSY），形成同步风暴。
- **修复**：Failed 分支的冷却加 ±50% 抖动：`cooldown + rand(0..cooldown/2)`；`Expired` 分支的立即重试（正常过期路径）保持不变。
- **验收**：单测断言连续两次计算的冷却时长不同（统计性，100 次采样方差 > 0）；集成测试：两实例同时进入冷却，重连时间点错开。
- **工作量**：S

---

## 阶段 2 — 可靠性与互操作（P2）

### 2.1 TLS standby 过期是双计时器竞态，正常过期约 50% 概率记为故障

- **位置**：`src/egress/tls.rs:147-161`（`wait_flow_start`）对照 `src/portal/conn.rs:160`（Portal 在**发送** ACCEPTED 后起 `expires_at = now + 120s`）
- **现状**：Egress 在**收到** ACCEPTED 后才起 `idle_ttl` 计时。设单向延迟 d：Portal 关闭时刻 ≈ `T_send+120s`，FIN 到达 Egress ≈ `T_send+120s+d`；Egress 计时到期 ≈ `T_send+d+120s`——两者**同一时刻**。`wait_flow_start` 是 `biased` 且 read 分支在 sleep 分支之前，EOF 与 timer 同 tick 就绪时 EOF 胜出 → `bail!("Egress TLS standby disconnected")` → `PendingResult::Failed` → error 级日志 + 3s 无 seed 冷却。每个空闲周期掷一次硬币。现有测试的 fake Portal 永不主动关闭 standby，掩盖了这条路径。
- **修复**：EOF 时检查是否临近自身 `expires_at`：
  ```rust
  None => {
      // Portal 与本端计时起点相差单向延迟，EOF 与 expires_at 同时到期属正常过期
      if Instant::now() + Duration::from_secs(1) >= expires_at {
          Ok(None)
      } else {
          bail!("Egress TLS standby disconnected")
      }
  }
  ```
  FlowStart 优先（af6ea32 的目标）不受影响。
- **验收**：`tests/egress/tls.rs` fake Portal 增加"在 idle_ttl 后主动关闭 standby"模式：断言返回 `PendingResult::Expired`、无 error 日志、无 3s 冷却；FlowStart 先到时仍返回 `Started`。
- **工作量**：S。**依赖**：测试基建升级（fake Portal 主动关闭），随本项同 PR 落地。

### 2.2 证书热重载在 `resolve()` 内同步做磁盘 I/O

- **位置**：`src/common/tls_cert.rs:82-107`（`ReloadingCertResolver::resolve`）
- **现状**：reload 间隔到期时，第一个到达的握手持**写锁**执行 `load_certified_key`（`fs::read` + PEM/DER 解析 + 私钥解析，全同步）；期间所有并发 `resolve()` 阻塞在同一把 `RwLock` 上。慢存储/NFS 上会卡住整个 accept 路径。且 `:105` 锁中毒后 `resolve()` 永久返回 `None`，握手全部失败。
- **修复**：构造时（portal setup 的 async 上下文）spawn 后台任务按 `reload_interval` 预加载并替换 `Arc<CertifiedKey>`；`resolve()` 只读缓存（读锁或 `ArcSwap`），无 I/O、无写锁；reload 失败保留旧证书并记日志（现有 `tests/common/tls_cert.rs:116` 的"保留旧证书"用例继续成立）；锁处理统一 `into_inner` 恢复。
- **验收**：
  1. 初始化后删除/破坏磁盘证书文件，`resolve()` 仍立即返回旧证书（证明热路径无 I/O）。
  2. 并发 1000 次 `resolve` 期间触发 reload，单次 resolve 耗时有上界断言。
- **工作量**：M

### 2.3 TCP 拨号无 Happy Eyeballs，所有候选共享一个总超时

- **位置**：`src/common/network.rs:69-86`（`dial_tcp_with_policy` 单个 `timeout` 包住解析+串行尝试）、`:110-122`（`connect_tcp_candidates` 逐个顺序 connect）；UDP 侧对称问题在 `:88-108`、`:124-137`
- **现状**：dual-stack 下 getaddrinfo 通常先返回 IPv6；v6 路由黑洞（SYN 丢弃）时第一个候选耗尽整个 dial 超时（Portal 默认 15s），总超时到期直接失败，可用的 v4 永远轮不到。
- **修复**：务实版 Happy Eyeballs——候选按 v6/v4 交错排序，每候选子超时 = 剩余总超时 / 剩余候选数，先成功者胜（`tokio::select!` over JoinSet）。完整 RFC 8305 的 250ms 交错并发标记为可选后续。
- **验收**：集成测试——候选表 `[203.0.113.1`（TEST-NET-3 黑洞）`, 127.0.0.1:port]`、短总超时：当前实现必失败，修复后经第二个候选成功；UDP 侧同样用例。
- **工作量**：M

### 2.4 目标域名校验拒绝合法的下划线域名

- **位置**：`src/protocol/util.rs:42-64`（`validate_domain_bytes` 仅允许字母数字与 `-`），作用点 `src/portal/forward/incoming.rs:42` 与 `src/vector/flow/mod.rs:32-37`
- **现状**：`_acme-challenge.example.com`、`_dmarc.example.com`、`foo_bar.example.com` 等真实可解析域名（RFC 1123 放宽、实践中大量存在）被判 `InvalidRequest`。SOCKS5（RFC 1928）本身允许任意域名字节。`tests/protocol/util.rs:16` 固化了拒绝行为。
- **修复**：放宽为——总长 ≤ `DOMAIN_LEN_MAX`、每 label ≤ 63、全 ASCII 可打印（`0x21..=0x7E`）、非空；删除字母数字+`-` 白名单（下划线随之合法）。校验不是安全边界（转发目标本就由客户端指定），无 SSRF 回归。
- **验收**：更新 `tests/protocol/util.rs` 期望（下划线域名通过、空字节/控制字符/超长仍拒绝）；2 万次变异语料中相关断言同步；`docs/interoperability.md` 补充说明。
- **工作量**：S。**行为变更**，需 docs 同步。

### 2.5 QUIC 分片 `TooLarge` 重试遗留孤儿分片，占用接收方重组预算至 TTL

- **位置**：`src/common/datagram.rs:42-82`（`send_quic_udp_packet`）；接收方 `src/transport/quic_runtime.rs:114-124`
- **现状**：分片循环中途遇 `SendDatagramError::TooLarge`（`:70-75`）时 break 重试，此时前若干分片已入队无法撤回；接收方为放弃的 `packet_id` 建立重组 slot，占用 `NOW_QUIC_UDP_QUEUE_BYTES` 预算与 semaphore 许可直到 10s TTL。PMTU 抖动时产生持续垃圾 slot。该函数目前零测试。
- **修复**：
  1. 抽纯函数 `plan_fragments(payload_len, max_datagram_size) -> Option<Vec<分片尺寸>>`（对给定 max_size 尺寸是确定的），入队前预检，任何一个放不下则直接返回 `DroppedTooLarge`，不产生孤儿。
  2. 兜底：中途失败时对该 `packet_id` 补发 CLOSE 帧（协议已有 CLOSE，接收方 reassembly 按 id 失效）。
- **验收**：planner 纯函数单测（恰好放下 / 超 1 字节 / 零长）；loopback 集成测试（真 quinn endpoint 对）：中途收缩 `max_datagram_size`，断言接收方重组表归零、预算全额返还。
- **工作量**：M

### 2.6 `set_max_concurrent_bi_streams(1024)` 语义与意图相反

- **位置**：`src/vector/client/quic.rs:78-80`，与 `:81-88`（方向违规监控）冲突
- **现状**：quinn 中该 API 设置的是**远端**可打开的 bidi 流上限——此行实际授权 Portal 打开 1024 条 server-initiated 流，而紧随其后的监控任务在 server 打开第一条 bidi 流时立即 `close(1, "role direction violation")`。对真正的意图（客户端自己的并发流数，由 server 端 transport parameters 决定）毫无作用。
- **修复**：改为 `connection.set_max_concurrent_bi_streams(0u32.into());`（从 transport parameters 层面禁止 server-initiated 流，监控保留为纵深防御），加注释说明。**注意**：`src/egress/connection.rs:58` 的同款 1024 是**正确**的（Egress 协议中 Portal 主动开流），不要改。
- **验收**：现有方向违规测试继续通过；新增用例：server 尝试 `open_bi` 被 transport parameters 拒绝。
- **工作量**：S

---

## 阶段 3 — 可运维性（P2/P3）

### 3.1 配置校验时机统一：env 每连接解析 → 启动期一次

- **位置**：`src/transport/quic.rs:31-37`（`transport_flow_control()` 每调用读 env；调用点 `portal/conn.rs:269`、`egress/connection.rs:55`、`vector/client/quic.rs:77`）；`src/transport/morph/tcp.rs:29-31,127`（`TcpPreludePolicy::from_env()` 每次 `connect()` 读取）；`src/common/config.rs:67-73`（`env_int` 解析失败/负数**静默回退默认值**且允许 0）+ `:164-166`（`tcp_data_buf_size()`）
- **现状**：`NOW_TRANSPORT_MEMORY_PROFILE=typo` 或 `NOW_MORPH_TCP_PRELUDE=typo` 时进程正常启动，之后**每一条**新连接握手中途失败（Portal 侧发生在 TLS 认证之后），表现为难以排查的全面掉线。`NOW_TCP_DATA_BUF_SIZE` 双标：Portal 走 `read_usize` 严格校验（`portal/config.rs:48`，拒绝 0、有上限），Egress/Vector 走 `env_int` 宽松路径（`egress/setup.rs:65`）——Egress 下设 0 得到空缓冲，`read(&mut [])` 返回 `Ok(0)` 被当 EOF，连接瞬断。
- **修复**：
  1. flow-control profile 与 morph prelude policy 在各角色 setup（`portal/setup.rs`、`egress/setup.rs`、`vector/mod.rs`）解析一次存入 runtime 结构，`transport_flow_control`/`from_env` 改为接收已解析值。
  2. `read_usize` 提升到 `common::config`，三角色共用；`NOW_TCP_DATA_BUF_SIZE` 统一拒绝 0、上限 1 MiB（`Buffers` 池缓存 64 份，`isize::MAX` 上限等于一个配置错误即 OOM abort）。
  3. `tls=2` 缺 `crt`/`key` 显式 `bail!("tls=2 requires crt and key parameters")`（现为 `unwrap_or_default()` 空路径 + 误导性报错，`common/tls.rs:71-75`）。
- **验收**：三个 env 各一条负例单测（非法值 → 启动报错含参数名）；`NOW_TCP_DATA_BUF_SIZE=0` 三角色均启动失败。
- **工作量**：M

### 3.2 URL query 未知参数静默忽略，安全语义键拼错无提示

- **位置**：`src/common/config.rs:17-33`（`query_first`：`:27` 丢弃不在 allowed 列表的键；`:24-26` 键解码失败也静默跳过）
- **现状**：`pinn=<sha256>`、`morphh=1`、`crtt=` 拼错时按默认值运行且无任何提示——用户以为启用了 pin/morph 实际没有。
- **修复**：`query_first` 增加未知键回调/返回值，调用方（各角色 config 解析）对未知键打 warning 日志（含键名）；至少覆盖 `tls/crt/key/out/in/morph/pin/sni/net/rate/etar/dial/dial4/dial6`（与 main.rs HELP_TEXT 对齐）。
- **验收**：单测：含未知键的 URL 解析产生 warning 且解析结果不变；键百分号解码失败也有 warning。
- **工作量**：S

### 3.3 静默路径可观测性：丢弃零计数

- **位置**：`src/vector/socks/udp.rs:79-87,104,110-116`（源不匹配/FRAG/队列满/预算耗尽/admission 耗尽全部 `continue` 无计数）；`src/transport/quic_runtime.rs:132`（channel 满丢包静默）；`src/portal/runtime/mod.rs:235`（QUIC `incoming.ignore()`）；`src/vector/socks/server.rs:95` 与 portal accept 循环（JoinError 吞掉）
- **修复**：`transport/stats.rs` 与 vector Stats 增加上述计数器字段；telemetry `wire.rs` schema 同步扩展并更新 `docs/telemetry.md`；JoinError 至少 debug 级日志。
- **验收**：各丢弃路径注入式单测断言计数递增；telemetry snapshot 集成测试包含新字段。
- **工作量**：M

### 3.4 观测一致性

- **位置**：`src/portal/runtime/mod.rs:132,136`（morph park 超时返回 `Closed` 不计入 `SilentRejections`）；`src/portal/conn.rs:125-131`（非 morph auth 超时/ALPN 错误以 error 级记录——扫描器可刷日志噪声；morph 侧同类输入完全静默）
- **修复**：park 超时与 QUIC ignore 计入 `SilentRejections`；非 morph 的 handshake 超时降为 debug + 计数器（保留错误级给真实协议错误）。
- **验收**：单测断言计数；日志级别断言。
- **工作量**：S

---

## 阶段 4 — 工程卫生（P3，触碰相邻代码时搭车）

### 4.1 锁中毒策略统一

现状三种并存：`into_inner` 恢复（`admission.rs:61,88`、`logger.rs:35`、`morph/udp.rs:185,234` ✓）、裸 `unwrap`（`egress/registry.rs:68,85,131`、`transport/quic_runtime.rs:69,90,101,168,192`、`rate_bucket.rs:44,59`）、fail-closed（`replay.rs:63,75`——中毒后拒绝**所有**带 prelude 的连接直到重启）。统一为 `unwrap_or_else(|err| err.into_inner())`，前提是临界区经审计无 panic（各处均为纯数据操作，成立）；`replay.rs` 的窗口丢失属可接受降级。release profile 是 `panic = "abort"`，panic 路径即进程死亡，更需容忍中毒。

### 4.2 杂项清单（每项 ≤ 半天）

| 事项 | 位置 |
|---|---|
| exporter 缓冲 `[0; 32]` → `TLS_EXPORTER_LEN` 常量 | `src/vector/client/quic.rs:68` |
| Vector 内日志文案复制粘贴残留 "Egress TLS: failed to configure TCP keepalive" | `src/vector/tls.rs:130` |
| CONNECT 目标 port 0 回码 `REPLY_ADDRESS_NOT_SUPPORTED(8)` 语义不符，应 `REPLY_GENERAL_FAILURE` | `src/vector/socks/server.rs:140-148` |
| NMETHODS=0 未回 `[5, 0xFF]`（RFC 1928 §3） | `src/common/socks/protocol/handshake.rs:59-61` |
| `bind_udp_addrs`：host `"*"` 未处理（走 DNS 报费解错误）；域名只取首个解析地址；名字带 udp 却被 TCP 监听复用（`server.rs:37-39`）——改名 `resolve_listen_addrs` | `src/common/network.rs:46-67` |
| `dial=` 接受 IPv4-mapped IPv6（`dial6` 在 `:49-51` 已拒绝，补齐一致） | `src/common/dial.rs:57-64` |
| `constant_time_equal` 手写实现 → 统一用 `subtle`（已在依赖） | `src/common/socks/protocol/handshake.rs:120-129` |
| `Credentials::from_shared_key` 不校验 hex（`for_service` 校验），hex 校验下沉统一 | `src/protocol/auth.rs:84-95` |
| 手写 HKDF 派生 → 可换 `hkdf` crate（可选，降审计成本非缺陷） | `src/protocol/auth.rs:104-110` |
| `reassembly.rs:140-157` 校验链条件顺序耦合（无下溢安全依赖前一子句先求值），把 payload 上界并入 `validate_fragment_metadata` | `src/protocol/reassembly.rs:140-157` |
| `replay.rs` `remove()` 链遍历无不变量防护（`current == EMPTY` 越界），加 `debug_assert` | `src/portal/replay.rs:126-140` |
| idle 超时与 activity 同 tick 就绪时 `select!` 随机分支可能误杀活跃流——`activity.notified()` 放 `biased` 首位 | `src/portal/forward/udp.rs:213-227` |
| `*buffer = Vec::new();` 死赋值 | `src/portal/forward/udp.rs:148-150` |
| morph acceptor 缓冲无显式上限（rustls 16MB/消息），累加已读字节超 64KB 提前返回 | `src/portal/prehello.rs:35-56` |
| QUIC auth 双段预算共 2×`handshake_timeout`（TCP morph 是 1×），统一共享 deadline | `src/portal/conn.rs:217-222` vs `:39-45` |
| `set_max_concurrent_bi_streams(1024)` 硬编码与 portal 级 flows 预算解耦，取 `min` 或提 config | `src/portal/conn.rs:271` |
| `if remaining == 0 && buf.remaining() != 0` 第二条件恒真，删除 | `src/transport/morph/tcp.rs:210-212` |
| `exhausted()` 用 `ErrorKind::Other`，2^38 终态与任意内部错误不可区分，改专用错误 | `src/transport/morph.rs:86-88` |
| `write_buffer` 只增不减 + `cipher_pos == write_offset` 不变量无注释（整段代码最关键的约定） | `src/transport/morph/tcp.rs:97,271-273` |
| GRO 尾段 ≤12B 时丢弃整批（含合法段），改为仅截断尾段 | `src/transport/morph/udp.rs:287-291` |
| `checked_sub(...).expect(...)` 依赖 quinn 常量假设，改返回错误 | `src/transport/morph/udp.rs:124-133` |
| `reserve_bounded` 的 limit 是软限制（`min(limit).max(required)`），改名 `reserve_at_least` 或 fail | `src/transport/buffers.rs:39-44` |
| 单次 sleep 无上限（rate=1B/s 时 18h），分片 sleep 使 cancel 可打断 | `src/transport/rate_bucket.rs:64-69` |
| 池化 buffer 脏读语义（只读 filled 区间的约定）无文档注明 | `src/transport/buffers.rs:108-118` |
| datagram 满丢弃加计数（并入 3.3） | `src/transport/quic_runtime.rs:132` |
| registration 期间 biased select 的 datagram 丢弃分支可饿死注册回执，先 poll registration | `src/egress/registration.rs:32-45` |
| probe cleanup 错误被 "client close timeout" 覆盖，`cleanup = cleanup.and(...)` 合并 | `src/toolbox/probe.rs:61-86` |
| status 任一实例失败即整体 bail，降级为面板内 `UNREACHABLE` 行并在 telemetry.md 写明 | `src/toolbox/status.rs:59-66` |
| `format.rs` 混用字节长度与字符数对齐 | `src/toolbox/format.rs:36-39` |
| rate 解析错误缺参数名；effective URL 手工拼接应走 `Url` | `src/egress/setup.rs:37-54` |
| diagnostic.rs 字符串前缀匹配错误链 → typed error + `downcast_ref`（较大，可独立 PR） | `src/toolbox/diagnostic.rs:8-113` |
| Windows named pipe accept：先 `take` 后 `create` 失败丢弃已接入客户端 + take→create 无监听窗口，先 `create` 再 `take` | `src/telemetry/local/windows.rs:339-351` |
| macOS `process_incarnation` 返回当前墙钟而非进程启动时间，注册表语义失真，改占位 0 | `src/telemetry/process.rs:31-43` |
| `publish` 的 `.pending` 残留永不清理，discovery 顺带清理 | `src/telemetry/local/unix.rs:97-100` |
| frame 首字节读取无 deadline，依赖调用方兜底，加文档注释或独立 idle deadline | `src/telemetry/ipc/frame.rs:114-131` |
| `&id[..16]` / `expect("valid name")` 靠调用点短路保护，改防御式 `id.get(..16).unwrap_or(id)` | `src/telemetry/local/unix.rs:109-114`、`ipc/client.rs:39` |

### 4.3 文档同步项

- `docs/egress.md`：补 standby expiry-close 竞态语义（随 2.1）。
- `docs/security.md`：morph 准入取舍（随 1.2）。
- `docs/interoperability.md`：域名校验放宽（随 2.4）。
- `docs/configuration.md`：`NOW_TCP_DATA_BUF_SIZE` 角色差异消除（随 3.1）、新增 env（`NOW_SOCKS_UDP_IDLE`、`NOW_UNAUTH_MAX`、`NOW_UNAUTH_PER_SOURCE`）。
- `docs/platforms.md`：Windows 不设 `SO_REUSEADDR` 的说明（随 0.4）。

---

## 阶段 5 — 测试补强（随对应修复同 PR 交付）

按价值排序：

1. **SOCKS 端到端**（目前完全空白，随 0.3/1.5）：CONNECT 成功路径——reply 字节、经 `relay_tcp` 双向数据、半关闭 drain 语义；UDP association 数据通路——收包 → flow 映射 → tunnel → 回包、FRAG≠0 丢弃、源不匹配、队列满。
2. **`egress/registration.rs` 直测**（零覆盖，随 1.1/1.6）：BUSY(0x01)、invalid reply、datagram 丢弃分支公平性。
3. **`quic_runtime` dispatch 路由**（最大缺口，随 2.6/3.3）：把纯路由逻辑从 quinn 依赖中抽出后测——flow_id 方向位校验、耗尽 draining、Close 帧处理、channel 满丢弃 + 计数、`UdpRoute::Drop` 清理。
4. **admission**（随 0.1/1.2）：`enable()` 竞态确定性测试、IPv6 /64 聚合行为、dual-stack 假设保护（listener 改双栈时 `::ffff:0:0/96` 塌缩为单键的回归）。
5. **Egress expiry**（随 2.1）：fake Portal 支持主动关闭 standby。
6. **可选**：cargo-fuzz 目标——prehello 读取路径、SOCKS 解码、`udp_flow/framing.rs`（现有 2 万次确定性变异语料的部分替代）。

---

## 排期与依赖

| 周 | 内容 | 说明 |
|---|---|---|
| 1 | 0.1、0.2、0.4、2.1、2.6、1.6 | 全部小改动高价值；0.2 与 3.1 的 flow-control 启动化重叠，建议 3.1 第 1 步（profile 启动化）同批做 |
| 2–3 | 0.3、1.1、1.4、1.5 | 0.3 单独 PR（超时语义设计）；1.1 与 `96c21bf`/`af6ea32` 同语义域，同一批评审 |
| 3–4 | 1.2、1.3、2.2、2.3 | 1.2 是行为变更，提前发 RFC 说明 |
| 4–5 | 2.4、2.5、3.1 收尾、3.2–3.4 | |
| 持续 | 阶段 4 搭车、阶段 5 随 PR | |

关键依赖：2.1 ← 测试基建（fake Portal 主动关闭）；1.2 ← security.md 取舍评审；2.4 ← interoperability.md + 变异语料更新。

## 明确不改动清单

评审确认健全、改动收益低回归风险高：

- **Morph 密码学结构**：方向密钥隔离（6 子密钥 HKDF 派生）、prelude 全位认证（tag 覆盖 nonce/prefix/全部 32 个高位）、2^38 字节限流与 reseed 边界数学、TCP 无帧结构下 `cipher_pos == write_offset` 不变量的 partial/Pending/Err 各路径回退（有专门测试）。
- **Replay 两阶段提交**：`precheck` → TLS ClientHello → `commit` 的 TOCTOU 收口、1024-bit 滑动窗口位移 carry、FIFO 逐出（有参考模型对拍测试）。
- **rate_bucket 连续时间记账**（"欠债前移 `updated_at`"）、**buffers 池脏读约定**（调用方只读 filled 区间）、**owned_io**、**stats 的 Relaxed 序**（独立计数器语义正确）。
- **auth.rs 的 HKDF 派生本身**（正确；换 `hkdf` crate 列为 4.2 可选项）。
