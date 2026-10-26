# Testing

Validate protocol behavior, service lifetimes and observations with reproducible
checks and measurements.

## Contents

- [Prerequisites](#prerequisites)
- [Standard checks](#standard-checks)
- [Native validation](#native-validation)
- [Test layout](#test-layout)
- [Regression requirements](#regression-requirements)
- [Headless IPC check](#headless-ipc-check)
- [Performance measurements](#performance-measurements)

## Prerequisites

Use a stable Rust toolchain with `rustfmt` and `clippy`. Network tests require
IPv4 and IPv6 loopback, `localhost` resolution for both families, and permission
to open local sockets. The headless IPC check additionally requires Python 3
and a Unix host. Tests use ephemeral ports and generated certificates.

## Standard checks

Run from the repository root:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo build --release --locked
git diff --check
```

Run a focused regression while developing, then run the full suite before
submitting a change:

```sh
cargo test --locked protocol::
cargo test --locked portal::tests::
cargo test --locked telemetry::
```

## Native validation

The [CI workflow](../.github/workflows/ci.yml) runs formatting, strict Clippy
and all test targets on Linux, macOS and Windows. Start it manually with
`workflow_dispatch` when needed.

| Host | Native boundaries |
|---|---|
| Linux | Sockets, Unix IPC, namespace identity, permissions and `/proc` process identity |
| macOS | Sockets, Unix IPC, permissions and process shutdown |
| Windows | Sockets, named pipes, ACLs, peer identity and console shutdown |

Native execution validates operating-system behavior. Cross-compilation
checks buildability and does not replace these runs. Shared protocol and
forwarding requirements apply to all three platforms. When test totals differ,
record the conditionally compiled test names and the boundaries they cover.

### Linux checks on macOS

[The Linux check script](../scripts/check-linux.sh) runs formatting, Clippy
and tests in Apple Container. It supplies IPv6 `localhost`
resolution for the container's network tests:

```sh
./scripts/check-linux.sh
```

## Test layout

All tests, fixtures and helper programs live under `src/tests/`. Production
modules mount private test modules with `#[cfg(test)]` and `#[path]`. Test
helpers are compiled only for tests; regression cases exercise production codecs,
connection paths and resource owners.

Test files mirror the module path below `src/`. For example,
`src/vector/socks/udp.rs` mounts `src/tests/vector/socks/udp.rs`, and
`src/toolbox/mod.rs` mounts `src/tests/toolbox/mod.rs`. Split tests by the
production component they exercise.

| Location | Responsibility |
|---|---|
| `src/tests/common/` | Shared configuration, dialing, TLS and lifecycle helpers; nested SOCKS5 modules |
| `src/tests/protocol/` | Authentication, frame codecs, Target validation, UDP reassembly, parser mutations and fixed vectors |
| `src/tests/vector/` | Client configuration and carrier setup; nested SOCKS5 ingress and UDP framing |
| `src/tests/portal/` | Listener admission and configuration; connection security, Egress ownership and forwarding matrices |
| `src/tests/egress/` | Service construction and registered connection ordering |
| `src/tests/transport/` | QUIC ownership, Morph, flow control, buffering and statistics |
| `src/tests/telemetry/` | Minimal statistics contract and endpoint privacy; nested IPC framing, registry and subscriber lifetimes |
| `src/tests/toolbox/` | Key generation, certificate inspection, probe, status and diagnostics |
| `src/tests/main.rs` | CLI parsing and command behavior |

Cross-module integration tests live under the owning service. Portal's
`mod.rs` provides the shared harness; `conn.rs`, `egress.rs` and `forward/`
cover the service's connection, exit and forwarding boundaries. Shared fixtures
use `support.rs` or `*_support.rs`, including test-only resource accessors.

Rust files begin with the copyright notice, SPDX identifier and a `//!` module
purpose. Python helpers use the same license notice and a module docstring.
Keep JSON fixtures valid JSON; describe their contract in this guide and in
the tests that consume them.

The fixed
[`protocol/vectors.json`](../src/tests/protocol/vectors.json) records the protocol
identifier inside the fixture. Its expected bytes are independent reference
values: do not generate expected output with the implementation under test.
When wire bytes change, update the specification, vectors and codec tests together.

## Regression requirements

| Area | Required cases |
|---|---|
| Wire contract | KDF/Auth/Morph vectors, FlowStart, Target, SetupResult and DATAGRAM bytes; reserved bits and truncated inputs |
| Authenticated Prelude | Fixed Tag/tail, every Bootstrap bit, policy/high-bit preservation, shared Counter exhaustion/cancellation, FIFO/window reference model, concurrent commit, strict Tag/Counter rejection, Legacy rejection and unbound ClientHello behavior |
| Authentication | ALPN, role and transport mismatch; fresh/resumed replay; pre-authentication admission, zero linger through Vector AuthFrame validation and post-authentication windows |
| Forwarding | TLS/QUIC × direct/SOCKS5/Egress × TCP/UDP, IPv4/IPv6, Morph and concurrent Vectors |
| Lifetime | Half-close, handshake/authentication/registration cancellation, setup cancellation, idle timeout, UDP control FIN/reset/stop, late DATAGRAMs and bounded drain |
| Egress | ACCEPTED ordering, BUSY, immediate offline failure, reconnect and stale-owner cleanup |
| Configuration | Role-specific endpoint carrier counts and families, first duplicates, ignored unknowns, percent decoding, conflicts, effective configuration and explicit bind failure |
| Telemetry | Known-byte counters, ownership counts, passive snapshots, ignored input, EOF and write timeout cleanup |
| IPC | Frame/client limits, permissions, identity/incarnation checks, PID reuse and namespace isolation |

A change to a resource owner must cover failure and cancellation as well as
success. Assert that active counts and permits are released once. Parser mutation
tests supplement explicit boundary cases; they do not establish exhaustive fuzz
coverage. Keep live-service waits bounded and terminate spawned processes during
cleanup, including assertion failures.

## Headless IPC check

Build the release executable, then run the independent subscriber:

```sh
python3 src/tests/telemetry/headless.py ./target/release/nowhere
```

The script launches Portal and Vector with redirected standard streams. Using
only Python's standard library and the public length-prefixed JSON interface,
it checks discovery, identity, passive reconnection, known instance logical byte
counts, one-shot status and shutdown cleanup. It requires neither a terminal nor
Rust module access.
Windows named-pipe, ACL and peer-identity checks belong to the native Rust suite.

## Performance measurements

### Control the comparison

Build each compared revision in a separate source and Cargo target directory.
Record revision, toolchain, host/OS, build flags, binary hash and runtime settings.
Compare equivalent direct paths, and report Egress paths as a separate group.
Keep certificate verification, Morph, worker count, transport windows, memory
budgets, packet sizes, pacing and concurrency consistent.

### Repeat and report

Repeat measurements with rotated case order. Report the number of runs and
distributions rather than a single best value:

| Measurement | Required context |
|---|---|
| Flow setup | First connection versus reused QUIC connection; TLS opens one connection per Flow |
| TCP throughput | Payload size, concurrency, direction and elapsed interval |
| UDP PPS/loss | Packet size, offered rate, fragmentation, delivery interval and receive timeout |
| Resources | CPU, idle/peak RSS, tasks, descriptors and values after cleanup |
| Observation overhead | No collectors, one collector, multiple collectors and slow readers |
| UDP control cost | Incremental resources relative to a warmed connection without UDP Flows |

### Account for resources and loss

Check known logical byte counts alongside measurements. Measure carrier traffic
with external instrumentation when needed. Report retained RSS separately from live Flow/task/descriptor counts. Unpaced fragmented
bursts can overflow bounded socket and application queues; end-to-end loss alone
does not identify the dropping layer. Explain profiling overhead and distinguish
instrumented results from normal release builds.

Keep raw samples, commands and build metadata with the measurement report outside
the source tree. Report regressions with a reproducer and an explanation. Binary
size and dependency reductions are separate from forwarding performance.
