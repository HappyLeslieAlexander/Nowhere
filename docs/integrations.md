# Integrations

Launch Nowhere services and observe them through public process and IPC interfaces.

## Contents

- [Service processes](#service-processes)
- [Local observation](#local-observation)
- [Subscriber workflow](#subscriber-workflow)
- [Deployment boundaries](#deployment-boundaries)

## Service processes

Each Vector, Portal or Egress runs as a service process with its own Telemetry
subsystem. Configure it with a [role URL](configuration.md), supervise its
lifetime and allow the bounded shutdown to complete.

| Role | Integration point |
|---|---|
| Vector | SOCKS5 ingress through `in`; one transport selected by `net` |
| Portal | Declared listeners and one fixed `out` |
| Egress | Outbound QUIC registration; target dialing when selected by Portal |

`nowhere probe` performs a one-shot setup check without an ingress listener.
`nowhere status` reads a local snapshot and exits. See [Operations](operations.md)
for diagnostics and [Platforms](platforms.md#process-control) for process signals.

## Local observation

Telemetry stays inside each service process. Each instance publishes its own
protected local IPC endpoint; status and subscribers connect to those endpoints.

```text
+---------------+     +---------------+     +---------------+
|     Vector    |     |     Portal    |     |     Egress    |
|   Telemetry   |     |   Telemetry   |     |   Telemetry   |
+-------+-------+     +-------+-------+     +-------+-------+
        |                     |                     |
        +---------------------+---------------------+
                              |
           +------------------v------------------+
           |     Protected local IPC endpoints   |
           +------------------+------------------+
                              |
           +------------------+------------------+
           |                                     |
+----------v----------+               +----------v----------+
|    nowhere status   |               |   IPC subscribers   |
+---------------------+               +---------------------+
```

A service maintains statistics and lifecycle even without subscribers or stdout
logging. Consumers use length-prefixed JSON directly. The
[Telemetry contract](telemetry.md), [schema](telemetry/schema.json) and
[examples](telemetry/examples.json) define discovery and messages independently
of Rust private modules and status text.

## Subscriber workflow

1. Discover an instance in the local per-user registry.
2. Validate permissions, endpoint namespace, peer and process identity.
3. Connect and validate Hello against discovery; send no data.
4. Read the initial Snapshot, then consume state updates, diagnostics, Flow events and Gap.
5. On disconnect, rediscover and reconnect.

All connections receive the same stream, without historical replay. Snapshot
contains current lifecycle and registration state. Flow finishes carry only ID,
time and result; collectors correlate available starts and tolerate missing ones.
Diagnostics use context and reason codes. Preserve counter precision, tolerate
unavailable samples and avoid treating per-process totals as unique end-to-end
traffic.

The [independent client](../src/tests/telemetry/headless.py) demonstrates Unix
framing, identity checks, passive streaming and snapshots using Python's standard
library. See [Testing](testing.md#headless-ipc-check) for running it.

## Deployment boundaries

The service and collector share an operating-system user and the platform's
system temporary directory. In containers, they also share the same container
and namespaces. Telemetry uses Unix sockets or local Windows named pipes;
it does not publish an HTTP or network service.

Use the [ecosystem guide](ecosystem.md) for client, deployment and controller
projects. Their own documentation defines the interfaces they support.
