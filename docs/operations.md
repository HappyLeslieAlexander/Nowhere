# Operations

Inspect service state, diagnose setup and manage the lifetime of running instances.

## Contents

- [Read local status](#read-local-status)
- [Diagnose target setup](#diagnose-target-setup)
- [Check deployment settings](#check-deployment-settings)
- [Monitor Egress](#monitor-egress)
- [Understand failure boundaries](#understand-failure-boundaries)
- [Manage capacity and shutdown](#manage-capacity-and-shutdown)

## Read local status

Read one snapshot from the local service processes:

```sh
nowhere status
```

Status discovers protected IPC endpoints, queries at most eight instances at a
time with a two-second deadline per instance, and exits without requiring a
terminal. Results are sorted by role, PID and instance ID. Successful snapshots
remain visible when another instance fails; partial failures are reported.

| Display | Meaning |
|---|---|
| Status, role, endpoint and uptime | Process identity and lifecycle |
| Egress | ONLINE or OFFLINE where registration applies |
| Traffic | Logical upload/download in the Vector-to-Target direction |
| Flows and Carriers | Active business Flows and transport ownership |
| CPU, Memory and FDs | Resource samples; unavailable values display as a dash |

Each process maintains Telemetry without subscribers or stdout logging.
Collectors use [public JSON IPC](telemetry.md); status text is a human interface.
Do not add different processes' traffic totals as unique end-to-end bytes.

## Diagnose target setup

Perform one real TCP Flow setup using Vector's configured transport:

```sh
nowhere probe "vector://KEY@relay.example:2000?pin=TRUSTED_SHA256" "example.com:443"
```

`in` is optional for probe. READY verifies the selected Portal output; probe
sends no target payload. Output failures return the fixed SetupResult described
in the [wire specification](protocol.md#setup-results).

Read a presented certificate over TCP/TLS:

```sh
nowhere fingerprint "nowhere://KEY@relay.example:2000"
```

Compare the result through a trusted channel before configuring a pin.
Fingerprint inspection accepts `nowhere://` links. It queries TCP/TLS only;
see [Security](security.md#certificate-trust).

Running `nowhere` without arguments displays help and exits normally.

## Check deployment settings

Expose the declared Portal carrier ports and the intended SOCKS ingress.
Confirm certificate trust, Morph agreement, `in`, `net` and `out`. Startup INFO
shows the effective role URL with explicit defaults and redacted credentials.

Unknown URL parameters are ignored. The first recognized duplicate wins, and
an invalid first value is an error. Portal uses `out=direct` when `out` is absent.
See [Configuration](configuration.md#parsing-and-effective-configuration) for
parsing and redaction rules, and [Platforms](platforms.md#network-exposure) for
firewall and container exposure.

## Monitor Egress

Portal's `out` is fixed for its lifetime. `out=egress` requires a QUIC listener
and cannot specify target `dial*`. New Flows fail immediately while Egress is
offline; a second registrant receives BUSY.

ONLINE means registration ownership is valid. An idle Egress adds one Carrier
and no business Flow. Watch Runtime registration events and snapshots for
changes; Carrier totals do not infer ONLINE. See [Egress](egress.md).

## Understand failure boundaries

| Failure | Effect |
|---|---|
| Ordinary setup or forwarding failure | Ends the affected Flow |
| Authentication or business Stream direction violation | Closes the connection |
| Egress connection loss | Ends every dependent bridge |
| UDP control FIN, RESET, STOP_SENDING, idle timeout or connection loss | Reclaims that Flow's routes and resources |

TLS is dedicated per Flow. QUIC carries business Streams in one initiation
direction. Reconnection starts new Flows. UDP control Streams remain open
through their lifetime; losing a CLOSE DATAGRAM does not keep a route alive.

## Manage capacity and shutdown

Admission and business resources are bounded. UDP budgets cover queued and
reassembly bytes; full Flow queues drop datagrams without blocking the
connection dispatcher. A shared Egress also shares congestion and budgets.
Observe per-process and per-Flow behavior when choosing concurrency or rate
settings. Use [Testing](testing.md#performance-measurements) for measurements.

Shutdown stops admission, cancels service work and drains within
`NOW_SHUTDOWN_TIMEOUT` (default `5s`). Tasks and owned resources are reclaimed;
active counters decrement with their owners. A timed-out drain aborts remaining
tasks. QUIC UDP ID exhaustion also stops new Flows and closes or reconnects
after bounded drain, without an additional protocol frame.

See [process control](platforms.md#process-control) for native shutdown signals.
