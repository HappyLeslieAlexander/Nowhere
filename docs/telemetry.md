# Nowhere Telemetry

Observe local services through a protected, read-only JSON interface.

| Property | Value |
|---|---|
| Contract identifier | `nowhere.telemetry.3` |
| Transport | Unix domain sockets or local Windows named pipes |
| Framing | Four-byte length prefix and UTF-8 JSON |
| References | [JSON Schema](telemetry/schema.json) · [Examples](telemetry/examples.json) |

## Contents

- [Overview](#overview)
- [Discovery and identity](#discovery-and-identity)
- [Framing](#framing)
- [Messages](#messages)
- [Statistics](#statistics)
- [Delivery and ordering](#delivery-and-ordering)
- [Egress registration state](#egress-registration-state)
- [Privacy and trust](#privacy-and-trust)
- [Resource limits](#resource-limits)
- [Containers](#containers)
- [Status](#status)

## Overview

Each Vector, Portal and Egress process maintains its own statistics, lifecycle
and sampling, even without collectors or stdout logging. `nowhere status` and
third-party collectors read the same public interface. Telemetry runs inside
the service process and requires no separate daemon.

The service pushes current state, instance statistics, Flow events and anomaly
codes to every connected collector. It provides no control commands, historical
queries, replay or remote listener. Application versions do not select a protocol;
there is no capability negotiation or legacy compatibility layer. The schema
covers registry records and messages, with valid and invalid examples.

## Discovery and identity

Service and collector use the platform system temporary directory and the
same operating-system user. Each instance publishes one registry record at
startup; the record is not a periodically written log.

### Unix

The directory `nowhere-telemetry-nw3-<effective UID>/` is owned by that user with
mode `0700`. An instance atomically publishes
`nowhere.<32 lowercase hexadecimal instance ID>.json` with mode `0600`.

Its `endpoint` is a Unix socket in the same private directory. Socket filenames
use the first 16 hexadecimal characters of the random ID to fit platform path
limits. The socket has mode `0600` and is not a data-storage file.

### Windows

The directory suffix is the first 16 bytes of SHA-256 of the current user's SID,
encoded as lowercase hexadecimal. Endpoints are local byte-mode named pipes:

```text
\\.\pipe\nowhere-telemetry-nw3-<user suffix>-<instance ID>
```

Directories, files and pipes restrict access to that user. Remote pipe clients
are rejected. Windows `uid` is metadata only and is not an authorization ID.

### Validate discovery

| Registry field | Meaning |
|---|---|
| `protocol` | Contract identifier |
| `instance` | Registry name, UID, PID and process incarnation |
| `transport` | `unix_socket` or `named_pipe` |
| `endpoint` | Protected local IPC address |
| `namespace` | Process namespace identity |

Records contain no business address, configuration or traffic
history. Before trusting a record:

1. Check permissions, object type, endpoint namespace and peer identity.
2. Check that the filename matches the embedded instance identity.
3. On Linux, check namespace identity before PID checks or cleanup.
4. Validate the process incarnation and PID identity.
5. Match Hello's instance ID against discovery after connecting.

A failed connection alone does not establish that a record is stale. Remove
records only after confirming process death or an incarnation mismatch.
Unavailable process identity is not evidence of death. Instance IDs change
at every start; discovery and cleanup stay within the namespace specified here.

### Startup and cleanup

Services remove their registry record and socket on normal exit. If permissions,
identity, entropy or path length cannot be guaranteed, local IPC initialization
fails closed and forwarding continues with a warning. There is no fallback.

Hello includes an instance descriptor with role `vector`, `portal` or `egress`,
release version, endpoint and sampling interval.
See [Privacy and trust](#privacy-and-trust) for visible metadata.

## Framing

Every frame contains a four-byte unsigned big-endian payload length followed
by exactly that many UTF-8 JSON bytes. The length excludes its own prefix:

```text
+-------------------+---------------------------------------+
|   Length: u32 BE  |        UTF-8 JSON: length bytes       |
+-------------------+---------------------------------------+
```

Server JSON payloads are limited to 65536 bytes. Collectors send no data.

Read exactly the specified bytes; one read does not necessarily contain a
whole message. Zero lengths and invalid JSON are rejected. Preserve 64-bit
integer precision, for example with a lossless JSON parser rather than ordinary
JavaScript Number for counters and identifiers.

## Messages

After operating-system access and peer validation, the service sends `hello`,
then the current `snapshot`. No request is needed. All connections receive the
same message types. Any client input closes the connection without a reply;
EOF releases its resources. An idle connection has no subscription deadline.

| JSON `type` | Purpose |
|---|---|
| `hello` | Instance identity, role, version, endpoint and sampling interval |
| `snapshot` | Current lifecycle, registration state, counters and process samples |
| `diagnostic` | Anomaly context and fixed reason code |
| `access_start` | Local Flow ID, timestamp, protocol, target and carrier |
| `access_finish` | Local Flow ID, timestamp and one result code |
| `gap` | Number of events lost by a lagging receiver |

Flow IDs identify observations within one process, not wire Flow IDs or sessions
across processes. A validated request starts an observation; normal completion,
setup rejection, timeout, cancellation or task destruction ends it exactly once.
Invalid or unauthenticated requests do not create target Flow records.

A finish has only `sequence`, `id`, `timestamp_ms` and `result`. `success` means
normal completion; all other values are fixed reasons, including `resource_limit`,
`invalid_request`, `timeout`, `idle_timeout`, `cancelled`, `connection_refused`
and `unknown`. There are no per-Flow byte totals or duration fields. Collectors
can compute approximate duration from start and finish wall-clock timestamps;
clock adjustments can affect that difference.

A finish may arrive without a start after connection or event loss. Only the
start carries target and transport metadata. Collectors accept an incomplete
record rather than assuming replay or a current Flow inventory.

Diagnostics contain `sequence`, `timestamp_ms`, `context` and `reason`. Contexts
are `egress_connection`, `egress_registration`, `socks_admission`, `socks_accept`
and `socks_handshake`. They report anomalies outside Flow results. Normal carrier
connections, disconnections and reconnect attempts do not create diagnostics.
Consumers choose display text and severity from the codes. The
[schema](telemetry/schema.json) defines the complete code set and field ranges.

## Statistics

### Traffic direction and counters

Upload means Vector-to-Target traffic; download is the reverse. Direction does
not depend on which transport peer opens the connection. All byte counters are
cumulative business payload bytes. Each Flow uses one bidirectional Carrier:

| Counter group | Classification |
|---|---|
| `tcp_upload_bytes` / `tcp_download_bytes` | TCP business traffic |
| `udp_upload_bytes` / `udp_download_bytes` | UDP business traffic |
| `tls_upload_bytes` / `tls_download_bytes` | Payload handled by TLS carriers |
| `quic_upload_bytes` / `quic_download_bytes` | Payload handled by QUIC carriers |

Portal counts bridged logical bytes once. Carrier counters include payload
processed on each transport side; a QUIC-to-QUIC bridge processes those bytes
twice. Do not sum different processes' counters as unique end-to-end traffic.

Counters exclude encryption headers, retransmissions and IP overhead. They
are not interface bandwidth counters. Compute bytes per second from counter
and `uptime_ms` differences. Independently read atomic counters do not form a
transactional accounting ledger.

### Time, resources and active counts

| Field or value | Unit and meaning |
|---|---|
| `timestamp_ms` | Unix wall-clock milliseconds |
| `uptime_ms` | Process running time in milliseconds |
| `rss_bytes` | Resident memory in bytes |
| `cpu_percent` | Percentage of one CPU; may exceed 100 |
| `open_fds` | Open file descriptors, where available |
| Active Flow counts | Owned TCP and UDP business Flows |
| Active Carrier counts | Live TLS and QUIC transport ownership |

Unavailable resources and the first CPU sample are `null`. Active counts follow
resource ownership and decrement once on cleanup. See [Platforms](platforms.md#telemetry)
for host sampling support.

## Delivery and ordering

Snapshot sequence numbers count sampling and state updates. Lifecycle state,
reason and `lifecycle_timestamp_ms` record the latest lifecycle transition.
Sampling preserves those values and `egress_online`. State changes publish
immediately; updates coalesce, so intermediate states and a final exit state
are not guaranteed to arrive.

Event sequence numbers are monotonic within an instance and shared by diagnostics,
starts and finishes. Assignment and publication use the same lock. There is no
global ordering between snapshots and events. Each connection registers its event
receiver before initial messages are sent. A bounded 1024-entry broadcast queue
reports lag through `gap.data.missed`; it does not provide a recoverable offset.

On Gap, collectors discard assumptions about complete Flow histories. On
disconnect, rediscover and reconnect. Pre-connection events and disconnect periods
are not replayed. This is live observation, not an audit or billing ledger.

## Egress registration state

Snapshots include `egress_online`, with registration and connection ownership
as its source:

| Instance | Value |
|---|---|
| Portal with `out=egress` | Whether its Slot holds a valid registered QUIC connection |
| Egress | Whether ACCEPTED was received and that connection remains valid |
| Vector or another Portal output | `null`, meaning not applicable |

Applicable instances report `true` while their registered connection is valid
and `false` while offline. An idle registered Egress owns a Carrier and no
business Flow. Carrier counts cannot establish registration state.

Registration changes update snapshots. Connection ownership checks prevent an
old connection's cleanup from overwriting its replacement's online state.
See [Egress](egress.md).

## Privacy and trust

### Access boundary

The same operating-system user is the trust boundary. Different ordinary users
and remote clients cannot subscribe. Administrators and compromised same-user
processes are outside this isolation boundary.

A collector may retain or forward the information it legitimately receives;
the service cannot enforce later handling. Subscriber access is read-only.

### Visible metadata

Destination domains/IPs and ports are intentionally visible to authorized
collectors as validated `host:port` values; IPv6 is bracketed. Collectors can
therefore learn visited destinations. URLs, credentials, request paths and
query strings are invalid targets and become `<redacted>`.

Hello includes a validated service endpoint. Configuration summaries, SNI, pins,
client addresses and transport peer identities are not published. There are no
pseudonyms or identity caches. The endpoint defaults to empty when absent.
Flow carrier values are `tls` and `quic`, independent of business protocol.

### Diagnostics

Known setup results, cancellation, timeouts and limits map directly to fixed codes.
IO, TLS and QUIC failures are classified by concrete error types and nested causes.
Opaque errors become `unknown`; error strings are not searched for keywords.
Credentials, client addresses, certificate paths and raw error chains never enter
IPC diagnostics or Flow results. Independent stdout/stderr logs follow their own
policy.

## Resource limits

| Resource | Limit |
|---|---|
| Connected collectors | 16 per service; Windows also has a pending pipe instance |
| Server writes | Two-second deadline |
| Client partial-frame assembly | Five-second deadline |
| Event broadcast queue | 1024 entries |
| Encoded Flow/diagnostic event | Below 8192 bytes |

A full service closes new clients without spawning rejection tasks. Every
connection enables events until EOF, input, write failure or service shutdown.
There are no unbounded client queues, disk histories or service-side Flow
inventories. New Flow and diagnostic records are built only while event receivers
exist; cumulative statistics and current state continue independently.

## Containers

Service and collector run in the same container with the same user and temporary
directory. No telemetry port publication, host networking, privileges or extra
capabilities are needed.

Host-to-container, sidecar and cross-container subscriptions are outside this
contract. Do not share the telemetry directory across namespaces: matching
numeric UIDs and PIDs alone do not establish matching identities. See
[container deployment](platforms.md#container-image) for writable temporary
storage and non-root operation.

## Status

`nowhere status` reads a single snapshot and exits without a terminal. It shows
lifecycle, role, endpoint, uptime, Flow/Carrier counts, logical traffic,
CPU, RSS and file descriptors. Applicable Egress state displays ONLINE/OFFLINE;
unavailable resources display as a dash.

Instances are sorted by role, PID and instance ID. At most eight requests run
concurrently with a two-second deadline per instance. Successful snapshots
remain visible when another instance fails. Status does not add process traffic
totals together. See [Operations](operations.md#read-local-status).
