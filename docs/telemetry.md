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
- [Subscriptions and messages](#subscriptions-and-messages)
- [Statistics](#statistics)
- [Delivery and ordering](#delivery-and-ordering)
- [Egress registration state](#egress-registration-state)
- [Privacy and trust](#privacy-and-trust)
- [Resource limits](#resource-limits)
- [Containers](#containers)
- [Status](#status)

## Overview

Each Vector, Portal and Egress process maintains its own statistics, lifecycle
and sampling, even without subscribers or stdout logging. `nowhere status` and
third-party collectors read the same public interface. Telemetry runs inside
the service process and requires no separate daemon.

The contract supports local observation and subscription changes. It does not
provide service control, configuration, file access, execution, historical
queries or replay. There is no network listener, TCP fallback, remote endpoint
or application authentication token.

This is one fixed contract without capability negotiation. Application release
versions do not select a protocol. Changes to public fields or semantics
require a separate compatibility review. The schema covers registry records
and every message; the examples include valid and invalid commands.

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

Records contain no business address, configuration, pseudonym key or traffic
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
release version, endpoint, sampling interval and sanitized `config_summary`.
See [Privacy and trust](#privacy-and-trust) for visible metadata.

## Framing

Every frame contains a four-byte unsigned big-endian payload length followed
by exactly that many UTF-8 JSON bytes. The length excludes its own prefix:

```text
+-------------------+---------------------------------------+
|   Length: u32 BE  |        UTF-8 JSON: length bytes       |
+-------------------+---------------------------------------+
```

| Direction | Maximum JSON payload |
|---|---:|
| Server to collector | 65536 bytes |
| Collector to server | 1024 bytes |

Read exactly the specified bytes; one read does not necessarily contain a
whole message. Zero lengths and invalid JSON are rejected. Preserve 64-bit
integer precision, for example with a lossless JSON parser rather than ordinary
JavaScript Number for counters and identifiers.

## Subscriptions and messages

### Initial subscription

The server verifies operating-system access and sends `hello`. Send `subscribe`
within five seconds. No snapshots or events arrive before subscription:

```json
{"type":"subscribe","data":{"request_id":1,"subscription":"detail"}}
```

The server acknowledges with `subscribed`, echoing the request ID and mode,
then sends the current `snapshot` and `lifecycle`:

```text
     Collector                                                Service
         |                                                       |
         |----------- Connect to protected local IPC ----------->|
         |<----------------------- hello ------------------------|
         |---------- subscribe: detail, request_id=1 ----------->|
         |<---------- subscribed: detail, request_id=1 ----------|
         |<---------------------- snapshot ----------------------|
         |<--------------------- lifecycle ----------------------|
         |<- runtime_event / access_start / access_finish / gap -|
         |                                                       |
```

### Delivery modes

| Mode | Delivery |
|---|---|
| `summary` | Snapshot and Lifecycle |
| `detail` | Summary messages plus Runtime, Access and Gap |

Send another `subscribe` to switch modes. Its acknowledgement establishes the
new delivery mode; previously sent messages may arrive before that
acknowledgement. A mode switch does not trigger another initial snapshot or
lifecycle message.

Access finishes are self-contained and may arrive without a start. Late
subscribers receive no inventory of individual active Flows. The publisher
assigns Access IDs and timestamps; they identify one local observation, not a
wire Flow ID or cross-process session.

| Access outcome | Meaning |
|---|---|
| `success` | Normal completion |
| `rejected` | A validated request was refused by Flow admission or SetupResult |
| `timeout` | Setup, relay or UDP idle timeout |
| `cancelled` | Setup cancellation, service shutdown or Carrier termination |
| `error` | Target, transport or protocol failure |

Invalid or unauthenticated requests do not create target Access records.

### Message reference

| JSON `type` | Purpose |
|---|---|
| `hello` | Instance identity, configuration metadata and current lifecycle |
| `subscribed` | Request ID and accepted subscription mode |
| `snapshot` | Cumulative counters, active resources, samples and Egress state |
| `lifecycle` | Process state, reason and timestamp |
| `runtime_event` | Sanitized runtime diagnostic |
| `access_start` | Validated target and initial Flow metadata |
| `access_finish` | Self-contained outcome, duration and logical byte totals |
| `gap` | Count of detailed events missed by a lagging receiver |
| `error` | Fixed error code; invalid commands end the connection |

The [schema](telemetry/schema.json) defines every field and its value range.
Commands are limited to the documented subscription shape.

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
| `ping_ms` | RTT in milliseconds |
| `rss_bytes` | Resident memory in bytes |
| `cpu_percent` | Percentage of one CPU; may exceed 100 |
| `open_fds` | Open file descriptors, where available |
| Active Flow counts | Owned TCP and UDP business Flows |
| Active Carrier counts | Live TLS and QUIC transport ownership |

Unavailable resources and the first CPU sample are `null`. Active counts follow
resource ownership and decrement once on cleanup. See [Platforms](platforms.md#telemetry)
for host sampling support.

## Delivery and ordering

Snapshot sequence numbers count captures and registration-state updates.
Snapshots may initially have sequence zero. Detailed event sequence numbers
are monotonic within an instance and shared by runtime/start/finish messages.
They are assigned under the same lock as publication.

Snapshot and Lifecycle updates coalesce. There is no global ordering across
message categories. Detailed events use a bounded 1024-entry broadcast queue;
`gap.data.missed` reports receiver lag rather than a recoverable offset.

Summary periods, pre-subscribe periods and disconnects have no replay guarantee.
On disconnect, rediscover and resubscribe. Delivery continuity is not assumed.
This is live observation, not an audit or billing ledger.

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

Registration changes update snapshots and emit Carrier Runtime events.
Offline Egress state clears RTT; a late sample cannot restore the old RTT.
Ownership transitions and snapshot publication are serialized so stale cleanup cannot
overwrite a new connection's online state. See [Egress](egress.md).

## Privacy and trust

### Access boundary

The same operating-system user is the trust boundary. Different ordinary users
and remote clients cannot subscribe. Administrators and compromised same-user
processes are outside this isolation boundary.

A collector may retain or forward the information it legitimately receives;
the service cannot enforce later handling. Subscriber access is read-only.

### Local pseudonyms

Client addresses are replaced before publication with instance-local numbers
such as `C001`. Source ports are ignored, so successive connections from the
same client IP share a number. The immediate transport `peer` uses a separate
`P001` numbering space and retains endpoint-level identity. Vector identifies
its Portal; Portal and Egress identify the peer that opened the Flow.

Numbers reset after restart and have no identity meaning across instances.
Each category caches at most 4096 keyed identity digests, never raw addresses.
When full, the oldest entry is evicted; a later occurrence gets a new number.
Numbers are never reused within a process. Access events contain one optional
`peer` and one `carrier` shared by both traffic directions.

### Visible metadata

Destination domains/IPs and ports are intentionally visible to authorized
collectors as validated `host:port` values; IPv6 is bracketed. Collectors can
therefore learn visited destinations. URLs, credentials, request paths and
query strings are invalid targets and become `<redacted>`.

Hello includes validated instance endpoints and an allowlisted effective
configuration summary:

| Visible | Redacted |
|---|---|
| Listen, Portal, ingress and fixed output endpoints | Shared Key and SOCKS credentials |
| Carrier, TLS mode, Morph and rate limits | Raw configuration URLs |
| `dial` or `dial4`/`dial6` selections, SNI and pin presence | Certificate and private key paths |

The endpoint and summary default to empty when absent; report unavailable
metadata in that case. Collectors using a closed instance schema must include
these fields. Access `carrier` values are `tls` and `quic`, independent of the
business `protocol` (`tcp` or `udp`). `peer` is `null` when unavailable.

### Diagnostics

Runtime events use `message` for a safe diagnostic template and an optional
classified reason, such as `TLS carrier connection failed: connection refused`.
Only known templates and a closed reason vocabulary are published. Unknown
details become `operation failed`.

Access errors use the same vocabulary, including DNS failure, timeout,
certificate failure and connection refusal. Lifecycle messages use whitelisted
reasons such as `STOPPED: START_FAILED`. Nested diagnostic causes are classified;
keys, passwords, tokens, authentication data and raw error chains never leave
the publisher through IPC.

Privacy is enforced by the publisher for every subscriber. Independent
stdout/stderr business logs follow their own policy.

## Resource limits

| Resource | Limit |
|---|---|
| Connected collectors | 16 per service; Windows also has a pending pipe instance |
| Server writes | Two-second deadline |
| Initial subscription and partial-frame assembly | Five-second deadlines |
| Command rate | Token bucket of eight, replenished at four per second |
| Detailed event broadcast queue | 1024 entries |
| Encoded detailed event | Below 8192 bytes |

A full service closes new clients without spawning rejection tasks. An idle
subscribed client remains connected while sending no commands. Invalid commands
close the connection; any error reply contains only a fixed code.

Detailed events use bounded identifiers, validated targets and peer metadata.
There are no unbounded client queues or disk histories. Access finishes require no
client-side start cache. New access records are built only while Detail
subscribers exist; cumulative statistics continue independently.

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
lifecycle, role, endpoint, uptime, Flow/Carrier counts, logical traffic, RTT,
CPU, RSS and file descriptors. Applicable Egress state displays ONLINE/OFFLINE;
unavailable resources display as a dash.

Instances are sorted by role, PID and instance ID. At most eight requests run
concurrently with a two-second deadline per instance. Successful snapshots
remain visible when another instance fails. Status does not add process traffic
totals together. See [Operations](operations.md#read-local-status).
