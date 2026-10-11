# Telemetry

Nowhere publishes only cumulative logical traffic and active Flow counts over
protected local IPC. Service logs use stdout and stderr.

The protocol identifier is `nowhere.telemetry.3`.
[JSON Schema](telemetry/schema.json) and [examples](telemetry/examples.json)
define the messages. All roles use the same contract.

## Contents

- [Discovery and identity](#discovery-and-identity)
- [Framing](#framing)
- [Messages](#messages)
- [Statistics](#statistics)
- [Delivery and ordering](#delivery-and-ordering)
- [Privacy and trust](#privacy-and-trust)
- [Resource limits](#resource-limits)
- [Containers](#containers)
- [Status](#status)

## Discovery and identity

Service and collector use the platform system temporary directory and the
same operating-system user. Each instance publishes one registry record at
startup; the record is not a periodically written log.

### Unix

The directory `nowhere-telemetry-3-<effective UID>/` is owned by that user with
mode `0700`. An instance atomically publishes
`nowhere.<32 lowercase hexadecimal instance ID>.json` with mode `0600`.

Its `endpoint` is a Unix socket in the same private directory. Socket filenames
use the first 16 hexadecimal characters of the random ID to fit platform path
limits. The socket has mode `0600` and is not a data-storage file.

### Windows

The directory suffix is the first 16 bytes of SHA-256 of the current user's SID,
encoded as lowercase hexadecimal. Endpoints are local byte-mode named pipes:

```text
\\.\pipe\nowhere-telemetry-3-<user suffix>-<instance ID>
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
fails closed and forwarding continues with an error on stderr. There is no fallback.

Hello includes an instance descriptor with role `vector`, `portal` or `egress`,
release version and endpoint.
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

The server sends `hello`, an immediate `snapshot`, then a `snapshot` every second.
Clients send no commands. Any input is read and discarded without parsing;
EOF or an I/O error closes the connection and releases its connection slot.
An idle read-only client remains connected. Reconnection begins with a new Hello
and the latest statistics.

Hello contains `instance`: `telemetry_protocol`, random `id`, `role`, `pid`,
`version` and validated `endpoint`. Identity checks precede trusting statistics.

Snapshot contains exactly six integer fields:

| Field | Meaning |
|---|---|
| `tcp_upload_bytes` | Cumulative TCP payload toward the target |
| `tcp_download_bytes` | Cumulative TCP payload toward the Vector |
| `udp_upload_bytes` | Cumulative UDP payload toward the target |
| `udp_download_bytes` | Cumulative UDP payload toward the Vector |
| `tcp_active` | Currently owned TCP business Flows |
| `udp_active` | Currently owned UDP business Flows |

## Statistics

Upload follows Vector → Portal → optional Egress → Target. Download follows
the reverse direction. Protocol framing, authentication, Morph, encryption,
QUIC control traffic and retransmissions do not contribute to logical payload
counters. A UDP association may own several target Flows. A target Flow becomes
active after setup; its owner releases the count on completion or cancellation.

Counters accumulate from process startup even without IPC clients. Each process
accounts for its own work. Adding Portal, Vector and Egress totals does not yield
unique end-to-end traffic. Preserve unsigned 64-bit precision in consumers.
Counters and active counts are independent atomic reads, not a transactional
multi-field sample. Active counts are nonnegative in normal ownership operation.

Nowhere does not persist counters. OpenCtrl keeps cumulative totals across child
restarts and supports explicitly resetting its displayed totals. Reconnecting to
the same process replaces its latest values and must not add the sample twice.

## Delivery and ordering

A connection delivers ordered snapshots of current statistics; there is no event
history, replay, sequence number, sampler timestamp, state or log message.
The consumer records receive time and derives throughput from differences.
Active counts may lag by approximately one second.

Writing one frame has a two-second limit. Clients should connect and read complete
messages with a five-second deadline. OpenCtrl disconnects and retries after a
read timeout, clears stale active counts, preserves cumulative bytes and keeps
process status unchanged.

## Privacy and trust

IPC requires the local user, platform permissions, process identity and namespace
checks described above. Hello excludes credentials; its endpoint is validated.
IPC contains no targets, client addresses or errors.

Service stdout contains startup configuration without credentials, TLS
fingerprints and graceful shutdown information. Service stderr contains original
exception details and their cause chains; addresses and file paths may appear.
Errors are constructed without passwords, Shared Keys or complete credential
URLs. Logs use `2026-10-11T08:30:00.123Z message`, without levels or ANSI colors.
Embedded newlines are escaped so each record occupies one line.

OpenCtrl reads both child streams and forwards the original text through SSE.
It retains no log history, applies no error classification, and does not infer
process state from text. Normal Flow starts, successful finishes, normal EOF,
active cancellation and ordinary UDP idle cleanup produce no access logs.

## Resource limits

There are at most 16 IPC connections. Frames are at most 64 KiB and each write
has a two-second timeout. Input is discarded through a fixed-size buffer.
Slow writers, EOF and I/O errors release connection resources. There are no
subscription timers, event queues or configurable sampling intervals.

## Containers

The publisher and consumer share the same user, temporary directory, container
and process/network namespaces. Permissions and peer validation remain enabled.
Host-to-container and cross-container observation are outside the contract.

## Status

`nowhere status` reads Hello and the first Snapshot with a two-second per-instance
deadline. It displays role, PID, instance ID, endpoint and the six statistics.
Service process state is the supervisor's responsibility.
