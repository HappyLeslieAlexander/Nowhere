# Interoperability

Implement compatible Vector, Portal and Egress peers using the transport,
ordering and lifetime requirements below. The [Nowhere Wire Protocol](protocol.md)
defines the exact byte layouts, cryptographic labels and encoding rules.

## Contents

- [Transport and authentication](#transport-and-authentication)
- [Flow direction and framing](#flow-direction-and-framing)
- [UDP delivery and lifetime](#udp-delivery-and-lifetime)
- [Morph](#morph)
- [Reference vectors and observation](#reference-vectors-and-observation)

## Transport and authentication

| Requirement | Contract |
|---|---|
| TLS | TLS 1.3 with system CA trust and hostname verification, or an exact certificate SHA-256 pin |
| ALPN | `nw3` only; missing or other values are rejected without negotiation or fallback |
| Early data | 0-RTT is disabled, including on resumed connections |
| Shared Key | Exactly 32 lowercase hexadecimal text characters after one percent decode; no password component |
| Authentication | Exactly one 16-byte tag bound to role, transport and the normal TLS exporter |

Shared Key enters the KDF as text bytes, without hexadecimal decoding. Malformed
percent escapes are invalid. Authentication uses the normal TLS exporter rather
than the early exporter; tags are compared in constant time and cannot be reused
across connections, resumed connections, roles or transports.

The [role KDF](protocol.md#authentication) distinguishes Vector and Egress. TLS
permits Vector only; QUIC permits either role. One Shared Key derives both role
keys and grants both authorities; derivation does not create independent
permissions.

## Flow direction and framing

### Connection establishment

Transport roles and business Flow directions are fixed for each connection:

| Connection | Transport initiator | Business Flow initiator |
|---|---|---|
| Vector to Portal over TLS or QUIC | Vector | Vector |
| Egress to Portal over QUIC | Egress | Portal |

QUIC authenticates on client bidirectional Stream 0. Later business Streams
carry FlowStart and Target without another AuthFrame.

| Path | Initial request | Response |
|---|---|---|
| Vector TLS | AuthFrame + FlowStart + Target | SetupResult |
| Vector QUIC Stream 0 | AuthFrame, optionally followed by FlowStart + Target | SetupResult only when a Flow exists |
| Egress QUIC Stream 0 | AuthFrame + FIN | RegistrationResult + FIN |
| Portal to Egress business Stream | FlowStart + Target | SetupResult |

Vector has no authentication ACK. An authentication-only QUIC Stream finishes
without a SetupResult, Flow permit or UDP route; authentication remains valid
for later Streams on that connection.

Egress registration requires Portal's `out=egress` policy and a vacant Egress
Slot. Egress waits for ACCEPTED before processing Portal business Streams or
dialing targets, even if a Stream arrives before the registration response.
BUSY does not authorize target work. See
[Connection establishment](protocol.md#connection-establishment).

### Flow framing and failure scope

Each Flow starts with one FlowStart byte followed immediately by the
[Target encoding](protocol.md#flowstart-and-target). Bit 0 selects TCP (`0`)
or UDP (`1`). Senders MUST set reserved Bits 1–7 to zero; receivers MUST ignore
them. Target has no additional outer length prefix.

Target payload waits for READY. TLS dedicates one connection to each Flow;
QUIC dedicates one bidirectional Stream to each TCP Flow or UDP control Flow.
TCP preserves half-close and per-Flow cancellation.

Authentication and role-direction violations close the connection. Invalid
Targets, truncated requests and ordinary resource or dial failures end only the
affected Flow. Each Flow sends at most one SetupResult; failures after READY
close or reset the Flow. Other QUIC Flows remain independent.

## UDP delivery and lifetime

### Payload and identity

| Carrier | UDP payload | Empty packet |
|---|---|---|
| TLS | Two-byte big-endian length followed by one complete payload | Zero length is an empty datagram, not closure |
| QUIC | DATA or FRAGMENT DATAGRAMs on the control Stream's connection | DATA with an empty payload is valid |

QUIC UDP requires DATAGRAM support; there is no carrier fallback. Derive its
Flow ID as `(quic_stream_id >> 2) + 1` after checking that the raw Stream is
bidirectional and has the correct initiator. Compute in a wide integer and
require `1 <= flow_id <= 2^30 - 1` before conversion. Never truncate or wrap.
IDs are scoped to their connection and cannot identify a Flow on another one.

Deliver complete UDP packets only. Unknown, unauthenticated and not-yet-READY
IDs are discarded without allocating routes or reassembly state. Fragment
metadata, payload size, queues and reassembly reservations remain bounded.

### Lifetime and bridging

After READY, both directions of a QUIC UDP control Stream stay open without
business bytes. FIN, RESET, STOP_SENDING, idle timeout or connection loss
reclaims its routes, tasks, permits and reassembly state once. DATAGRAM CLOSE is
auxiliary; its loss cannot keep the Flow alive. TLS UDP ends at packet-boundary
EOF; EOF inside a length or payload is truncation.

Portal bridges complete business packets. Each leg uses its own connection,
Stream-derived ID, fragmentation and path MTU. Losing a registered Egress
connection ends all dependent Flows. Reconnection starts new Flows; an offline
Egress Slot fails new requests immediately without queuing or local fallback.
See [Connection lifecycle](protocol.md#connection-lifecycle),
[UDP flows](protocol.md#udp-flows) and [QUIC datagrams](protocol.md#quic-datagrams).

## Morph

Morph operates below TLS/QUIC and defaults to enabled. Peers agree on Shared Key
and the Morph setting; there is no in-band detection or switch. Derivation uses
`nowhere/nw3/morph` as the root domain and `tcp c2s`, `tcp s2c`, `udp c2s`,
`udp s2c` as direction info. Directions follow the transport initiator and
acceptor: on an Egress connection, Egress sends with `udp c2s` and Portal sends
with `udp s2c`.

TCP starts with a 64-byte client prelude and a 12-byte client nonce. The receiver
consumes the prelude without interpreting it, and the server sends no bootstrap.
Prelude generation supports `fade` (default), `full8` and `low7`; this local
policy is not negotiated and need not match the receiver's generation policy.
Each direction starts IETF ChaCha20 at block zero with its own key and the same
client nonce. Cipher positions advance continuously by bytes actually consumed
or written, independently by direction, and fail before keystream reuse.

UDP prefixes each transformed datagram with its own fresh unpredictable 12-byte
nonce and restarts the cipher at block zero. Include the prefix in path-MTU
accounting. Segment/GSO/GRO handling preserves each datagram's nonce and boundary.
Follow the [Morph specification](protocol.md#morph) for exact derivation and
encapsulation rules. TLS/QUIC supplies authentication and integrity.

## Reference vectors and observation

Use the independent [wire vectors](../src/tests/protocol/vectors.json) and
[Morph vectors](../src/tests/transport/morph.rs) when validating a peer.
Validate connection ordering, reserved-bit decoding, failure isolation, UDP
cleanup and partial Morph I/O alongside the fixed byte vectors. See
[Testing](testing.md) for boundary, replay and lifecycle coverage.

Third-party observers implement the [Telemetry JSON contract](telemetry.md).
They validate discovery and instance identity, then consume the six logical
traffic and active-Flow statistics over protected local IPC. Observation uses
the public JSON contract independently of forwarding frames, Rust modules and
status text.
