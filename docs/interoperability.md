# Interoperability

Implement compatible peers using the byte layouts, ordering and lifetime rules
of the [Nowhere Wire Protocol](protocol.md).

## Contents

- [Transport and authentication](#transport-and-authentication)
- [Flow direction and framing](#flow-direction-and-framing)
- [UDP delivery and lifetime](#udp-delivery-and-lifetime)
- [Morph](#morph)
- [Reference vectors and observation](#reference-vectors-and-observation)

## Transport and authentication

| Requirement | Contract |
|---|---|
| TLS | TLS 1.3 with certificate trust and hostname verification, or an exact pin |
| ALPN | `nw3` only; other values are rejected without negotiation or fallback |
| Early data | 0-RTT is disabled, including on resumed connections |
| Shared Key | Exactly 32 lowercase hexadecimal text characters after one percent decode; used as text bytes |
| Authentication | A 16-byte tag bound to role, transport and the normal TLS exporter |

The role KDF distinguishes Vector and Egress. A shared credential grants both
role authorities; derivation does not create independent permissions.

## Flow direction and framing

Each connection has one business Stream initiator:

| Connection | Transport initiator | Business Flow initiator |
|---|---|---|
| Vector to Portal over TLS or QUIC | Vector | Vector |
| Egress to Portal over QUIC | Egress | Portal |

Role-direction violations close the connection. Each Flow starts with TCP `0`
or UDP `1`, followed by the [Target encoding](protocol.md#flowstart-and-target).
All other FlowStart bits are invalid. READY is required before target payload.
TLS uses one Flow per connection; QUIC uses one bidirectional Stream per Flow.
Ordinary Flow errors end the affected Flow.

## UDP delivery and lifetime

QUIC UDP IDs derive from the control Stream after direction and range checks.
IDs are valid only within that connection and cannot be truncated or reused
across connections. An authentication-only Stream creates no UDP route.

UDP control Streams remain open after READY and provide reliable lifetime
signals. FIN, RESET, STOP_SENDING, idle timeout or connection loss reclaims the
Flow. DATAGRAM CLOSE is auxiliary; fragments, queues and reassembly stay bounded.
TLS UDP carries length-prefixed complete packets over its dedicated connection.

Portal bridges complete business packets. Each side uses its own connection
identity, Stream-derived ID, fragmentation and path MTU. See
[UDP flows](protocol.md#udp-flows) and [QUIC datagrams](protocol.md#quic-datagrams).

## Morph

Peers agree on Shared Key and whether Morph is enabled. Derivation uses
`nowhere/nw3/morph` as the root domain and `tcp c2s`, `tcp s2c`, `udp c2s`,
`udp s2c` as direction info. Directions follow the transport initiator and acceptor.

Morph preserves the specified prelude, nonce and ChaCha20 positions. UDP
segment/GSO/GRO handling preserves datagram boundaries. Follow the
[Morph specification](protocol.md#morph) exactly.

## Reference vectors and observation

Use the independent [wire vectors](../src/tests/protocol/vectors.json) and
[Morph vectors](../src/tests/transport/morph.rs) when validating a peer.
See [Testing](testing.md) for boundary, replay and lifecycle coverage.

Third-party observers implement the [Telemetry JSON contract](telemetry.md).
They consume public IPC independently of the forwarding protocol, Rust modules
and status text.
