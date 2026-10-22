# Interoperability

Validate independent Nowhere Protocol implementations against Nowhere's Rust
runtime. The [Core specification entry](protocol.md) identifies the Wire
baseline; the [Egress Extension](extension.md) defines Nowhere's remote-exit
behavior. This guide describes integration and validation, not a second Wire
specification.

## Contents

- [Transport and authentication](#transport-and-authentication)
- [Flow direction and framing](#flow-direction-and-framing)
- [UDP delivery and lifetime](#udp-delivery-and-lifetime)
- [Morph](#morph)
- [Reference vectors and observation](#reference-vectors-and-observation)

## Transport and authentication

Follow [Core transport and authentication](protocol.md).
When connecting to Nowhere, use its [certificate trust](security.md#certificate-trust)
and [Shared Key provisioning](configuration.md) interfaces. Configuration URL
parsing is independent of the authenticated Wire frames.

Test fresh and resumed connections, invalid credentials and replayed tags. A
failed connection must not dial a target or claim Egress registration ownership.
The original authentication fixtures also contain Egress/TLS as a negative case;
Egress does not support that carrier.

## Flow direction and framing

Exercise both TLS and QUIC with TCP and UDP payloads. Include authentication-only
Stream 0, a pipelined first request, partial reads, reserved-bit decoding, TCP
half-close, rejection before READY and failure isolation after READY.

A standard Vector uses the same Core protocol when Portal selects Egress as its
exit. It does not implement registration or reverse Stream initiation. Egress
peers separately test the [registration barrier](extension.md#registration),
role-direction rejection and [Slot ownership](extension.md#registration-ownership-and-lifetime).

## UDP delivery and lifetime

Validate empty packets, Stream-derived ID boundaries, fragmented payloads,
out-of-order delivery, duplicate/conflicting fragments and unknown or not-yet-ready
routes. Missing QUIC DATAGRAM capability must not trigger a hidden carrier fallback.

Exercise control-stream FIN, reset and STOP_SENDING without relying on a CLOSE
DATAGRAM. Reassembly and queue pressure must not prevent unrelated Flows from
making progress. For Egress, validate both bridge legs and disconnect cleanup;
reconnection must not recover a previous Flow.

## Morph

Use the [Core Morph contract](protocol.md). Test both enabled and disabled
configurations, TCP partial reads/writes and continuous cipher offsets, UDP
segmentation boundaries and nonce overhead. The receive path must accept the
64-byte prelude independently of the sender's generation policy. Nowhere's
[prelude policies](configuration.md#tcp-morph-prelude) do not require a matching
policy on the peer.

## Reference vectors and observation

The original [wire fixtures](../src/tests/protocol/vectors.json) and
[Morph fixtures](../src/tests/transport/morph.rs) remain part of Nowhere's test
suite, including extension coverage. Fixed byte agreement complements live
transport and lifecycle tests; it does not replace them. See [Testing](testing.md).

Third-party observers use the separate [Telemetry JSON contract](telemetry.md).
Local IPC, discovery, process identity and statistics are implementation
interfaces, not requirements for a forwarding protocol peer.
