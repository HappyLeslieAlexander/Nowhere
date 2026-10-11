# Security

Understand certificate trust, connection authentication and the boundaries that
protect service resources and local observations.

## Contents

- [Certificate trust](#certificate-trust)
- [Connection authentication](#connection-authentication)
- [Admission and Flow resources](#admission-and-flow-resources)
- [Flow lifetime and exit ownership](#flow-lifetime-and-exit-ownership)
- [Local IPC](#local-ipc)
- [Metadata and diagnostics](#metadata-and-diagnostics)

## Certificate trust

Normal Vector and Egress connections require system CA trust with hostname
validation, or an exact certificate SHA-256 pin. TLS 1.3 and ALPN `nw3` are
mandatory. 0-RTT is disabled, including on resumed connections.

| Trust mode | Verification |
|---|---|
| System CA | The certificate chain is trusted and the server name matches |
| Exact pin | The presented certificate matches the configured SHA-256 fingerprint |
| Fingerprint inspection | Reads the presented certificate; trust must be checked separately |

A pin is 64 lowercase hexadecimal characters. A missing, empty or `none` pin
uses normal certificate verification. Explicit fingerprint inspection does
not establish trust; compare its result through a trusted channel before use.

Morph masks the transport wire image. TLS/QUIC provides authenticated encryption
and integrity. See [Morph](protocol.md#morph) for its complete contract.

## Connection authentication

Authentication is a 16-byte HMAC tag over the transport byte and normal TLS
exporter, using the [role KDF](protocol.md#authentication). Tags are compared in
constant time. They cannot authenticate another connection, resumed connection,
transport or role.

Shared Key is percent-decoded once and used as text bytes. Portal, Vector and
Egress require exactly 32 lowercase hexadecimal text characters.
`nowhere generate-key` encodes 16 cryptographically random bytes as text,
providing 128 bits of entropy. Key derivation does not increase that entropy.
One credential derives both Vector and Egress role keys; sharing it shares its
authority. Role derivation does not provide independent credential permissions.

## Admission and Flow resources

Authentication precedes target work and Egress Slot ownership. Portal applies
these limits before accepting a role:

| Resource | Pre-authentication limit |
|---|---|
| Pending connections | 256 total; 32 per IPv4 source or IPv6 /64 |
| QUIC Stream credit | One client bidirectional Stream; no unidirectional Streams |
| QUIC connection receive window | 64 KiB |
| Handshake and authentication | `NOW_HANDSHAKE_TIMEOUT`, default `5s` |

After authentication, receive windows are raised to the selected QUIC profile.
Business resources remain bounded by target Flow permits, Stream credit,
UDP queues, reassembly reservations and transport receive buffers.

UDP DATAGRAM bypasses Stream flow control. Unknown, pre-READY and unauthenticated
IDs are discarded. Reassembly has slot, byte and TTL limits; queued datagrams
retain reservations until delivery or cleanup. Full Flow queues use nonblocking
dispatch so one slow Flow cannot stall the connection.

## Flow lifetime and exit ownership

Stream direction and the 30-bit derived UDP ID range are checked before use,
without truncation. ID exhaustion stops admission and triggers a bounded drain
and close or reconnect. FIN, RESET, STOP_SENDING, idle timeout and connection loss
reclaim UDP routes independently of CLOSE DATAGRAM delivery.

Egress registers only when Portal has `out=egress`. Slot ownership is atomic;
cleanup checks the actual connection identity. Egress waits for ACCEPTED before
target work. Offline Flows fail immediately without local fallback.

DNS and target sockets belong to the selected exit. Explicit source binding
errors fail the dial and do not retry with an automatic source.

## Local IPC

Local observation is restricted to the service's operating-system user. Unix
permissions and symlink/object checks protect the registry and sockets. Windows
ACLs and peer checks protect registry files and local named pipes.

Collectors validate registry/Hello consistency, process liveness and platform
peer identity. Linux and Windows also check process incarnation during discovery.
Discovery and cleanup stay inside the documented IPC namespace.
Administrators and compromised processes running as the same user are outside
this isolation boundary.

The 64 KiB server frame ceiling, 16-client limit, five-second write deadline,
bounded frame writes disconnect blocked consumers. See
[Telemetry](telemetry.md) for limits and identity requirements.

## Metadata and diagnostics

Startup output omits Shared Key and SOCKS credentials. Private key contents are
never logged. IPC metadata exposes validated service endpoints
to authorized collectors; it includes no configuration summary,
client address or transport peer identity.

IPC carries instance identity and six statistics. It contains no Flow events,
error messages or logs.

Service errors preserve their original cause chains and can contain addresses
or paths. Error construction excludes passwords, Shared Keys and complete
credential URLs. See [Telemetry privacy](telemetry.md#privacy-and-trust).
