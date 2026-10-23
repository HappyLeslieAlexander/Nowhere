# Security

Understand certificate trust, connection authentication, transport masking and
the boundaries that protect service resources and local observations.

## Contents

- [Certificate trust](#certificate-trust)
- [Connection authentication](#connection-authentication)
- [Morph transport protection](#morph-transport-protection)
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

## Connection authentication

AuthFrame is a 16-byte HMAC tag over the transport byte and normal TLS
exporter. The [Core specification](protocol.md) defines Vector authentication;
the [Egress Extension](egress.md#authentication) defines its additional role
key. AuthFrame tags are compared in constant time and are bound to the
connection, transport and role, including on resumed TLS connections.

Shared Key is percent-decoded once and used as text bytes. Portal, Vector and
Egress require exactly 32 lowercase hexadecimal text characters.
`nowhere generate-key` encodes 16 cryptographically random bytes as text,
providing 128 bits of entropy. Key derivation does not increase that entropy.
One credential derives both Vector and Egress role keys; sharing it shares its
authority. Role derivation does not provide independent credential permissions.

A captured Morph TCP bootstrap permits offline verification of candidate Shared
Keys through its Prelude Tag. The hexadecimal format does not guarantee
entropy; use the random output of `nowhere generate-key`. Prelude masking has
no forward secrecy: disclosure of the Shared Key permits decoding captured
Identity and Counter metadata. TLS session encryption is a separate boundary.

## Morph transport protection

Morph masks the transport wire image. TLS/QUIC provides authenticated encryption
and integrity. Nowhere limits each TCP cipher direction to `2^38 - 64` bytes
to prevent cipher block-counter wrap within a connection. The 96-bit TCP Nonce
is randomly generated, so uniqueness across connections sharing a key is
probabilistic. A repeated Nonce reuses the outer Morph keystream; Prelude
counters do not prevent that collision. TLS encryption is a separate boundary.
See the [Core specification](protocol.md) for the Morph contract.

For Morph TCP ingress, Portal reads ClientHello through rustls without sending
parser alerts. Incomplete or rejected input, including a peer's write-side FIN,
is held silently until the authentication deadline. That deadline starts when
TCP accept completes and covers the prelude, nonce, ClientHello, TLS handshake
and AuthFrame together. `NOW_HANDSHAKE_TIMEOUT` controls it (default `5s`).
Shutdown, resets and unrecoverable I/O failures may end the connection earlier.
Portal enables zero linger before reading the Morph prelude, requesting an
abortive close for rejected or incomplete input at the deadline. On Linux this
uses RST even when the bounded input-disposal budget leaves unread data.
Before continuing an accepted ClientHello, Portal disables linger and rechecks
the deadline; an expired connection retains zero linger. Socket-option failures
terminate the connection without continuing TLS. They are outside this close
policy's guarantees, as are shutdown and resource rejection. Packet-level
behavior on other operating systems depends on the kernel.

The [Prelude Extension](prelude.md) adds a 14-byte Tag over Morph TCP bootstrap
metadata. A matching Tag requires a valid Counter and successful replay commit
before any TLS response. A nonmatching Tag takes the silent ClientHello path
without replay state. The silent boundary ends after rustls Acceptor accepts
ClientHello, replay commit succeeds when applicable, and the linger/deadline
handoff completes. Configuration-dependent ClientHello checks, TLS completion
and AuthFrame validation follow; those checks can send TLS alerts.

The 1024-bit replay window applies while an Identity is in the 16,384-entry FIFO.
Eviction or Portal restart removes its history. Modifying captured Prelude
metadata can invalidate the Tag and enter the path without replay checks.
Prelude authentication is therefore not enforced for every Morph TCP connection.

The Prelude Tag does not authenticate the encrypted TLS stream. An observer
who knows a captured ClientHello field's position and value can modify its
Morph ciphertext without the Shared Key. Modified input may pass Acceptor and
trigger later alerts; a captured bootstrap can race its first use with a
modified ClientHello and consume its Counter. TLS and AuthFrame authentication
still have to succeed. Shared Key holders can churn the FIFO or advance replay
windows. Random 64-bit Identity collisions can cause unwanted window sharing.

Rejected connections retain their admission permits. Portal discards further
TCP input using a 4 KiB buffer, up to 64 KiB or 64 reads per connection, then
stops reading while retaining the original deadline. It does not send filler
data or introduce random delays. Zero linger removes the Linux FIN/RST split
caused by unread input at this boundary; RST and the deadline remain observable.
Admission exhaustion can cause immediate rejection. This protection removes
early parser responses to invalid Morph TCP probes; it does not eliminate all
active-probing or traffic-analysis fingerprints. Standard TLS and QUIC ingress
do not use this silent ClientHello stage.

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
IDs are discarded. Reassembly permits 64 partial packets per connection with a
ten-second TTL. Queued datagrams and fragments share the per-connection
`NOW_QUIC_UDP_QUEUE_BYTES` budget (default 4 MiB), separate from QUIC's DATAGRAM
receive and send buffers (4 MiB each). Reservations remain held until delivery
or cleanup. Full Flow queues use nonblocking dispatch so one slow Flow cannot
stall the connection.

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
