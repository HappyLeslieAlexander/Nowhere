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

## Morph transport protection

Morph masks the transport wire image. TLS/QUIC provides authenticated encryption
and integrity. The [Core specification](protocol.md) defines the Morph envelope;
the [Prelude Extension](prelude.md) defines Morph TCP bootstrap authentication.

### Cipher and Nonce limits

Nowhere limits each TCP cipher direction to `2^38 - 64` bytes to prevent cipher
block-counter wrap within a connection. The 96-bit TCP Nonce is randomly
generated, so uniqueness across connections sharing a key is probabilistic.
A repeated Nonce reuses the outer Morph keystream; Prelude counters do not
prevent that collision. TLS encryption is a separate boundary.

### Prelude authentication and replay

Morph TCP requires a valid 14-byte Prelude Tag and Counter. Invalid Tags and
Counters are rejected before ClientHello parsing. There is no Legacy Prelude
fallback. Invalidating a captured Prelude's Tag cannot bypass authentication
or replay checks.

Replay precheck precedes silent ClientHello parsing. After rustls Acceptor
accepts ClientHello, Portal checks the deadline and atomically rechecks and
commits replay state before any TLS response. Incomplete or malformed
ClientHello does not reserve a Counter. Later TLS or AuthFrame failures do not
undo a commit.

The 1024-bit replay window applies while an Identity is in the 16,384-entry FIFO.
Eviction or Portal restart removes its history. Shared Key holders can churn
the FIFO or advance replay windows. Random 64-bit Identity collisions can cause
unwanted window sharing.

A captured bootstrap permits offline verification of candidate Shared Keys
through its Tag. The hexadecimal key format does not guarantee entropy; use
`nowhere generate-key`. Prelude masking has no forward secrecy: disclosure of
the Shared Key permits decoding captured Identity and Counter metadata.

### Silent ClientHello admission

Portal reads ClientHello through rustls Acceptor without sending parser alerts.
Before acceptance, incomplete or rejected input, including a peer's write-side
FIN, is held silently until the authentication deadline. The absolute deadline
starts when TCP accept completes and covers Prelude, Nonce, ClientHello, TLS
and AuthFrame together. `NOW_HANDSHAKE_TIMEOUT` controls it (default `5s`).
Shutdown, resets and unrecoverable I/O failures may end the connection earlier.

Silent rejection retains the admission permit. Portal discards further TCP
input using a 4 KiB buffer, up to 64 KiB or 64 reads per connection, then stops
reading while retaining the original deadline. It sends no filler data and
introduces no random delays.

The silent boundary ends after ClientHello acceptance, successful replay commit
and the deadline check. Configuration-dependent ClientHello checks, TLS
completion and AuthFrame validation follow. TLS processing can send alerts
after this boundary. Standard TLS (`morph=0`) and QUIC ingress do not use the
silent ClientHello stage.

### Unauthenticated socket closure

Portal enables `SO_LINGER=0` before reading the Morph bootstrap and retains it
through TLS, ALPN and AuthFrame verification. The close policy follows the
connection's authentication state:

| Stage | Socket close policy |
|---|---|
| Prelude and replay verification | Zero linger; abortive close |
| ClientHello parsing, TLS and ALPN verification | Zero linger; abortive close |
| AuthFrame incomplete, invalid or wrong role | Zero linger; abortive close |
| Complete Vector AuthFrame within the deadline | Restore normal linger; normal close and half-close |

Portal checks the original deadline before and after restoring normal linger.
Expiry retains zero linger; failure, timeout or cancellation before successful
authentication does not restore normal linger. Socket-option failures terminate
the connection without forwarding.

On Linux, zero linger requests RST even when the bounded discard budget leaves
unread data. Packet-level FIN/RST behavior on other operating systems depends
on the kernel. Socket-option failures and resource rejection before connection
authentication begins are outside this close policy's guarantees.

### Observable boundaries

The Prelude Tag does not authenticate the encrypted TLS stream. An observer
who knows a captured ClientHello field's position and value can modify its
Morph ciphertext without the Shared Key. Modified input may pass Acceptor and
trigger later alerts; a captured bootstrap can race its first use with a
modified ClientHello and consume its Counter. TLS and AuthFrame authentication
still have to succeed.

Silent admission suppresses early parser responses to invalid Morph TCP probes.
Zero linger removes the Linux FIN/RST split caused by unread input at that
boundary. RST and the deadline remain observable, and admission exhaustion can
cause immediate rejection. Valid Prelude input can reach TLS responses after
ClientHello acceptance and replay commit. These protections do not eliminate
all active-probing or traffic-analysis fingerprints.

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

A 64 KiB server frame ceiling, 16-client limit and bounded writes constrain
resource use. A five-second write deadline disconnects blocked consumers. See
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
