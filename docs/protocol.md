# Nowhere Wire Protocol

Authenticated TCP and UDP forwarding between Portal, Vector and Egress.

| Protocol | Value |
|---|---|
| Version | 3 |
| ALPN | `nw3` |
| Transports | TLS 1.3 and QUIC |

## Contents

- [Overview](#overview)
- [Conventions](#conventions)
- [Roles and connections](#roles-and-connections)
- [Transport requirements](#transport-requirements)
- [Authentication](#authentication)
- [Connection establishment](#connection-establishment)
- [FlowStart and Target](#flowstart-and-target)
- [Setup results](#setup-results)
- [UDP flows](#udp-flows)
- [QUIC datagrams](#quic-datagrams)
- [Connection lifecycle](#connection-lifecycle)
- [Morph](#morph)
- [Related documentation](#related-documentation)

## Overview

This specification defines connection establishment, role authentication, Flow
framing, UDP delivery and Morph. It is intended for developers implementing a
compatible peer. The byte layouts and ordering rules define interoperability.

## Conventions

A **connection** is one TLS or QUIC association. A **Flow** is one TCP byte stream
or one UDP association to a fixed Target. **Client** and **server** identify the
transport initiator and acceptor; Egress is therefore a QUIC client even though
Portal initiates its business Streams. Upload means Vector-to-Target traffic;
download is the reverse direction.

All multibyte integers use unsigned network byte order. Sizes are in bytes unless
stated otherwise. `||` means byte concatenation; `[0..16]` selects the first 16
bytes. Quoted cryptographic labels are exact ASCII without a terminator. Frames
have no implicit padding, version byte or outer length field. A parser consumes
exactly the fields described for its current state. Diagrams are schematic;
field labels and tables specify byte sizes rather than drawing widths.

## Roles and connections

Arrows show connection establishment; all connections are bidirectional:

```text
Direct or SOCKS5 output

               TLS / QUIC                 Direct / SOCKS5
+----------+                 +----------+                 +----------+
|  Vector  |---------------->|  Portal  |---------------->|  Target  |
+----------+                 +----------+                 +----------+

Egress output

               TLS / QUIC                      QUIC
+----------+                 +----------+                 +----------+
|  Vector  |---------------->|  Portal  |<----------------|  Egress  |
+----------+                 +----------+                 +----------+
                                                               |
                                                               | TCP / UDP
                                                               v
                                                         +----------+
                                                         |  Target  |
                                                         +----------+
```

Vector provides SOCKS ingress and initiates business Flows on one configured
carrier. Portal listens, authenticates and selects one fixed output. Egress
connects to Portal over QUIC, registers, accepts Portal Streams and dials targets.
Each connection has exactly one business Flow initiation direction. TLS uses
one connection per Flow. Each QUIC bidirectional Stream owns one TCP Flow or
one UDP control Flow. TLS ingress bridged to QUIC Egress is ordinary forwarding.

## Transport requirements

Both transports use TLS 1.3 and only ALPN `nw3`. Peers reject missing or
other ALPN values. There is no negotiation or fallback. Normal clients verify
system CA trust and hostname, or an exact certificate SHA-256 pin. 0-RTT is
disabled, including on resumed connections. Authentication uses the normal
TLS exporter, never the early exporter.

## Authentication

### Shared Key

Percent-decode the URL username once to obtain Shared Key. Its text
bytes enter the KDF directly; hexadecimal-looking text is not hex-decoded.
Portal, Vector and Egress service URLs require exactly 32 lowercase hexadecimal
text characters after decoding and no password component. Malformed percent
escapes are invalid. All three roles apply the same input validation.

### Role key derivation

```text
salt       = SHA256("nowhere/nw3/auth-root")
root       = HMAC-SHA256(salt, shared_key)
vector_key = HMAC-SHA256(root, "vector-authentication" || 0x01)
egress_key = HMAC-SHA256(root, "egress-authentication" || 0x01)

exporter = TLS-Exporter("EXPORTER-Nowhere-nw3-Auth", empty_context, 32)
tag      = HMAC-SHA256(role_key, transport || exporter)[0..16]
transport = 0x01 (TLS), 0x02 (QUIC)
```

The same root derives both role keys:

```text
                      +---------------------------+
                      |    Authentication root    |
                      +---------------------------+
                                    |
                   +----------------+----------------+
                   |                                 |
     +---------------------------+     +---------------------------+
     |  "vector-authentication"  |     |  "egress-authentication"  |
     |          || 0x01          |     |          || 0x01          |
     |  HMAC-SHA256(root, input) |     |  HMAC-SHA256(root, input) |
     +---------------------------+     +---------------------------+
                   |                                 |
     +---------------------------+     +---------------------------+
     |     32-byte Vector key    |     |     32-byte Egress key    |
     +---------------------------+     +---------------------------+
```

### AuthFrame

```text
+--------------------------------------------------------------+
|                        tag: 16 bytes                         |
|     HMAC-SHA256(role_key, transport || exporter)[0..16]      |
+--------------------------------------------------------------+
```

All quoted labels are exact ASCII bytes, including lowercase `nw3` in the
exporter label. AuthFrame is exactly the 16-byte tag, with no role byte or
metadata. Compare tags in constant time. Portal selects a fixed role from the
matching role key; TLS permits Vector only. A tag cannot move between
connections, resumed connections, roles or transports. One Shared Key derives
both role keys; the role distinction is not independent credential isolation.
Independent KDF/tag fixtures are in
[`src/tests/protocol/vectors.json`](../src/tests/protocol/vectors.json).
Authentication and Flow tests check these fixtures. Independent Morph vectors
are checked in [`transport/morph.rs`](../src/tests/transport/morph.rs).
See [Testing](testing.md) for transport, security and interoperability coverage.

## Connection establishment

| Connection | First request | Response |
|---|---|---|
| Vector TLS | AuthFrame + FlowStart + Target | SetupResult |
| Vector QUIC | Client Stream 0: AuthFrame, optionally FlowStart + Target | SetupResult if a Flow exists |
| Egress QUIC | Client Stream 0: AuthFrame, then FIN | RegistrationResult |
| Portal to Egress Flow | New server bidirectional Stream: FlowStart + Target | SetupResult |

### Vector establishment

The authentication Stream is client bidirectional Stream ID 0; accepting a
later Stream first does not authorize treating it as the authentication Stream.
Vector has no authentication ACK. The first Flow can be pipelined after Auth;
target payload waits for READY. EOF immediately after Vector QUIC Auth is an
authentication-only Stream: finish it normally without a SetupResult, Flow
permit or UDP route. Authentication remains connection-wide for later Streams.
Vector TLS requires a Flow because it is a dedicated connection.

TLS and a pipelined first QUIC Flow follow the same application ordering.
For QUIC, the request and result below use client bidirectional Stream 0:

```text
      Vector                                                  Portal
         |                                                       |
         |---------------- TLS / QUIC handshake ---------------->|
         |----------- AuthFrame + FlowStart + Target ----------->|
         |                  target payload waits                 |
         |<----------------- SetupResult: READY -----------------|
         |<============== TCP bytes / UDP packets ==============>|
         |                                                       |
```

A QUIC authentication-only Stream creates no Flow. Later Streams carry their
own FlowStart and Target without another AuthFrame:

```text
      Vector                                                  Portal
         |                                                       |
         |------------- Stream 0: AuthFrame + FIN -------------->|
         |<----------- Stream 0: FIN (no SetupResult) -----------|
         |------------ Stream 4: FlowStart + Target ------------>|
         |<--------------- Stream 4: SetupResult ----------------|
         |<=============== Flow data after READY ===============>|
         |                                                       |
```

### Egress registration

Egress sends no Flow bytes on its authentication Stream. RegistrationResult is
one byte: `0` ACCEPTED, `1` BUSY, followed by FIN on the authentication Stream.
Invalid authentication or disallowed Egress policy closes the connection
without an application result. Portal permits registration only with
`out=egress`. It atomically claims the vacant
Slot after successful authentication; an occupied Slot returns BUSY and the
contender closes. An accepted connection has no Vector-originated business
Streams. Egress must wait for ACCEPTED before processing any Portal business
Stream or dialing a target; Stream arrival order cannot substitute for this
barrier. Failure to write ACCEPTED releases only that connection's ownership.

Egress is the transport client; Portal initiates business Streams:

```text
      Egress                                                  Portal
         |                                                       |
         |------------------- QUIC handshake ------------------->|
         |---------- Client Stream 0: AuthFrame + FIN ---------->|
         |<---------- Client Stream 0: ACCEPTED + FIN -----------|
         |<-------- Server Stream 1: FlowStart + Target ---------|
         |--------------- Server Stream 1: READY --------------->|
         |<=============== Flow data after READY ===============>|
         |                                                       |
```

A BUSY result ends registration and does not authorize target work. Business
Streams can arrive before the registration response; the ACCEPTED barrier still
applies to their processing.

### Authentication resource limits

Authentication is bounded by the handshake deadline (default five
seconds). Portal keeps the pre-authentication receive window at 64 KiB and
permits only one client bidirectional Stream, no unidirectional Streams. It
limits admission to 256 unauthenticated connections and 32 per
IPv4 source or IPv6 /64. DATAGRAMs are dropped until authentication completes.
No target dial, Slot ownership or unbounded business allocation precedes auth.
After success, apply the configured QUIC receive window and bounded Stream
credit before admitting business data. Admission limits and resource permits
remain application constraints even when QUIC transport credit is available.

## FlowStart and Target

FlowStart is one byte. Bit 0 is `0` for TCP, `1` for UDP. Bits 1–7 must be zero.
Thus only bytes `00` and `01` are valid. Target immediately follows:

| ATYP | Address bytes | Final field |
|---|---|---|
| `01` IPv4 | Four address bytes | Two-byte port |
| `03` Domain | One-byte length, then that many domain bytes | Two-byte port |
| `04` IPv6 | Sixteen address bytes | Two-byte port |

Target encodes the port in network byte order; port zero is invalid. IPv4 and
IPv6 use raw address octets, without text delimiters or IPv6 scope IDs. A domain
contains 1–253 ASCII bytes in IDNA wire form. Each dot-separated label contains
1–63 ASCII letters, digits or hyphens and cannot begin or end with a hyphen.
Empty labels and a trailing dot are invalid. Unicode names must be converted to
IDNA before encoding. DNS resolution belongs to the selected exit.

### FlowStart byte

```text
+-----------------------------------+-------------+
|             Bits 7..1             |    Bit 0    |
|         Reserved: all zero        | TCP=0 UDP=1 |
+-----------------------------------+-------------+
```

### Target layouts

```text
IPv4
+-------------+----------------------------+-------------+
|  ATYP: 0x01 |       IPv4: 4 bytes        |   Port: 2   |
+-------------+----------------------------+-------------+

IPv6
+-------------+----------------------------+-------------+
|  ATYP: 0x04 |       IPv6: 16 bytes       |   Port: 2   |
+-------------+----------------------------+-------------+

Domain
+-------------+------------+----------------------------+-------------+
|  ATYP: 0x03 | Length: 1  |    Domain: length bytes    |   Port: 2   |
+-------------+------------+----------------------------+-------------+
```

For TCP to `127.0.0.1:443`, FlowStart + Target is:

```text
00    01    7f 00 00 01    01 bb
TCP   IPv4  address       port 443
```

There is no Target length prefix outside its address-type-specific encoding.
Reserved FlowStart bits, invalid ATYP, invalid Target or truncated input fail
only that Flow. TCP carries reliable payload after READY and preserves
half-close, per-Flow cancellation and the configured shutdown/read deadlines.

## Setup results

SetupResult is exactly one byte:

| Value | Meaning |
|---|---|
| `0` | READY |
| `1` | INVALID_REQUEST |
| `2` | FLOW_LIMIT |
| `3` | DIAL_FAILED |
| `4` | INTERNAL_ERROR |

Resource exhaustion fails promptly with FLOW_LIMIT. Target setup failure or
offline Egress gives DIAL_FAILED. Each Flow sends at most one SetupResult;
after READY, close/reset ends it. Authentication and role-direction violations
close the connection; ordinary Flow errors leave other QUIC Flows intact.
No carrier fallback is permitted, including for missing DATAGRAM support.

```text
                    +-------------------------+
                    |    FlowStart + Target   |
                    +------------+------------+
                                 |
                    +------------v------------+
                    |       Target setup      |
                    +------------+------------+
                                 |
                +----------------+----------------+
                |                                 |
   +------------v------------+       +------------v------------+
   |    SetupResult: READY   |       |    SetupResult: error   |
   +------------+------------+       +------------+------------+
                |                                 |
   +------------v------------+       +------------v------------+
   |      Payload phase      |       |      End this Flow      |
   +------------+------------+       +-------------------------+
                |
   +------------v------------+
   |      Close or reset     |
   +-------------------------+
```

| Failure | Scope |
|---|---|
| Invalid authentication or business Stream initiator | Close the connection |
| Invalid FlowStart/Target or per-Flow resource/dial failure | End the affected Flow |
| Failure after READY | Close/reset the Flow; do not send a second SetupResult |
| Registered Egress connection lost | End every Flow depending on that connection |

## UDP flows

### Stream-derived identity

For a QUIC UDP control Stream:

```text
flow_id = (quic_stream_id >> 2) + 1
```

The low two Stream ID bits encode direction; they are checked before derivation:

```text
+---------------------------+------------------+--------------------+
|      Stream sequence      |      Bit 1       |       Bit 0        |
|        raw ID >> 2        |  0=bidi, 1=uni   | 0=client, 1=server |
+---------------------------+------------------+--------------------+
```

Check the raw Stream's bidirectional bit and initiator first. On a Vector
connection, only client-initiated business Streams are valid. On an Egress
connection, only server-initiated business Streams are valid. Compute in a
wide integer, then require `1 <= flow_id <= 2^30 - 1` before converting.
Never truncate or wrap. The last usable raw IDs are `4294967288` for Vector
and `4294967289` for Egress. Authentication-only Stream 0 creates no UDP route;
the next client Stream 4 derives ID 2. TCP needs no business ID.

IDs have meaning only within that QUIC connection. There is no cross-connection
map, allocator or retired-ID set. At exhaustion stop admitting Flows, drain
active tasks for the configured shutdown deadline, close and reconnect.
There is no exhaustion control frame or Flow recovery on another connection.

### Control Stream and DATAGRAM lifetime

After READY, keep both directions of a UDP control Stream open; it carries no
business bytes. FIN, RESET, STOP_SENDING, idle timeout or connection loss
triggers idempotent route/task/permit/reassembly cleanup. CLOSE DATAGRAM is
an auxiliary signal; its loss cannot keep a terminated Flow alive. Nonempty
post-READY control data is invalid for that Flow. Unknown, unauthenticated or
not-yet-READY IDs are dropped without allocating routes or reassembly slots.

The reliable Stream owns lifecycle; DATAGRAM carries complete or fragmented
UDP payloads on the same QUIC connection:

```text
     Initiator                                               Acceptor
         |                                                       |
         |--------- Control Stream: FlowStart + Target --------->|
         |<--------------- Control Stream: READY ----------------|
         |      control Stream stays open; no payload bytes      |
         |<============= DATAGRAM: DATA / FRAGMENT =============>|
         |      FIN / RESET / STOP_SENDING / timeout / loss      |
         |         reclaim route, tasks and permits once         |
         |                                                       |
```

### TLS UDP framing

TLS UDP uses a two-byte big-endian length followed by one complete payload
(UoT), repeated independently in each direction. The length excludes its own
two bytes and permits 0–65535 payload bytes. Zero length represents an empty
datagram, not closure. EOF between packets ends the Flow; EOF inside a length
or payload is truncation. The dedicated connection owns the Flow's lifetime.

```text
+-----------------+-------------------+-----------------+-------------------+
|   Length: u16   |  Payload: length  |   Length: u16   |  Payload: length  |
+-----------------+-------------------+-----------------+-------------------+
```

## QUIC datagrams

### Base word

The four-byte network-order base word has the following layout:

```text
+----------------------+------------------------------------------+
|  Type: bits 31..30   |           Flow ID: bits 29..0            |
| 0 DATA / 1 FRAGMENT  |              1 .. 2^30 - 1               |
| 2 CLOSE / 3 invalid  |            unsigned, nonzero             |
+----------------------+------------------------------------------+
```

DATA is the base word plus a complete business payload. CLOSE is exactly the
base word, with no trailing bytes. Empty DATA payloads are valid. Type `3`, zero
Flow IDs, truncated headers and oversized payloads are invalid and are dropped.
FRAGMENT adds an eight-byte fragment header after the base word:

| Bytes | Field |
|---:|---|
| 4 | Nonzero packet ID, network order |
| 1 | Zero-based fragment index |
| 1 | Fragment count, 2..255 |
| 2 | Total complete payload length, network order |

### Packet layouts

```text
DATA
+----------------------+------------------------------------+
|  Base word: 4 bytes  |   Complete UDP payload: 0..65535   |
+----------------------+------------------------------------+

CLOSE
+----------------------+
|  Base word: 4 bytes  |
+----------------------+

FRAGMENT header (12 bytes), followed by nonempty fragment payload
+--------------+--------------+----------+----------+--------------+
| Base word: 4 | Packet ID: 4 | Index: 1 | Count: 1 | Total len: 2 |
+--------------+--------------+----------+----------+--------------+
```

### Fragmentation and reassembly

The complete payload is at most 65535 bytes. Fragment payloads are nonempty,
`index < count`, and `total_len >= count`. A fragment must leave at least one
byte for every other fragment. Use DATA when the complete packet fits the peer's
DATAGRAM limit; otherwise split into at most 255 FRAGMENT frames. A sender that
cannot fit the header and a payload byte cannot send that packet.

Reassembly is scoped by connection, Flow ID and packet ID. All fragments of a
packet agree on count and total length. Deliver only after every index is present
and the concatenation in index order has exactly `total_len` bytes. Identical
duplicates do not add bytes; conflicting metadata or payload invalidates the
partial packet. Fragments may arrive out of order. Packet IDs are nonzero and
must distinguish concurrent partial packets within the same Flow.

For a three-fragment packet, arrival order does not change delivery order:

```text
Arrival                 Reassembly by index                  Delivery
+----------+            +----------+----------+----------+   +----------+
| 2, 0, 1  |----------->|    0     |    1     |    2     |-->|  packet  |
+----------+            +----------+----------+----------+   +----------+

Missing fragment        Keep a bounded partial packet until TTL/cleanup.
Conflicting fragment    Drop the partial packet; release its reservation.
Complete packet         Deliver once all indices and total length validate.
```

### Budgets and Portal bridging

Reassembly enforces 64 partial-packet slots, a ten-second TTL, per-connection
byte reservations and bounded per-Flow queues. The connection application
queue/reassembly budget
is `NOW_QUIC_UDP_QUEUE_BYTES` (default 4 MiB), in addition to Quinn's bounded
DATAGRAM receive/send buffers (Portal receive: 256 KiB; Vector/Egress receive
and all send buffers: 4 MiB). Queue admission is nonblocking; a slow Flow
must not block the connection dispatcher. Empty packets consume a
budget unit. Reservations survive until packet/fragment delivery or cleanup.

Portal UDP bridges complete business datagrams. Each side reassembles and
encodes/fragments independently using its own connection-local ID and MTU.
Each bridge task owns both handles; no global bidirectional ID map is needed.

In this example, client Stream 4 derives ID 2 and server Stream 1 derives ID 1:

```text
+----------+                    +----------+                    +----------+
|  Vector  |<== ID 2 packets ==>|  Portal  |<== ID 1 packets ==>|  Egress  |
+----------+                    +----------+                    +----------+
```

## Connection lifecycle

A connection owns its fixed role, cancellation signal, active tasks, resource
permits, UDP routes and reassembly state. A Flow owns its two handles, timeout,
rate limiter and cancellation state. Portal owns one EgressSlot containing a
valid registered QUIC connection.

The first authenticated connection claims the Slot atomically. Another cannot
join or replace it. Cleanup compares the actual connection object identity
before releasing the Slot; stale cleanup cannot release a new owner. Connection
loss cancels every dependent Flow. Reconnect starts new Flows only. An offline
Slot causes immediate DIAL_FAILED without waiting, queuing or local fallback.
QUIC keepalive and idle timeouts maintain connection liveness without an
application heartbeat.

The Slot belongs to one registered connection, not to a reconnecting process:

```text
+---------------------+     authenticated claim      +---------------------+
|     Vacant Slot     |----------------------------->|   Owned connection  |
+---------------------+                              +---------------------+
           ^                                                    |
           |            connection identity matches             |
           +----------------------------------------------------+

Owned + another registrant     BUSY; the owner is unchanged.
Owner lost                     Cancel dependent Flows, then release ownership.
Stale owner's cleanup          Cannot release a different connection's Slot.
```

## Morph

Morph is an optional transform below TLS/QUIC, enabled by `morph=1`. Peers must
agree on Shared Key and whether Morph is enabled; no in-band switch or detection
is performed. With Morph disabled, the transport bytes pass through unchanged.

### Key derivation

Use the same once-decoded Shared Key bytes as authentication:

```text
root    = HMAC-SHA256("nowhere/nw3/morph", shared_key)
tcp_c2s = HMAC-SHA256(root, "tcp c2s" || 0x01)
tcp_s2c = HMAC-SHA256(root, "tcp s2c" || 0x01)
udp_c2s = HMAC-SHA256(root, "udp c2s" || 0x01)
udp_s2c = HMAC-SHA256(root, "udp s2c" || 0x01)
```

Each output is a 32-byte key. The Morph root label is used directly as the HMAC
key; unlike authentication, it is not hashed first. The Morph root domain provides
domain isolation. Directions follow transport roles: on Egress-to-Portal QUIC,
Egress sends with `udp_c2s` and Portal sends with `udp_s2c`.

### TCP encapsulation

```text
client -> server  +-------------+-----------+-----------------------------+
                  | prelude: 64 | nonce: 12 | ChaCha20-XOR(TLS bytes)     |
                  +-------------+-----------+-----------------------------+
server -> client                            | ChaCha20-XOR(TLS bytes)     |
                                            +-----------------------------+
```

The client sends a 64-byte random prelude and a 12-byte random nonce before the
masked TLS stream. These 76 bytes are not encrypted by Morph. The server consumes
them without interpreting the prelude and sends no bootstrap of its own.
`NOW_MORPH_TCP_PRELUDE=full8` uses all random bits; `low7` clears each byte's high
bit. Both modes have the same length and are accepted by the receiver.

Each direction uses IETF ChaCha20 with its directional key, the client's nonce
and initial block counter zero. Cipher positions advance continuously across
reads, writes and TLS records, independently by direction. Partial writes advance
only by bytes actually written. Exhaustion fails the stream before keystream
reuse; the Rust runtime bounds each direction to `2^38 - 64` bytes.

### UDP encapsulation

```text
+-------------------+-------------------------------------------+
| nonce: 12         | ChaCha20-XOR(one QUIC UDP datagram)       |
+-------------------+-------------------------------------------+
```

Each outgoing UDP datagram receives a fresh unpredictable 12-byte nonce. Apply
IETF ChaCha20 with the sending direction's key and block counter zero, then prefix
the nonce. The receiver removes the nonce and applies the corresponding key.
The 12-byte prefix is outside the QUIC packet and must be included in path-MTU
accounting. Packets no longer than the nonce are discarded.

A segmented send applies an independent nonce and transform to every UDP segment.
A coalesced receive removes each segment's nonce separately and adjusts lengths
and stride before handing datagrams to QUIC. UDP boundaries must be preserved;
a nonce is never shared across a GSO batch as if it were one datagram.

Morph provides wire masking, not authentication or integrity. TLS/QUIC still
provides authenticated encryption, certificate validation and replay protection.

## Related documentation

The wire specification defines peer behavior. Operational interfaces have their
own references:

| Reference | Scope |
|---|---|
| [Configuration](configuration.md) | Role URLs, parsing, source binding and effective configuration |
| [Security](security.md) | Certificate trust, admission and resource boundaries |
| [Telemetry](telemetry.md) | `nowhere.telemetry.3`, local IPC and process statistics |
| [Interoperability](interoperability.md) | Peer implementation requirements |
| [Testing](testing.md) | Reference vectors, regression coverage and validation |

Traffic accounting follows Vector-to-Target direction. Portal bridges count
logical bytes once. IPC exposes only per-process TCP/UDP logical payload totals
and active Flow ownership counts.
Active counts follow resource ownership and decrement once. Per-process totals
cannot be added as unique end-to-end traffic.
