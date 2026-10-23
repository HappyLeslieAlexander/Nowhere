# Egress Extension

Egress is a Nowhere-specific extension to
[Nowhere Protocol (NW3)](protocol.md). It is not part of NW3 Core. The extension
preserves the Core Vector/Portal contract and uses a separately authenticated
QUIC connection for a registered remote exit. It uses ALPN `nw3` without
version negotiation or a capability frame.

An ordinary Vector uses Core authentication and Flow framing even
when Portal forwards through Egress. Vector does not send registration messages,
derive the Egress role key or understand the Portal-to-Egress connection.

## Contents

- [Roles and connections](#roles-and-connections)
- [Configure the peers](#configure-the-peers)
- [Authentication](#authentication)
- [Registration](#registration)
- [Business Streams](#business-streams)
- [UDP identity and bridging](#udp-identity-and-bridging)
- [Registration ownership and lifetime](#registration-ownership-and-lifetime)
- [Morph](#morph)
- [Observe registration](#observe-registration)
- [Validation](#validation)

## Roles and connections

Arrows show connection establishment; all connections carry bidirectional traffic:

```text
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

Egress is the QUIC transport client and Portal is the transport server. Portal
initiates business Streams on the registered connection; Egress accepts them and
resolves/dials their targets. The connection has one fixed business initiation
direction. Egress has no TLS carrier. TLS ingress bridged to QUIC Egress is
ordinary forwarding, not a change to the Vector carrier.

Portal uses one fixed output for its lifetime. `out=egress` requires a QUIC
listener. Target dialing and DNS resolution belong to Egress.

## Configure the peers

Use a Shared Key from `nowhere generate-key` on Portal, Vector and Egress.
Start Portal with a QUIC listener and the Egress output:

```sh
nowhere "portal://KEY@*/tcp:2000/udp:2001?out=egress"
```

Connect Egress using a trusted certificate pin:

```sh
nowhere "egress://KEY@relay.example/udp:2001?pin=TRUSTED_SHA256"
```

A Portal certificate validated by the system CA and hostname can be used
instead of a pin. Vector connects to Portal as described in [Quick start](quick-start.md).

For target source selection, set Egress `dial` or `dial4`/`dial6`. These options
apply to Egress-to-Target work and do not bind the Portal connection. Portal
`out=egress` conflicts with explicit `dial`, `dial4` or `dial6`, including `auto`.
See [Configuration](configuration.md) for option defaults and binding rules.

## Authentication

Core TLS 1.3, ALPN `nw3`, certificate verification and disabled 0-RTT requirements
apply. Shared Key has the same validation and text-byte interpretation as Core.
The extension uses the Core authentication root and an Egress role label:

```text
salt       = SHA256("nowhere/nw3/auth-root")
root       = HMAC-SHA256(salt, shared_key)
egress_key = HMAC-SHA256(root, "egress-authentication" || 0x01)

exporter  = TLS-Exporter("EXPORTER-Nowhere-nw3-Auth", empty_context, 32)
transport = 0x02
AuthFrame = HMAC-SHA256(egress_key, transport || exporter)[0..16]
```

The root and role key are 32 bytes; AuthFrame is exactly 16 bytes, without a role
byte or metadata. Portal compares tags in constant time against the Vector and
Egress role keys and fixes the matching role for the connection lifetime. TLS
permits Vector only: an Egress tag over the TLS transport byte is invalid.
Tags cannot move between connections, resumed connections, roles or carriers.

The same Shared Key derives both authorities. Role derivation is domain
separation, not independent credential isolation. Enabling Egress admission is a
Portal policy decision; knowledge of the key alone does not bypass that policy.
No target dial or Slot ownership precedes successful authentication.

## Registration

Egress sends no Flow bytes on its authentication Stream. RegistrationResult is
one byte: `0` ACCEPTED, `1` BUSY, followed by FIN on the authentication Stream.
Invalid authentication or disallowed Egress policy closes the connection
without an application result. Portal permits registration only with
`out=egress`. It atomically claims the vacant Slot after successful
authentication; an occupied Slot returns BUSY and the
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
Streams can arrive before the registration response; the ACCEPTED barrier
applies to their processing.

Registration uses client bidirectional Stream 0, never a later Stream that
happens to arrive first. RegistrationResult and SetupResult are distinct
messages despite overlapping numeric values:

| RegistrationResult | Meaning |
| --- | --- |
| `00` | ACCEPTED |
| `01` | BUSY |
| Other values, missing result or trailing response bytes | Invalid registration |

The response contains exactly one result byte followed by FIN. Egress waits for
the complete ACCEPTED response before target work. Any registration failure ends
the attempt. The handshake/authentication and registration waits are bounded by
Nowhere's configured deadlines. Unauthenticated DATAGRAMs and DATAGRAMs received
by Egress while awaiting registration are discarded.

## Business Streams

After registration, each Portal-initiated bidirectional Stream starts with the
Core FlowStart and Target and receives one SetupResult from Egress. There is no
AuthFrame on these Streams. The first server bidirectional Stream is 1, followed
by 5, 9, and so on. Client-initiated business Streams on an Egress connection are
role-direction violations and close the connection.

FlowStart reserved-bit handling, Target validation, payload waiting for READY,
TCP half-close, UDP control lifetime, datagram framing and fragmentation use
Core rules. Unidirectional Streams have no application messages.
Each Flow sends at most one SetupResult. Invalid or truncated requests and
ordinary resource/dial failures affect only that Flow; failures after READY
close/reset it without another result. There is no carrier fallback.

## UDP identity and bridging

Validate that the raw Stream is bidirectional and **server-initiated** before
calculating the same Core formula in a wide integer:

```text
flow_id = (quic_stream_id >> 2) + 1
1 <= flow_id <= 2^30 - 1
```

The last usable raw Egress Stream ID is `4294967289`. Never truncate or wrap.
The authentication Stream creates no UDP route. Each ID is local to its own
connection. At exhaustion stop admitting Flows, drain for the configured bounded
deadline, close and reconnect. No control frame resets the ID space.

After READY, UDP control Streams remain open in both directions without business
bytes. FIN, RESET, STOP_SENDING, idle timeout or connection loss performs
idempotent Flow cleanup. CLOSE DATAGRAM is auxiliary. Unknown, unauthenticated
and not-yet-READY IDs are dropped without creating reassembly state.

Portal bridges complete business datagrams. Each leg reassembles and encodes
independently using its own ID and MTU. Client Stream 4 derives ID 2; Egress
server Stream 1 derives ID 1:

```text
+----------+                    +----------+                    +----------+
|  Vector  |<== ID 2 packets ==>|  Portal  |<== ID 1 packets ==>|  Egress  |
+----------+                    +----------+                    +----------+
```

Each bridge owns its two Flow handles; no cross-connection ID identity is
implied. Resource queues and reassembly remain bounded independently on both legs.

## Registration ownership and lifetime

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

All Vectors using this Portal output share the registered connection's
congestion and resource budgets. Egress reconnects after the configured backoff,
`NOW_SERVICE_COOLDOWN` (default `3s`), and must register again. Previous Flows
stay closed; Flow identity and target state are not restored.

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

When enabled, the Core UDP Morph transform masks Egress QUIC packets. Directional keys follow
**transport roles**, not business-Stream initiation: Egress sends with `udp_c2s`
and Portal sends with `udp_s2c`. Each outgoing UDP datagram has its own nonce;
segmentation and MTU accounting retain Core behavior. Both peers must agree on
Shared Key and Morph enablement out of band.

## Observe registration

The Slot's registration ownership is internal. IPC reports only logical TCP/UDP
traffic and active business Flows; an idle registration does not add a Flow.
Egress connection or registration failures are emitted to stderr as raw errors.
The service retries while running. `nowhere probe` checks target setup through
the configured Portal output. See [Operations](operations.md) and [Telemetry](telemetry.md).

## Validation

The [authentication and role fixtures](../src/tests/protocol/vectors.json)
are part of the GPL-3.0-only Nowhere test suite, including Egress key/tag and
RegistrationResult values. The Egress/TLS tag is a negative role-validation
fixture, not a supported carrier.

Tests cover mixed TLS/QUIC Vector ingress, TCP/UDP forwarding, Morph on/off,
registration barriers, BUSY, role-direction rejection, stale-owner cleanup,
disconnect and reconnect. See [Testing](testing.md).
