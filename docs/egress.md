# Egress

Place target DNS, TCP and UDP access on a host that connects outward to Portal.

## Contents

- [Connection model](#connection-model)
- [Configure the peers](#configure-the-peers)
- [Registration and ownership](#registration-and-ownership)
- [Disconnect and reconnect](#disconnect-and-reconnect)
- [Observe registration](#observe-registration)

## Connection model

Egress establishes a QUIC connection to Portal. After registration, Portal
opens business Streams on that connection for its Vectors. Arrows show
connection establishment; traffic travels in both directions.

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

Portal uses one fixed output for its lifetime. `out=egress` requires a QUIC
listener. Target dialing and DNS resolution belong to Egress.

## Configure the peers

Use a Shared Key from `nowhere generate-key` on Portal, Egress and Vector.
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
`out=egress` conflicts with every explicit `dial*` parameter, including `auto`.
See [Configuration](configuration.md) for option defaults and binding rules.

## Registration and ownership

The first authenticated connection atomically owns Portal's EgressSlot.
Egress must receive ACCEPTED before processing business Streams or dialing
any target, even if a business Stream arrives before the registration response.

| Condition | Result |
|---|---|
| Slot is vacant and authentication succeeds | ACCEPTED; the connection owns the Slot |
| Slot already has an owner | BUSY; the contender cannot join or replace it |
| Authentication fails or Portal uses another output | The connection closes |
| Registered connection is lost | Dependent Flows terminate and its ownership is released |
| Cleanup belongs to an earlier connection | It cannot release a different owner |

The Slot holds one connection. All Vectors using this Portal output share that
connection's congestion and resource budgets. There is no application heartbeat;
QUIC keepalive and idle mechanisms maintain liveness.

## Disconnect and reconnect

An offline Egress causes new Flows to fail immediately with DIAL_FAILED.
Portal does not wait, queue target work or fall back to direct access.

Egress reconnects after the configured backoff, `NOW_SERVICE_COOLDOWN`
(default `3s`). A reconnect creates a new connection and must register again.
Previous Flows stay closed; Flow identity and target state are not restored.

## Observe registration

`nowhere status` shows ONLINE or OFFLINE for Portal's Egress output and for
Egress itself. Public snapshots expose the same state as `egress_online`.

| Instance | Online condition |
|---|---|
| Portal with `out=egress` | Its Slot owns a valid registered QUIC connection |
| Egress | ACCEPTED was received and that connection remains valid |
| Vector or another Portal output | Not applicable; `egress_online` is `null` |

An idle accepted Egress counts one Carrier and zero business Flows. Carrier
counts do not establish online state. Registration changes update snapshots. See [Telemetry](telemetry.md#egress-registration-state).
