# Ecosystem

Connect, deploy and operate with tools built around Nowhere's public interfaces.

## Contents

- [Projects](#projects)
- [Connections and management](#connections-and-management)
- [Share links](#share-links)
- [Service configuration](#service-configuration)

## Projects

Use the layer that fits your workflow. Each project's documentation describes
the protocol and interfaces it supports.

| Project | Purpose | Get started |
|---|---|---|
| [Anywhere](https://github.com/NodePassProject/Anywhere) | Native connections on iOS, iPadOS and tvOS | [App Store](https://apps.apple.com/us/app/id6758235178) · [Import guide](https://github.com/NodePassProject/Anywhere#deep-links) |
| **Vector** | Built-in SOCKS5 ingress for desktop and server applications | [Quick start](quick-start.md) · [Configuration](configuration.md#vector-url) |
| [nowhere-sh](https://github.com/NodePassProject/nowhere-sh) | Linux VPS deployment and service management | [Quick start](https://github.com/NodePassProject/nowhere-sh#quick-start) · [Commands](https://github.com/NodePassProject/nowhere-sh#commands) |
| [OpenCtrl](https://github.com/NodePassProject/OpenCtrl) | Local process supervision through REST and SSE | [Run](https://github.com/NodePassProject/OpenCtrl#run) · [API reference](https://github.com/NodePassProject/OpenCtrl/blob/main/docs/master.md) |
| [NowhereDash](https://github.com/NodePassProject/NowhereDash) | Portal fleet operations through OpenCtrl | [Quick start](https://github.com/NodePassProject/NowhereDash#quick-start) · [Product tour](https://github.com/NodePassProject/NowhereDash#product-tour) |

## Connections and management

Client traffic, deployment and process management use separate interfaces:

```text
Connect

+----------+                 +----------+                 +----------+
| Anywhere |-- wire protocol>|  Portal  |<-- wire protocol|  Vector  |
+----------+                 +----------+                 +----------+

Deploy

+------------+     installs and operates      +----------+
| nowhere-sh |------------------------------->|  Portal  |
+------------+                                +----------+

Manage

+-------------+       REST + SSE       +----------+
| NowhereDash |----------------------->| OpenCtrl |
+-------------+                        +-----+----+
                                            |
                                            | supervises
                                            v
                              +---------------------------+
                              |  Portal / Vector / Egress |
                              +---------------------------+
```

### Connect

Anywhere connects directly to Portal and imports `nowhere://` links. Vector
ships in the `nowhere` binary and exposes a local SOCKS5 endpoint. Client peers
implement the [wire protocol](protocol.md).

### Deploy

nowhere-sh installs and manages one systemd Portal on a Linux VPS. Its
interactive workflow covers release selection, upgrades, transport and Portal
configuration, service lifecycle, logs and generated Anywhere or Vector links.
It operates Portal directly.

### Manage

OpenCtrl runs beside the Portal, Vector or Egress processes it supervises. It stores
process definitions and exposes lifecycle, logs and telemetry through a
versioned REST API and Server-Sent Events. The controller and its children
share a host or container, operating-system user and telemetry namespace.

NowhereDash connects to multiple OpenCtrl endpoints. It operates Portal
instances, displays live telemetry and publishes protected subscriptions with
QR codes and mobile import links. Its management model is Portal-only.

## Share links

Client sharing and service configuration have distinct URL schemes:

| Scheme | Purpose | Consumer |
|---|---|---|
| `nowhere://` | Share a Portal connection and display name | Anywhere; CLI `fingerprint` |
| `vector://` | Configure SOCKS5 ingress | `nowhere` CLI |
| `portal://` | Configure listeners and the fixed exit | `nowhere` CLI |
| `egress://` | Register a QUIC exit connection | `nowhere` CLI |

A `nowhere://` link may include a display-name fragment. Service URLs do not
accept display-name fragments. The external client's import guide defines its
supported share-link fields.

## Service configuration

The CLI runs `portal://`, `vector://` and `egress://` URLs:

```text
portal://KEY@HOST/tcp:2000/udp:2001?out=direct
vector://KEY@HOST/tcp:2000/udp:2001?net=tcp&in=127.0.0.1:1080
egress://KEY@HOST/udp:2001
```

Use a key from `nowhere generate-key`. Vector requires `in` for its local
listener and selects one carrier with `net=tcp|udp`. Egress uses QUIC and
registers only with a Portal configured for `out=egress`.

Vector and Egress verify system CA trust and the server name, or an exact trusted
certificate pin. The endpoint host is the default verified name; `sni` can
override it. See [Security](security.md#certificate-trust).

The `fingerprint` command accepts `nowhere://` links, including display-name
fragments, and reads the certificate over TCP. It uses the endpoint, Shared Key,
`morph` and `sni`; other query parameters are ignored. See
[Operations](operations.md#diagnose-target-setup) for inspection and trust.

[Configuration](configuration.md) defines the complete CLI grammar, defaults,
listener options and environment variables. [Integrations](integrations.md)
describes service supervision and third-party Telemetry subscribers.
