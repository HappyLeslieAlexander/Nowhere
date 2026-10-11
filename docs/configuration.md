# Configuration

Configure roles, transports and a fixed exit with service URLs.

## Contents

- [Role URLs](#role-urls)
- [Endpoints](#endpoints)
- [Vector URL](#vector-url)
- [Portal URL](#portal-url)
- [Egress URL](#egress-url)
- [Parsing and effective configuration](#parsing-and-effective-configuration)
- [Runtime environment](#runtime-environment)

## Role URLs

| Role | URL | Primary settings |
|---|---|---|
| Vector | `vector://KEY@HOST:PORT` | SOCKS ingress `in`; transport `net` |
| Portal | `portal://KEY@HOST:PORT` | Listeners; fixed exit `out` |
| Egress | `egress://KEY@HOST:PORT` | QUIC registration; target source selection `dial*` |

Shared Key is percent-decoded once and used as text bytes. Vector, Portal and
Egress require exactly 32 lowercase hexadecimal text characters. Generate a valid
key with `nowhere generate-key` and use the same value on the peers. Service
URLs do not accept a password component or display-name fragment.

## Endpoints

Declare a common port or separate carrier ports:

```text
portal://KEY@HOST:PORT
portal://KEY@HOST/tcp:PORT/udp:PORT
vector://KEY@HOST:PORT?in=127.0.0.1:1080&net=tcp
egress://KEY@HOST:PORT
```

Portal uses one common host with TCP and UDP ports declared independently.
A compact Portal endpoint enables both transports. Explicit paths may declare
one or both carriers, once each.

| Carrier declaration | Transport | Address family |
|---|---|---|
| `tcp` | Dedicated TLS | IPv4 or IPv6 |
| `udp` | QUIC | IPv4 or IPv6 |
| `tcp4`, `udp4` | TLS or QUIC respectively | IPv4 only |
| `tcp6`, `udp6` | TLS or QUIC respectively | IPv6 only |

Client hosts must be concrete. Portal accepts `*` or an empty listen host.
Unrestricted wildcard listeners may omit an unavailable family with a diagnostic on stderr;
explicit families and concrete binds fail on errors. See
[network exposure](platforms.md#network-exposure) for socket and firewall rules.

Vector selects one carrier with `net=tcp|udp`, default `tcp`. Both carriers
forward TCP and UDP business Flows. Egress always selects QUIC. A compact
client endpoint supplies the selected carrier's port; an explicit path must
include that carrier.

## Vector URL

| Parameter | Meaning | Default |
|---|---|---|
| `in` | SOCKS ingress `[USER:PASS@]HOST:PORT` | Required for a service; optional for probe |
| `net` | `tcp` for dedicated TLS; `udp` for QUIC | `tcp` |
| `sni` | Verified DNS server name | Endpoint host |
| `pin` | Exact certificate SHA-256 | System CA and hostname verification |
| `morph` | `0` or `1`; peers share the key and setting | `0` |
| `rate`, `etar` | Upload/download Mbps; `0` disables the limit | `0` |

A pin is exactly 64 lowercase hexadecimal characters. A missing, empty or
`none` pin uses normal certificate verification. An empty or `none` SNI uses
the endpoint host. Obtain a fingerprint with `nowhere fingerprint` and compare
it through a trusted channel before configuring it. See
[certificate trust](security.md#certificate-trust).

Upload and download follow the Vector-to-Target business direction, regardless
of which transport peer establishes the connection.

## Portal URL

| Parameter | Meaning | Default |
|---|---|---|
| `out` | `direct`, `egress`, or `[USER:PASS@]HOST:PORT` SOCKS5 exit | `direct` |
| `tls` | `1` generated certificate; `2` supplied PEM certificate/key | `1` |
| `crt`, `key` | PEM paths; required exactly when `tls=2` | Absent |
| `dial` | Source IP/single-family policy, or `auto` | Automatic |
| `dial4`, `dial6` | Family-specific source IP, or `auto` | Automatic |
| `morph`, `rate`, `etar` | Same meaning as Vector | `0`, `0`, `0` |

`out=egress` requires a QUIC listener and conflicts with every explicit `dial*`
parameter, including `auto`. The first registered Egress owns the Slot; another
connection receives BUSY. An offline Egress fails new Flows immediately without
waiting, queuing or falling back to direct access. See [Egress](egress.md).

### Target source selection

`dial` is mutually exclusive with `dial4` and `dial6`. Explicit source binding
errors fail the dial; they do not trigger an unbound retry.

### SOCKS credentials

Credentials are split at raw delimiters before each component is decoded once.
Percent-encode reserved credential characters. For example:

```text
out=a%3Ab:p%40ss@127.0.0.1:1080
```

The decoded username is `a:b` and the password is `p@ss`. Vector's `in` uses
the same credential parsing rules.

## Egress URL

Egress accepts `sni`, `pin`, `morph`, `rate`, `etar` and target `dial*`.
Connection options have the same defaults as Vector. Transport is fixed to QUIC.

| Connection | Source selection |
|---|---|
| Egress to Portal | Ordinary automatic source selection |
| Egress to Target | `dial`, or `dial4`/`dial6`, if configured |

Target `dial*` also applies to Egress's target DNS work. Egress waits for ACCEPTED
before target dialing, even if a business Stream arrives first. A reconnect
creates a new connection and does not recover previous Flows.

## Parsing and effective configuration

Unknown parameters and their values are ignored. For recognized parameters,
the first duplicate wins; an invalid first value is an error. Portal defaults
to `out=direct` when `out` is absent. Unknown parameters do not change that default.

| Query | Result |
|---|---|
| `net=tcp&net=udp` | Vector selects TLS |
| `net=invalid&net=tcp` | Configuration error |
| An unknown parameter with no `out` | Portal keeps its default direct output |

Startup output uses `vector starting:`, `portal starting:` or `egress starting:`
followed by a redacted role URL. Query fields use `&` and have a fixed order:

| Role | Field order |
|---|---|
| Vector | `in`, `net`, `sni`, `pin`, `morph`, `rate`, `etar` |
| Portal | `out`, `tls`, applicable `dial*`, `morph`, `rate`, `etar` |
| Egress | `sni`, `pin`, `dial*`, `morph`, `rate`, `etar` |

The order groups ingress or output selection, transport and certificate
verification, target dialing, Morph, traffic limits and logging. Defaults are explicit.
`dial*` is either `dial` or `dial4` followed by `dial6`; omitted family bindings
appear as `auto`. Portal with `out=egress` omits `dial*`. Egress omits `net`
because its Portal connection always uses QUIC.

Shared Key and SOCKS credentials are absent. Portal omits `crt` and `key`,
including when `tls=2`; certificate loading and validation still apply.
Unknown and inapplicable options are omitted. Environment-based runtime budgets
and timeouts are documented separately below. The URL is a diagnostic view;
credentials and certificate files must be supplied separately to launch a service.
IPC Hello contains the validated endpoint and does not contain configuration settings.

## Runtime environment

Set environment variables before starting the service. Byte sizes use integer
values; duration settings use values such as `5s` or `250ms`.

| Variable | Default | Purpose |
|---|---|---|
| `NOW_TCP_DATA_BUF_SIZE` | `32768` | TCP copy buffer bytes |
| `NOW_UDP_DATA_BUF_SIZE` | `65536` | UDP buffer bytes |
| `NOW_TCP_DIAL_TIMEOUT`, `NOW_UDP_DIAL_TIMEOUT` | `15s` | Target dial limits |
| `NOW_HANDSHAKE_TIMEOUT` | `5s` | Transport/authentication limit |
| `NOW_FLOW_SETUP_TIMEOUT` | `20s` | Flow setup limit |
| `NOW_TCP_READ_TIMEOUT` | `30s` | TCP half-close completion limit |
| `NOW_UDP_IDLE_TIMEOUT` | `120s` | UDP Flow/QUIC idle limit |
| `NOW_QUIC_UDP_QUEUE_BYTES` | `4194304` | Connection-wide queue/reassembly reservation |
| `NOW_SHUTDOWN_TIMEOUT` | `5s` | Bounded drain |
| `NOW_RELOAD_INTERVAL` | `1h` | Supplied certificate reload |
| `NOW_SERVICE_COOLDOWN` | `3s` | Egress reconnect backoff |
| `NOW_TRANSPORT_MEMORY_PROFILE` | `throughput` | QUIC window profile |
| `NOW_MORPH_TCP_PRELUDE` | `full8` | Morph prelude mode: `full8` or `low7` |

### QUIC window profiles

| Profile | Stream receive | Connection receive | Send window |
|---|---:|---:|---:|
| `memory` | 4 MiB | 8 MiB | 8 MiB |
| `balanced` | 8 MiB | 16 MiB | 16 MiB |
| `throughput` | 16 MiB | 32 MiB | 32 MiB |

Portal uses a 64 KiB connection receive window before authentication and raises
it after success. Transport windows are separate from UDP application budgets
and do not represent total process memory.

Atomic traffic totals and active Flow ownership counts continue without IPC
clients. Each connected collector receives the current values once per second. See [Telemetry](telemetry.md) for the observation contract.
