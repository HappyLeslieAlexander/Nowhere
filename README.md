# Nowhere

> **One spec seed. A protocol of your own.**

Nowhere is an encrypted relay protocol built around one idea: protocol
semantics can stay stable without every deployment sharing the same wire
identity.

A compact `spec` is expanded deterministically by the client and Portal into
authentication constants, padding, and field order. The seed is never sent on
the connection. Change it, and the same TCP and UDP relay contract takes a
different shape on the wire.

<div align="center">
  <img src="assets/nowhere.png" width="640" alt="Nowhere">
</div>

## The Idea

Most compact relay protocols have one fixed application-layer shape. Nowhere
keeps the contract small while making that shape deployment-defined.

From a single `spec`, both peers independently derive:

- authentication identity, padding, and field order;
- deterministic padding for TCP requests; and
- field order for TCP requests and UDP datagrams.

The shared key authenticates the connection; `spec` shapes the protocol. No
profile registry or extra negotiation is required. Peers that agree on the
shared key, `spec`, ALPN, and protocol version arrive at the same wire contract.

Nowhere does not imitate another protocol. It removes a simpler invariant: the
need for every deployment to expose one universal application-frame layout.

## One Contract, Two Transports

| Traffic | TLS/TCP | QUIC/UDP |
| --- | --- | --- |
| TCP | Dedicated encrypted connection | Bidirectional stream |
| UDP | Length-prefixed UDP-over-TCP | QUIC DATAGRAM |

Both transports use TLS 1.3, the same authentication model, and the same
spec-derived protocol material. There is no plaintext mode. A Portal can serve
TLS/TCP, QUIC, or both from one configuration URL.

## Run a Portal

```bash
cargo run --release -- 'portal://change-me@:2077?spec=nightfall'
```

The URL username is the shared key. An empty host listens on the IPv4 and IPv6
wildcard addresses, and the default `net=mix` mode starts TLS/TCP and QUIC on
the same port. Clients must use the same key, `spec`, and ALPN.

The default `tls=1` mode creates an ephemeral self-signed certificate. Use
`tls=2` with a PEM certificate and private key for a long-lived deployment:

```bash
nowhere 'portal://change-me@:2077?spec=nightfall&tls=2&crt=/etc/nowhere/cert.pem&key=/etc/nowhere/key.pem'
```

Portal configuration is intentionally expressed as one URL:

```text
portal://<shared-key>@<listen-host>:<listen-port>?tls=<mode>&spec=<spec>&alpn=<alpn>&net=<mode>&dial=<ip-or-auto>&rate=<mbps>&etar=<mbps>&crt=<path>&key=<path>&log=<level>
```

See the [quick start](docs/quick-start.md) and
[configuration reference](docs/configuration.md) for deployment details.

## Documentation

- [Protocol specification](docs/protocol.md)
- [Security model](docs/security.md)
- [Operations guide](docs/operations.md)
- [Documentation index](docs/README.md)

## Build

```bash
cargo build --release --locked
cargo test
cargo clippy --all-targets -- -D warnings
```

Nowhere targets the Rust 2024 edition. Protocol changes should update the test
vectors and protocol specification in the same commit.

## License

GPL-3.0-only. See [LICENSE](LICENSE).
