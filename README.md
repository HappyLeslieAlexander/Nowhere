# Nowhere Protocol

One protocol for streams, datagrams, and difficult networks.

Nowhere is a compact encrypted relay protocol for carrying TCP and UDP traffic
across TLS/TCP and QUIC. Each deployment exposes one authenticated entry point. 
TCP flows use dedicated TLS connections or QUIC streams; UDP flows use 
QUIC DATAGRAM or UDP-over-TCP (UoT) when native UDP is not available.

<div align="center">
  <img src="assets/nowhere.png" width="640">
</div>

## Core Features

- TLS/TCP transport for TCP flows and length-prefixed UoT flows.
- QUIC transport for TCP streams and DATAGRAM-based UDP flows.
- Deterministic `spec` derivation for auth material, padding, and field ordering.
- Independent ALPN selection through `alpn`, without changing the wire layout.
- IPv4, IPv6, and dual-stack listener behavior from a single URL.
- Directional traffic limits through `rate` and `etar`.
- Structured local event records for operational counters.
- No plaintext mode. `tls=1` and `tls=2` are the supported TLS modes.

## Quick Start

```bash
cargo run --release -- 'portal://secret@:2077'
```

The empty listen host binds IPv4 and IPv6 wildcard sockets. The URL username is
the shared key. The default network mode is `mix`, which enables TLS/TCP and
QUIC/UDP on the same port. `net=tcp` still supports UDP through UoT; `net=udp`
still supports TCP through QUIC bidirectional streams.

Build a release binary:

```bash
cargo build --release --locked
./target/release/nowhere --help
./target/release/nowhere --version
```

## Configuration Shape

```text
portal://<shared-key>@<listen-host>:<listen-port>?tls=<mode>&spec=<spec>&alpn=<alpn>&net=<mode>&dial=<ip-or-auto>&rate=<mbps>&etar=<mbps>&crt=<path>&key=<path>&log=<level>
```

Common examples:

```bash
nowhere 'portal://secret@:2077'
nowhere 'portal://secret@0.0.0.0:2077?net=tcp&log=info'
nowhere 'portal://secret@:2077?tls=2&crt=/etc/nowhere/cert.pem&key=/etc/nowhere/key.pem'
nowhere 'portal://secret@:2077?rate=100&etar=200'
```

## Documentation

- [Documentation index](docs/README.md)
- [Quick start](docs/quick-start.md)
- [Configuration reference](docs/configuration.md)
- [Operations guide](docs/operations.md)
- [Security notes](docs/security.md)
- [Protocol specification](docs/protocol.md)

## Development

```bash
cargo fmt --all
cargo test
cargo clippy --all-targets -- -D warnings
```

The repository targets the Rust 2024 edition. Protocol changes should update
the tests and the documentation in the same commit.

## License

GPL-3.0-only. See [LICENSE](LICENSE).
