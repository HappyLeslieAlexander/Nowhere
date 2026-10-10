# Platforms

Build and deploy Nowhere on native hosts and in containers.

## Contents

- [Overview](#overview)
- [Release targets](#release-targets)
- [Network exposure](#network-exposure)
- [Container image](#container-image)
- [Command lines](#command-lines)
- [Process control](#process-control)
- [Telemetry](#telemetry)

## Overview

Linux, macOS and Windows share one configuration model and the same Vector,
Portal and Egress connection semantics. Platform-specific IPC and process
sampling follow the operating system's facilities.

Native validation follows [Testing](testing.md#native-validation). A successful
cross-build does not replace execution on the target platform.

## Release targets

| Platform | Architecture and toolchain | Archive |
|---|---|---|
| Linux | x86-64 and AArch64, GNU libc | `.tar.gz` |
| Linux | x86-64 and AArch64, musl | `.tar.gz` |
| FreeBSD | x86-64 and AArch64, cross-built | `.tar.gz` |
| macOS | Apple Silicon | `.tar.gz` |
| Windows | x86-64 MSVC | `.zip` |

The [release workflow](../.github/workflows/release.yml) defines the packaged
targets. FreeBSD packages are cross-built; the native CI matrix covers Linux,
macOS and Windows.

The executable is `nowhere` on Unix hosts and `nowhere.exe` on Windows. Build
and test from the repository root:

```sh
cargo build --release --locked
cargo test --all-targets --locked
```

## Network exposure

Portal binds one socket for every address selected by each declared carrier.
The endpoint path therefore defines both process listeners and the firewall or
container rules required around the process.

| Endpoint | Required inbound exposure |
|---|---|
| `*:2000` | TCP 2000 and UDP 2000 |
| `*/tcp:2006` | TCP 2006 |
| `*/udp:2017` | UDP 2017 |
| `*/tcp:2006/udp:2017` | TCP 2006 and UDP 2017 |
| `*/tcp4:2006/udp6:2017` | IPv4 TCP 2006 and IPv6 UDP 2017 |

An unrestricted `*` carrier opens separate IPv4 and IPv6 wildcard sockets.
IPv6 sockets use `V6ONLY` on Linux, macOS, and Windows, so an IPv6 firewall
rule does not replace the corresponding IPv4 rule. If the operating system
does not support one family, only an unrestricted wildcard carrier may start
with the available family and a warning. Explicit families and concrete bind
addresses fail startup when unavailable.

A hostname listener resolves once at startup and binds every matching address.
DNS changes take effect after a process restart. Vector and Egress resolve the
selected Portal carrier, filter by its `4` or `6` suffix and fail rather than
crossing the declared family boundary.

## Container image

### Build the image

Build from the repository root:

```sh
docker build -t nowhere:local .
```

Container builds support `linux/amd64` and `linux/arm64`. The examples use
the local `nowhere:local` image.

The runtime image uses `scratch`. It contains the statically linked executable
and a CA bundle for default client certificate verification, with no shell,
package manager, or dynamic libraries.

### Run Portal

Start a Portal with its generated certificate:

```sh
docker run -d --rm --name nowhere-portal \
  -p 2000:2000/tcp \
  -p 2000:2000/udp \
  nowhere:local \
  "portal://<generated-key>@:2000"
```

Publish separate carrier ports when the endpoint uses an explicit path:

```sh
docker run -d --rm --name nowhere-portal \
  -p 2006:2006/tcp \
  -p 2017:2017/udp \
  nowhere:local \
  "portal://<generated-key>@*/tcp:2006/udp:2017"
```

Docker publication is transport-specific. Publishing `2006/udp` does not
expose the TCP carrier, and publishing `2017/tcp` does not expose QUIC. For an
IPv4-only or IPv6-only carrier, align the Docker host binding and host firewall
with the endpoint suffix.

### Supply certificates

For `tls=2`, mount the CA-issued PEM certificate chain and private key:

```sh
docker run -d --rm --name nowhere-portal \
  -p 2000:2000/tcp \
  -p 2000:2000/udp \
  -v /path/fullchain.pem:/cert.pem:ro \
  -v /path/private-key.pem:/key.pem:ro \
  nowhere:local \
  "portal://<generated-key>@:2000?tls=2&crt=/cert.pem&key=/key.pem"
```

`crt` is the full certificate chain and `key` is its private key. A Vector
verifies the endpoint host by default; `sni=relay.example` can override that name.
The image CA bundle trusts public CAs. For a private CA, mount its root
certificate and set `SSL_CERT_FILE` to the mounted path.

### Read local status

Run status inside the same container as the service:

```sh
docker exec nowhere-portal /nowhere status
```

The relay and collector must use the same UID and system temporary directory.
Telemetry uses a private Unix socket, not a published network port. Run third-party
collectors inside the same container. Host-to-container, sidecar and cross-container
subscription are outside the supported contract; do not share telemetry directories
across PID or user namespaces.

### Use writable temporary storage

The image supplies `/tmp` with mode `1777` and does not force a user. A non-root
UID can create its own mode-`0700` directory. Mounted certificates and keys must
also be readable by that UID. Read-only containers need writable temporary storage:

```sh
docker run -d --rm --name nowhere-portal \
  --user 10001:10001 --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777 \
  -p 2000:2000/tcp -p 2000:2000/udp \
  nowhere:local \
  "portal://<generated-key>@:2000"
docker exec --user 10001:10001 nowhere-portal /nowhere status
```

### Deploy on Kubernetes

Mount an in-memory `emptyDir` at `/tmp`, use the same UID for the service and
collector, and permit that UID to create its private directory. This
container/volume fragment
uses a group-writable temporary mount and requires no privileged init process:

```yaml
spec:
  securityContext:
    runAsUser: 10001
    runAsGroup: 10001
    fsGroup: 10001
  containers:
    - name: nowhere
      image: nowhere:local
      args: ["portal://<generated-key>@:2000"]
      securityContext:
        readOnlyRootFilesystem: true
        allowPrivilegeEscalation: false
        capabilities:
          drop: [ALL]
      volumeMounts:
        - name: temporary
          mountPath: /tmp
  volumes:
    - name: temporary
      emptyDir:
        medium: Memory
        sizeLimit: 16Mi
```

A missing, full or unwritable temporary mount disables local Telemetry IPC
with a warning; forwarding continues. No TCP fallback, extra capabilities
or host networking are needed. Registry files are written once; messages and
history are not stored in the mount. Process memory and tmpfs count against container resource budgets.
Normal shutdown removes instance files; forced termination can leave files until
safe discovery cleanup or destruction of the temporary mount.

## Command lines

Bourne-compatible shells, PowerShell and Windows Command Prompt accept the
documented double-quoted URLs. Replace `KEY` with `nowhere generate-key` output.
For a generated Portal certificate, set `pin` to a fingerprint verified through
a trusted channel:

```sh
nowhere "vector://KEY@portal.example:2000?net=udp&in=127.0.0.1:1080&pin=TRUSTED_SHA256"
```

On Windows, use the executable's `.exe` name:

```powershell
nowhere.exe "vector://KEY@portal.example:2000?net=udp&in=127.0.0.1:1080&pin=TRUSTED_SHA256"
```

A CA-issued certificate with a matching hostname can use normal trust without
a pin. See [certificate trust](security.md#certificate-trust).

Certificate and key values accept native filesystem paths. Relative paths
resolve from the process working directory. Quote the URL when a path or query
contains shell-significant characters.

## Process control

Interactive instances stop with Ctrl+C on every platform. Unix process
managers may send SIGINT or SIGTERM. Windows services should use a wrapper
that forwards a console termination event and allows `NOW_SHUTDOWN_TIMEOUT` to
complete.

Local Telemetry discovery uses a protected per-user registry in the system
temporary directory and local IPC: Unix sockets or Windows named pipes. Linux also
checks boot, PID namespace and user namespace identity before PID-based cleanup.
See the [telemetry contract](telemetry.md).

## Telemetry

All roles publish lifecycle, traffic and active Flow/Carrier counts. Local IPC
and optional process samples depend on the host:

| Host | IPC | CPU, RSS and file descriptors |
|---|---|---|
| Linux | Unix domain sockets | Best-effort samples from `/proc` |
| macOS | Unix domain sockets | `null` |
| Windows | Local named pipes | `null` |

Unavailable samples remain `null` in JSON and display as a dash in status.
Forwarding continues independently of resource sampling. Permissions, peer
identity and discovery are defined by the [Telemetry contract](telemetry.md).

The [native CI workflow](../.github/workflows/ci.yml) runs on Linux, macOS and
Windows. Use [Testing](testing.md) to record coverage and validation results.
