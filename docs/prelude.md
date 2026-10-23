# Prelude Extension

Authenticated Prelude is a Nowhere-specific extension to
[Nowhere Protocol (NW3)](protocol.md). It carries Shared Key authentication data
in the 64-byte Morph TCP Prelude. Portal verifies each Tag and checks replay
state for matching tags before sending a TLS response. Nonmatching tags follow
the acceptance policy below.

The extension uses the Core TCP envelope, Nonce and directional cipher keys.
It requires no additional message, ALPN, negotiation or round trip. TLS 1.3,
certificate verification, exporter-bound AuthFrame and Flow processing apply.
The extension operates only on Morph TCP.

## Contents

- [Wire layout](#wire-layout)
- [Authentication](#authentication)
- [Identity and Counter](#identity-and-counter)
- [Replay window](#replay-window)
- [Silent admission](#silent-admission)
- [Acceptance policy and limits](#acceptance-policy-and-limits)

## Wire layout

The TCP envelope starts with a 64-byte Prelude and a 12-byte random Nonce:

```text
Offset  0                          64             76
        +--------------------------+--------------+------------------------+
        |      Prelude (64B)       | Nonce (12B)  | ChaCha20-XOR(TLS) ...  |
        +--------------------------+--------------+------------------------+

Offset  0                          32                         64
        +--------------------------+--------------------------+
        |      Prefix P (32B)      |    Encoded tail (32B)    |
        +--------------------------+--------------------------+
          Base policy bytes          H bit + 7 payload bits per byte

Bit       7   6   5   4   3   2   1   0
        +---+---------------------------+
Tail    | H |    Masked payload bits    |
        +---+---------------------------+
        Repeated for all 32 tail bytes.
```

Vector first generates all 64 bytes using the configured
[Prelude policy](configuration.md#tcp-morph-prelude): `fade`, `full8` or `low7`.
It preserves the first 32 bytes and every highest bit, replacing only the tail's
low seven bits. The tail carries `32 x 7 = 224` bits, exactly 28 bytes:

```text
Offset  0                8              14                           28
        +----------------+--------------+----------------------------+
        | Identity (8B)  | Counter (6B) |         Tag (14B)          |
        +----------------+--------------+----------------------------+
```

Identity and Counter are unsigned big-endian integers. Payload bits are encoded
most significant bit first, in byte order. No visible marker or version field
is reserved. Nonce remains twelve independent CSPRNG bytes; none of its bits
are reused for authentication metadata. Portal uses one decoder for all policies.

## Authentication

The authentication input uses these byte strings:

| Symbol | Size | Meaning |
|---|---|---|
| `P` | 32 bytes | `Prelude[0..32]` |
| `N` | 12 bytes | Morph Nonce |
| `H` | 4 bytes | Highest bits of `Prelude[32..64]`, packed MSB-first |
| `I` | 8 bytes | Encoded Identity |
| `C` | 6 bytes | Encoded Counter |

Derive two separate keys from the Morph root:

```text
root     = HMAC-SHA256(key="nowhere/nw3/morph", data=SharedKey)
auth_key = HMAC-SHA256(key=root, data="tcp prelude auth" || 0x01)
mask_key = HMAC-SHA256(key=root, data="tcp prelude mask" || 0x01)

Tag      = HMAC-SHA256(key=auth_key, data=N || P || H || I || C)[0..14]
Mask     = HMAC-SHA256(key=mask_key, data=N || P || H)[0..28]
Payload  = (I || C || Tag) XOR Mask
```

SharedKey is the validated ASCII byte string, without hexadecimal decoding.
Labels are exact ASCII bytes without terminators or version suffixes.
The root, auth key and mask key are 32 bytes. Auth and mask keys are independent
of the four directional TCP/UDP keys.

Split Payload into 32 consecutive seven-bit groups, MSB-first, and write each
group to a tail byte's low seven bits. Preserve that byte's highest bit.
Portal reverses this encoding, reconstructs Mask, recovers Identity, Counter and
Tag, and compares all fourteen Tag bytes in constant time. A matching Tag marks
an authenticated input before Counter validity is checked.

## Identity and Counter

Each Vector instance lazily generates one random 64-bit Identity on its first
Morph TCP connection. All TCP Flows and TLS client clones share that Identity
and one atomic Counter. QUIC and disabled Morph do not allocate counter values.

Counter starts at one and is allocated immediately before Prelude encoding and
transmission. Each allocation is unique, including concurrent attempts. Failed
connections and cancelled tasks consume any value already allocated. Values
range from `1` through `2^48-1`; exhaustion rejects further allocations without
wrapping. Identity and Counter are not persisted. A new Vector instance creates
fresh state.

## Replay window

All TCP listeners of one Portal instance share a fixed registry:

| State | Bound | Update rule |
|---|---|---|
| Identity FIFO | 16,384 entries | Append on first successful registration |
| Highest Counter | One per Identity | Advance when a higher Counter commits |
| Replay bitmap | 1024 bits per Identity | Mark accepted Counter offsets |

Bit zero represents Highest Counter. Increasing the highest value shifts old
marks toward larger offsets; a jump of 1024 or more clears the previous window.
An unused Counter up to 1023 below Highest is accepted. Zero, duplicate values
and values below the window are rejected.

```text
Counter     Highest    Highest - 1    ...     Highest - 1023
Offset         0            1         ...          1023
         +-----------+-------------+-------+------------------+
Bitmap   |     1     |    0 / 1    |  ...  |      0 / 1       |
         +-----------+-------------+-------+------------------+
           Newer values advance the window; older values fall out.
```

Updating an existing Identity does not refresh FIFO order. At capacity, a new
Identity replaces the oldest registration. An evicted Identity can register
again. Established Flows do not reference registry entries and survive eviction.
There is no TTL, timer, persistence or additional Nonce cache. Registry storage
is preallocated; registration, window updates and eviction allocate no per-Flow
memory. A new Portal instance starts with an empty registry.

## Silent admission

Portal applies the accept-time handshake deadline, admission limits, bounded
discard budget and socket close policy. For a matching Tag, Prelude verification
precedes ClientHello parsing; successful parsing precedes replay commit:

```text
      Vector                                            Portal
         |                                                 |
         |---------------- TCP connection ---------------->|
         |-------------- Prelude + Nonce ----------------->|
         |                                     Verify Tag  |
         |                              Replay precheck    |
         |-------------- Masked ClientHello -------------->|
         |                              Silent Acceptor    |
         |                          Replay recheck/commit  |
         |                          Linger/deadline check  |
         |<-------------- TLS 1.3 response ----------------|
         |------------------- AuthFrame ------------------>|
         |<================== Flow data ==================>|
         |                                                 |
```

Prelude alone never reserves a Counter. Incomplete or malformed ClientHello
leaves replay state untouched. After rustls Acceptor accepts ClientHello, Portal
checks the deadline and atomically rechecks and commits replay state before any
TLS response. Concurrent copies can commit only once while their Identity
remains registered. A mutex protects registry operations and is released before
network IO or TLS work. Poisoned state rejects authenticated inputs.

Replay rejection stays on the silent discard path and cannot use the
Tag-mismatch path. Later socket, TLS, ALPN or AuthFrame failures do not undo a commit.
Configuration-dependent TLS checks after the silent boundary can send alerts.

## Acceptance policy and limits

Portal applies these rules to every complete Morph TCP bootstrap:

| Tag and Counter | Result |
|---|---|
| Nonmatching Tag | Parse ClientHello silently; do not access replay state |
| Matching Tag, valid unused Counter | Precheck, parse ClientHello, then atomically recheck and commit |
| Matching Tag, zero, duplicate or out-of-window Counter | Reject silently; no fallback |

A receiver that ignores Prelude contents can consume this envelope. No
negotiated policy or additional configuration is needed.

The Tag-mismatch path permits an observer to modify a captured Prelude,
invalidate its Tag and bypass replay checks. The Tag does not bind the complete
ClientHello: a captured bootstrap can race its first use with a modified hello
and consume its Counter. FIFO eviction and Portal restart discard history.
Shared Key holders can churn the FIFO or advance windows; random 64-bit
Identity collisions can cause unwanted window sharing.

Captured bootstrap data permits offline checks of guessed Shared Keys. Masking
hides Identity and Counter from observers without the key, but provides no
forward secrecy for this metadata after Shared Key disclosure.

The 112-bit Tag authenticates bootstrap metadata. TLS supplies integrity for
the connection. See [Security](security.md#morph-transport-protection) and
[Interoperability](interoperability.md) for the full protection boundary and
peer requirements.
