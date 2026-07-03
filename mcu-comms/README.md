# mcu_comms

> ⚠️ **Status: `0.1.0`, under active development.** The core AES-CCM implementation
> follows RFC 3610. The key-rotation protocol is **original design** and has
> **not yet received independent cryptographic review**. Please read
> [SECURITY.md](./SECURITY.md) before using this in anything that matters.
> Feedback and review are very welcome — see "Getting Involved" below.

A lightweight, `#![no_std]`, zero-allocation AES-CCM communication layer for
resource-constrained microcontrollers, with:

- **RFC 3610–conformant AES-CCM** authenticated encryption, generic over any
  hardware AES peripheral via a small HAL trait.
- **Peer-bound sessions** — one `AESCCM` instance is tied to exactly one
  fixed peer (MAC address) and one shared symmetric key, by construction.
- **A symmetric-only key rotation protocol**, designed for links with no
  coordinator, no PKI, and no reliable/ordered transport (packet loss and
  reordering are assumed, not exceptional).
- **A `#[payload]` attribute macro** that computes the exact worst-case
  encoded buffer size for your data structures at compile time, so you never
  have to hand-size static buffers or guess at overflow margins.

This crate was originally built for [ESP-NOW](https://www.espressif.com/en/solutions/low-power-solutions/esp-now)
but has no ESP-NOW-specific dependencies — anything that can hand you raw
bytes over an unreliable, unordered, peer-to-peer link (LoRa, nRF24, a bare
UART pair, etc.) can use it.

## Why this exists

Most existing lightweight embedded radio protocols solve key management by
either:

- **Centralizing trust** in a coordinator that pushes keys to all nodes
  (e.g. Zigbee's Trust Center model), or
- **Running a full asymmetric handshake** over a reliable transport
  (e.g. Thread's EC-JPAKE + DTLS).

Neither fits a bare two-peer radio link with no infrastructure and no room
for a public-key stack. `mcu_comms` targets that specific gap: two fixed
peers, symmetric primitives only, and a link where messages can be lost or
arrive out of order.

The AES-CCM primitive itself is not novel — see
[RustCrypto's `aes-ccm`](https://github.com/martindisch/aes-ccm) for a
mature, more general-purpose `no_std` implementation if you don't need the
peer-binding and rotation protocol here. What `mcu_comms` adds on top is the
rotation protocol and the buffer-sizing macro.

## Design overview

### Packet layout

```text
+----------------+----------------+-----------------+------------------+----------------+
| MAC (6 bytes)  | flags (1 byte) | nonce (5 bytes)  | ciphertext (N)   | tag (16 bytes) |
+----------------+----------------+-----------------+------------------+----------------+
                   \___________ HEADER (12 bytes) __________/
```

- **Nonce** is a monotonically increasing 40-bit counter, persisted across
  reboots via a `NonceStore` trait you implement for your device's flash/
  EEPROM/FRAM.
- **Flags** carry a reserved bit for key-rotation control packets, which are
  authenticated but carry an empty payload.
- **Tag** is verified in constant time.

### Key rotation

Rotation uses a three-message, proof-of-possession commit protocol:

1. The initiator derives a candidate key for the next epoch and sends a
   `RotateRequest`, still under the _current_ key.
2. The responder derives the same candidate key locally, but does not switch
   to it — it replies with a `RotateAck`, itself encrypted under the _new_
   key. Since the responder can only produce a valid tag under the new key
   if it actually derived it correctly, this ack is cryptographic proof of
   possession, not just a claim.
3. Once the initiator successfully verifies a new-key-encrypted ack, it
   commits: this is the one atomic, one-way step in the protocol. The
   responder commits the moment it sees _any_ successfully-authenticated
   new-key traffic, so a lost final confirmation doesn't leave it stuck.

Retransmission of the (fixed, empty-payload) `RotateRequest`/`RotateAck`
packets is safe and idempotent, including at the boundary of the nonce
counter's maximum value — see [SECURITY.md](./SECURITY.md) for the exact
guarantees this relies on.

### The `#[payload]` macro

```rust
use mcu_comms::prelude::*;

#[payload]
struct SensorReading {
    temperature_c_x100: i16,
    battery_mv: u16,
    flags: u8,
}
```

This derives `Serialize`/`Deserialize` (via `postcard`) and computes
`SensorReading::FRAME_SIZE` — the exact worst-case encoded size, including
header and tag overhead — as a compile-time constant. The stack buffer used
to hold an encrypted frame of this type is sized to exactly this value; it
can never be too small for a well-formed `SensorReading`, and you never
compute it by hand.

**Constraints on payload types**, enforced at compile time where possible:

- No `usize`/`isize` fields — their wire size depends on the _compiling_
  platform's pointer width, which silently breaks size-agreement (and
  potentially decoding) between mismatched-width peers. Use `u32`/`u64`
  explicitly and cast at the boundary.
- No unbounded collections (`Vec<T>`, `String`) — use fixed-size arrays or
  `heapless` equivalents so the worst case is derivable from the type alone.
- No representation-changing serde attributes (`#[serde(tag = ...)]`, etc.)
  on `#[payload]` types — the size calculation assumes postcard's default
  encoding.

## Usage

```rust
use mcu_comms::prelude::*;

#[payload]
struct Command {
    id: u32,
    value: u16,
}

let mut ccm = AESCCM::new(my_aes_hal, root_key, peer_mac, &mut my_nonce_store);

let packet = PacketData::new(0b0000_0000, Command { id: 1, value: 42 });
let frame = ccm.encrypt(&packet)?;
radio.send(frame.bytes());

// on the receiving device
let cmd: Command = ccm.decrypt(&mut received_bytes)?;
```

See `examples/` for a full round-trip and a rotation-handshake walkthrough.

## Getting involved

This crate wants scrutiny, especially on:

- The AES-CCM core, against RFC 3610.
- The rotation protocol's nonce-uniqueness and atomicity guarantees.
- The XOR-then-AES key derivation used for epoch keys — feedback on whether
  a more standard KDF construction (e.g. CMAC-based) would be preferable is
  very welcome.

Issues, PRs, and review from anyone with cryptography or protocol design
experience are genuinely wanted — please don't assume this has already been
checked by someone more qualified than you.

## License

Dual-licensed under MIT or Apache-2.0, at your option.
