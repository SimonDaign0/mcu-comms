# mcu_comms

> ⚠️ **Status: under active development.** The core AES-CCM implementation
> follows RFC 3610. The key-rotation protocol is based on HKDF. Please read
> [SECURITY.md](./SECURITY.md) before using this in anything that matters.
> Feedback and review are very welcome, see "Getting Involved" below.

A lightweight, `#![no_std]`, zero-allocation AES-CCM communication layer for
resource-constrained microcontrollers, with:

- **RFC 3610–conformant AES-CCM** authenticated encryption, generic over any
  hardware AES peripheral via a small HAL trait.
- **Peer-bound channels** — one `PeerChannel` instance is tied to exactly one
  fixed peer (MAC address) and one shared root key, by construction.
- **A symmetric-only key rotation protocol** — keys are derived from a root
  key and a 32-bit epoch via HKDF, with no handshake required. See
  [SECURITY.md](./SECURITY.md) for the full rotation state machine.
- **A `#[payload]` attribute macro** that computes the exact worst-case
  encoded buffer size for your data structures at compile time, so you never
  have to hand-size static buffers or guess at overflow margins.
  This crate was originally built for [ESP-NOW](https://www.espressif.com/en/solutions/low-power-solutions/esp-now)
  but has no ESP-NOW-specific dependencies. Anything that can hand you raw
  bytes over an unreliable, unordered, peer-to-peer link (LoRa, nRF24, a bare
  UART pair, etc.) can use it.

## What is the goal

- **Decentralized encrypted trust.** Each `PeerChannel` is built from a
  different shared root key. A single channel serves exactly two peers and
  is based on an incrementing nonce and epoch. No handshake is required.
- **Plug and play.** `mcu_comms`'s main goal is to make setting up a secure
  peer-to-peer channel as easy, lightweight, and carefree as possible, and
  compatible with most microcontrollers.
- **Low power consumption.** Because there's no handshake, peers can send
  packets in high-packet-loss areas without getting stuck in a handshake
  retry loop that drains the battery. (This also means there's no delivery
  guarantee — see [SECURITY.md](./SECURITY.md) for what that trades away.)
  The AES-CCM primitive itself is not novel — see
  [RustCrypto's `aes-ccm`](https://github.com/martindisch/aes-ccm) for a
  mature, more general-purpose `no_std` implementation if you don't need the
  peer-binding and rotation protocol here. What `mcu_comms` adds on top is the
  rotation protocol and the plug-and-play buffer-sizing macro.

## Packet layout

```text
+----------------+----------------+-----------------+------------------+------------------+----------------+
| MAC (6 bytes)  | flags (1 byte) | nonce (5 bytes) | epoch (4 bytes)  | ciphertext (N)   | tag (16 bytes) |
+----------------+----------------+-----------------+------------------+------------------+----------------+
        \__________________ HEADER (16 bytes) _________________/
```

- **Nonce** is a monotonically increasing 40-bit counter, persisted across
  reboots via a `Store` trait you implement for your device's flash /
  EEPROM / FRAM.
- **Epoch** is a monotonically increasing 32-bit counter, also persisted via
  `Store`, which determines the current HKDF-derived encryption key.
- **Flags** carry 2 reserved bits for control packets, which are
  authenticated but carry an empty payload.
  Full detail on key derivation, the rotation window, and nonce/epoch
  resync behavior lives in [SECURITY.md](./SECURITY.md) — read it before
  relying on this for anything sensitive.

## The `#[payload]` macro

```rust
#[derive(Debug, PartialEq, Eq)]
#[payload]
struct CustomDataStructure {
    temp: i16,
    temp_type: TempType,
    battery_mv: u16,
    flags: u8,
}

#[derive(Debug, PartialEq, Eq)]
#[payload]
enum TempType {
    C,
    F,
}
```

This derives `Serialize`/`Deserialize` (via `postcard`) and computes
`CustomDataStructure::FRAME_SIZE` — the exact worst-case encoded size,
including header and tag overhead, as a compile-time constant. The stack
buffer used to hold an encrypted frame of this type is sized to exactly this
value: it can never be too small for a well-formed `CustomDataStructure`,
and you never compute it by hand.

**Constraints on payload types**, enforced at compile time where possible:

- No `usize`/`isize` fields — their wire size depends on the compiling
  platform's pointer width, which silently breaks size agreement (and
  potentially decoding) between mismatched-width peers. Use `u32`/`u64`
  explicitly and cast at the boundary.
- No unbounded collections (`Vec<T>`, `String`) — use fixed-size arrays or
  `heapless` equivalents so the worst case is derivable from the type alone.
- No representation-changing serde attributes (`#[serde(tag = ...)]`, etc.)
  on `#[payload]` types — the size calculation assumes postcard's default
  encoding.
- Serialized `#[payload]` buffers must be ≤ `u16::MAX`, or the payload will
  be rejected at encryption time.

## Usage

```rust
use mcu_comms::prelude::*;

struct AesHal(/* your MCU's AES HAL */);
impl Encrypt for AesHal {
    fn encrypt(&mut self, key_stream_buf: &mut [u8; 16], block: &mut [u8; 16], key: [u8; 16]) {
        /* snip */
    }
}

let mut channel = PeerChannel::new(
    AesHal(aes),
    root_key,
    MacAddr::new(1, 2, 3, 4, 5, 6), // host MAC address
    MacAddr::new(6, 5, 4, 3, 2, 1), // peer MAC address
);

let packet_data = PacketData::new(0b0011_1111, payload).unwrap();

let mut frame = channel.encrypt(&packet_data).unwrap();
send(frame.bytes());

let decrypted = peer_channel.decrypt(&mut bytes).unwrap();
```

See `examples/` for a full round-trip used with actual MCU HALs.

## Implementation status

| Component                                        | Status                                   |
| ------------------------------------------------ | ---------------------------------------- |
| AES-CCM core (encrypt/decrypt, tag verification) | ✅ Implemented                           |
| `#[payload]` macro                               | ✅ Implemented                           |
| Epoch key rotations                              | ✅ Implemented                           |
| Out of window rate limiting                      | 🚧 In progress — not yet safe to rely on |
| `NonceStore` persistence + checkpointing         | 🚧 In progress — not yet safe to rely on |

## Getting involved

This crate wants scrutiny, especially on:

- The AES-CCM core, against RFC 3610.
- The rotation protocol's nonce and epoch uniqueness guarantees (see
  [SECURITY.md](./SECURITY.md)).
  Issues, PRs, and review from anyone with cryptography or protocol design
  experience are genuinely wanted — please don't assume this has already been
  checked by someone more qualified than you.

## License

Licensed under the Apache License, Version 2.0 (LICENSE or http://www.apache.org/licenses/LICENSE-2.0).
