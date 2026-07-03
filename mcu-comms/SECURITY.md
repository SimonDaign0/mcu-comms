# Security

## Status

`mcu_comms` is **pre-1.0 and has not undergone independent cryptographic
review**. The AES-CCM core follows RFC 3610 and is relatively easy to
sanity-check against the spec. The key-rotation protocol is original design
built specifically for this crate and is the part most in need of outside
scrutiny — please read this document before relying on it, and see
"Reporting a Concern" below if you find something.

**Do not use this crate to protect anything where a failure would cause
real harm (safety-critical systems, medical devices, financial systems,
access control for physical security) until it has received review from
someone with cryptographic protocol design experience.**

## Threat model

`mcu_comms` is designed for exactly two fixed peers communicating over a
link that is:

- **Unauthenticated at the transport layer** — anyone in radio range can
  send, receive, jam, drop, duplicate, delay, or reorder packets.
- **Unreliable and unordered** — no assumption of delivery or ordering is
  made anywhere in the protocol.
- **Resource-constrained** — no heap, no asymmetric crypto, minimal RAM/flash
  budget for protocol state.

Given a shared 128-bit symmetric key known only to the two peers, the goals
are:

1. **Confidentiality** of payload data against a passive eavesdropper.
2. **Authenticity/integrity** — a receiver can detect any tampering,
   forgery, or replay of a packet.
3. **Safe key rotation** — the shared key can be periodically replaced
   without a window in which nonce reuse, key desynchronization, or a
   downgrade to an old key is possible, even under packet loss.

### Explicitly out of scope

- **Key distribution.** How the initial shared key gets onto both devices
  (manual flashing, a factory provisioning step, etc.) is the integrator's
  responsibility. This crate assumes the key is already present and secret
  on both ends.
- **Denial of service.** An attacker who can jam the radio or flood packets
  can prevent communication. Nothing here defends against that.
- **Physical/side-channel attacks.** Power analysis, fault injection, and
  similar hardware-level attacks against the AES peripheral itself are not
  addressed by this crate — that's a property of your HAL's `Encrypt`
  implementation and hardware, not this code.
- **Multi-party / group keys.** This crate is explicitly two-peer. Sharing
  one key across more than two devices reintroduces nonce-collision risk
  and is not supported — each `AESCCM` instance is bound to exactly one
  peer's MAC address for this reason.

## Design guarantees and how they're maintained

| Guarantee                                                       | Mechanism                                                                                                                                                                    |
| --------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| No nonce reuse under a given key                                | Peer-bound instances (one key = one peer = one counter space); monotonic 40-bit counter enforced on both send and receive                                                    |
| Nonce survives reboot/power loss                                | `NonceStore` trait, checkpointed ahead of the persisted value on load rather than resumed exactly, to tolerate unflushed writes                                              |
| Tag verification is constant-time                               | `is_tag_match_const_time` avoids early-exit comparison                                                                                                                       |
| Key rotation cannot desynchronize peers permanently             | Proof-of-possession commit: a peer only commits to a new key after successfully authenticating traffic under that key, not merely a plaintext claim                          |
| Retransmitted rotation control packets cannot cause nonce reuse | Control packets have a fixed, empty payload — retransmitting the same plaintext at the same nonce leaks nothing, since there is only one possible plaintext for that message |
| Cross-platform buffer/wire agreement                            | `#[payload]` macro computes worst-case size from fixed-width types only; `usize`/`isize` are disallowed in payload structs / enums                                           |

## Known limitations / accepted risks

- **The epoch-key derivation (`AES_encrypt(root_key, root_key XOR wrapping epoch)`)
  is a custom construction**, not a standardized KDF like HKDF or a
  CMAC-based derivation. It is believed sound (AES is a permutation for a
  fixed key, so this is injective in `epoch`), but it has not been reviewed
  against known related-key or key-derivation attack literature. This is
  the single highest-priority item for outside review.
- **Nonce persistence relies on the integrator's `NonceStore`
  implementation.** If a device's storage medium fails silently, is not
  actually durable, or the checkpoint interval is set too large relative to
  crash frequency, nonce reuse becomes possible again. This crate cannot
  enforce correct `NonceStore` behavior — get this reviewed for your
  specific hardware.
- **No protection against a compromised device.** If one peer's key is
  extracted (e.g. via flash dump), all past and future traffic on that
  pairwise link is compromised. This is inherent to symmetric,
  non-forward-secret designs and is a deliberate simplicity/resource
  tradeoff, not an oversight — forward secrecy would require asymmetric
  crypto this crate is explicitly avoiding.
- **No sender/destination check beyond what's structurally implied.**
  Confirm this matches your integration's expectations if you rely on
  `decrypt()` implicitly authenticating "this came from my configured peer"
  — the guarantee is "this came from someone holding the key for this
  peer's `AESCCM` instance," which is equivalent only if you have not
  shared the key elsewhere.

## Reporting a concern

**This project is not yet requesting review.** Core pieces described in
this document (see [Implementation status](./README.md#implementation-status))
are still being built. Please hold off on filing issues about missing or
incomplete functionality — that's expected right now, not a bug.

Once the key rotation protocol and its test suite are complete, this
section will be updated with an explicit call for cryptographic review,
and that will be the right time to look closely at the design and report
concerns.

In the meantime, if you notice something that looks like an actual
**security flaw in the parts already marked ✅ Implemented** (not a
missing feature), feel free to open an issue — but general design
feedback on unfinished pieces is better saved for after the review call
goes out.

## Implementation status

| Component                                        | Status                                   |
| ------------------------------------------------ | ---------------------------------------- |
| AES-CCM core (encrypt/decrypt, tag verification) | ✅ Implemented                           |
| `#[payload]` macro                               | ✅ Implemented                           |
| Peer-bound sessions                              | 🚧 In progress — not yet safe to rely on |
| `NonceStore` persistence + checkpointing         | 🚧 In progress — not yet safe to rely on |
| Key rotation handshake                           | 🚧 In progress — not yet safe to rely on |
