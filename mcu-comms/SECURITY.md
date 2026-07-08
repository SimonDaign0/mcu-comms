# Security

## Status

`mcu_comms` is **pre-1.0 and has not undergone independent cryptographic
review**. The AES-CCM core follows RFC 3610 and is relatively easy to
sanity-check against the spec. The key-rotation protocol is HKDF-based and
is the least-reviewed part of this crate. Read this document before relying
on `mcu_comms` for anything, and see "Reporting a Concern" at the bottom if
you find something.

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
  Given a shared 256-bit root key known only to the two peers, the
  protocol's goals are:

1. **Confidentiality** of payload data against a passive eavesdropper.
2. **Authenticity/integrity** — a receiver can detect any tampering,
   forgery, or replay of a packet.
3. **Safe key rotation** — the shared key can be periodically replaced
   without a window in which nonce reuse, key desynchronization, or a
   downgrade to an out-of-window key is possible, even under packet loss.

### Explicitly out of scope

- **Key distribution.** How the initial shared root key gets onto both
  devices (manual flashing, a factory provisioning step, etc.) is the
  integrator's responsibility. This crate assumes the key is already
  present and secret on both ends before a `PeerChannel` is constructed.
- **Denial of service.** An attacker who can jam the radio or flood packets
  can prevent communication. Nothing here defends against that.
- **Physical/side-channel attacks.** Power analysis, fault injection, and
  similar hardware-level attacks against the AES peripheral itself are not
  addressed by this crate — that's a property of your HAL's `Encrypt`
  implementation and hardware, not this code.
- **Multi-party / group keys.** This crate is explicitly two-peer. Sharing
  one key across more than two devices reintroduces nonce-collision risk
  and is not supported — each `PeerChannel` is bound to exactly one peer's
  MAC address for this reason.
- **Forward secrecy.** Not provided — see "Known limitations" below.

## Packet authentication and confidentiality

Payloads are encrypted and authenticated with AES-CCM per RFC 3610. Each
packet header includes the sender's MAC, a 40-bit nonce, and a 32-bit
epoch, all of which are authenticated (the MAC and epoch are also used to
select the decryption key and expected nonce range on the receiving side).
Tag verification uses a constant-time comparison
(`is_tag_match_const_time`) so that a mismatched tag doesn't leak timing
information about where the mismatch occurred.

Replay protection falls out of the nonce being a strictly monotonic
per-key counter, enforced on receive: a packet whose nonce is not greater
than the last accepted nonce for that key is rejected.

## Key rotation protocol

Keys are derived from the root key via HKDF, keyed on a 32-bit `epoch`
counter. There is no handshake: each side advances its own epoch
independently and signals the new epoch inline, in the packet header,
rather than negotiating it up front.

**Key cache.** Each peer maintains a 1-wide sliding window of derived keys
centered on its current epoch: the previous epoch's key, the current
epoch's key, and the next epoch's key are all kept live at once. This is
what lets rotation tolerate packet loss — a peer doesn't need to see every
packet in order to stay synchronized with the other side's epoch.

**Nonce tracking across a rotation.** While a peer is still on the previous
epoch, incoming packets continue to be checked against that epoch's last
known nonce. The first packet that arrives carrying the _new_ epoch resets
nonce tracking to that packet's nonce value, and the receiver's current
epoch advances to match. The receiver's notion of "current epoch" follows
the sender's, packet by packet, rather than being driven by a local timer.

**Out-of-window packets.** If a received packet's epoch falls outside the
cached window (too old or too far ahead), the corresponding key is derived
on the fly, solely to check whether the packet is validly encrypted and
authenticated:

- If it is **not** valid, it's dropped as usual — indistinguishable from a
  forged or corrupted packet.
- If it **is** valid but simply outside the window, it is still dropped,
  since nonce continuity can't be verified for an epoch that isn't cached
  — but a resync packet is sent back to the sender to bring it back to the
  receiver's current epoch/nonce.
  This bounds how much epoch drift is tolerated (one epoch behind or ahead)
  while avoiding unbounded key-derivation cost for arbitrary epoch claims,
  which is the mechanism behind the "no downgrade to an out-of-window key"
  part of goal 3 above.

**Automatic rotation triggers.** A peer rotates to the next epoch
automatically either when its own nonce counter is close to exhaustion, or
upon receiving a resync packet from the other side. There is no manual or
time-based rotation trigger.

## Design guarantees and how they're maintained

| Guarantee                            | Mechanism                                                                                                                                         |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| No nonce reuse under a given key     | Peer-bound instances (one key = one peer = one counter space); monotonic 40-bit counter enforced on both send and receive                         |
| No nonce reuse across a key rotation | Sliding key-cache window plus resync-on-out-of-window behavior — see [Key rotation protocol](#key-rotation-protocol)                              |
| Replay rejection                     | Strictly increasing nonce check on receive, per key                                                                                               |
| Nonce survives reboot/power loss     | `Store` trait, checkpointed ahead of the persisted value on load rather than resumed exactly, to tolerate unflushed writes                        |
| Tag forgery / tampering detection    | AES-CCM tag, verified with constant-time comparison                                                                                               |
| No handshake-blocking on rotation    | Rotation happens automatically on nonce exhaustion or resync receipt, not via negotiation — a peer never blocks sending on a handshake completing |
| Cross-platform buffer/wire agreement | `#[payload]` macro computes worst-case size from fixed-width types only; `usize`/`isize` are disallowed in payload structs/enums                  |

## Known limitations / accepted risks

- **No forward secrecy.** If one peer's key material is extracted (e.g. via
  a flash dump), all past and future traffic on that pairwise link is
  compromised. This is inherent to a symmetric, non-forward-secret design
  and is a deliberate simplicity/resource tradeoff, not an oversight.
  Forward secrecy would require asymmetric crypto or computation this
  crate is explicitly avoiding.
- **Nonce persistence relies on the integrator's `Store` implementation.**
  If a device's storage medium fails silently, or is not actually durable,
  nonce reuse becomes possible again. This crate cannot enforce correct
  `Store` behavior — get this reviewed for your specific hardware.
- **Flash wear from epoch/nonce persistence.** To guard against nonce/epoch
  reuse after a reboot, state has to be checkpointed to flash at some
  interval. That interval will likely be relatively coarse (e.g. every
  ~100k counter values), so the persisted value is jumped ahead of the true
  value and re-checkpointed on every boot. A device that reboots unusually
  often can wear flash faster than expected as a result.
- **No sender/destination check beyond what's structurally implied.** The
  guarantee `decrypt()` actually provides is "this came from someone
  holding the key for this peer's `PeerChannel` instance," not "this came
  from my configured peer" in any stronger sense. Those are equivalent only
  if the key hasn't been shared elsewhere — confirm this matches your
  integration's expectations.
- **No denial-of-service resistance**, per the threat model above — an
  attacker able to jam or flood the link degrades or blocks communication
  regardless of anything in this protocol.

## Open questions for reviewers

These are the parts of the design most worth scrutinizing, and where
answers aren't yet pinned down by tests or documentation:

- **AES-CCM core conformance against RFC 3610**, and general review of the
  HKDF-based key derivation, are both still wanted — see "Reporting a
  concern" below.

## Reporting a concern

**This project is not yet requesting a full review.** Core pieces of the
rotation protocol are still being built — see
[Implementation status](./README.md#implementation-status) in the README
for the current state of each component. Please hold off on filing issues
about missing or incomplete functionality; that's expected right now, not
a bug.

Once the key rotation protocol and its test suite are complete, this
section will be updated with an explicit call for cryptographic review,
and that will be the right time to look closely at the full design and
report concerns, including the open questions above.

In the meantime, if you notice what looks like an actual **security flaw
in a component already marked ✅ Implemented** in the README, please open
an issue — general design feedback on unfinished pieces is more useful
once the review call goes out.
