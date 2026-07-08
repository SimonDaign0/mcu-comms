//! # AES-CCM Embedded Packet Cryptography Crate
//!
//! This crate provides a lightweight, `no_std`-compatible implementation of AES-CCM
//! (Counter with CBC-MAC) tailored for resource-constrained microcontrollers.
//! It handles packet serialization, MAC address authentication and handling, nonce tracking,
//! and hardware-accelerated encrypt/decrypt operations through a custom HAL trait.
use core::ops::Deref;

// Package-wide global constants to prevent repetition
pub const HEADER_SIZE: usize = 16;
pub const TAG_SIZE: usize = 16;
const FLAGS_IDX: usize = 6;
const NONCE_OFFSET: usize = 7;
const EPOCH_OFFSET: usize = 12;
const MAC_OFFSET: usize = 0;
const PAYLOAD_OFFSET: usize = HEADER_SIZE;
const RESYNC_FLAG: u8 = 0b10000000;

/// Errors that can occur during packet construction, serialization, or decryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The packet does not match the expected structure or is too small.
    InvalidFormat,
    /// The destination mac address on the packet is not yours
    InvalidMac,
    /// The underlying frame buffer's capacity was exceeded while writing
    /// header or tag bytes (e.g. `T::FrameBuf` too small for this payload type).
    BufferOverflow,
    /// The 5-byte AES counter exceeded its maximum value ($2^{40} - 1$).
    AESCounterOverflow,
    /// Received a packet with a duplicate or older nonce within the current
    /// epoch (replay attack protection). Not raised for packets from other epochs.
    Duplicate,
    /// If reserved bits are overridden with custom flags
    ReservedBitOverride,
    /// Cryptographic verification failed (tampered payload or invalid key).
    Authentication,
    /// Postcard specific error during Encryption/Decryption
    PostcardError,
    /// If serialized payload exceeds u16::MAX in size
    LengthPrefixOverflow,
    /// The incoming packet's epoch is older than this channel's key window can
    /// still decode (the peer has fallen behind, e.g. after being offline).
    /// The caller should send the enclosed resync frame back to the peer.
    PeerDesynced(Frame<Empty>),
    /// Should theoretically never happen, but if it does, the user will need to
    /// flash a new root_key, resetting the PeerChannel completely.
    EpochExhaustion,
    /// Returned when a peer sends a resync packet to sync your epochs. This also means your previous packet was dropped because your epoch was way outdated.
    SuccessfulResync,
    #[cfg(feature = "test-util")]
    /// Purely for debugging purposes .map_err(|_| Error::Debug)?
    Debug,
}

/// A HAL trait to allow different MCUs with AES hardware acceleration to hook onto the AES-CCM implementation.
pub trait Encrypt {
    /// Encrypts the given 16-byte buffer with the given key using the MCU's AES hardware peripheral.
    fn encrypt(&mut self, out_block: &mut [u8; 16], in_block: &mut [u8; 16], key: [u8; 16]);
}

use crate::{Payload, payload_size::Empty, peer_channel::Error::LengthPrefixOverflow};
/// A stack-allocated serialized packet buffer optimized for `no_std` environments.
#[derive(Debug)]
pub struct Frame<T: Payload> {
    pub inner: T::FrameBuf,
    len: usize,
}
impl Clone for Frame<Empty> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner,
            len: self.len,
        }
    }
}
impl Eq for Frame<Empty> {}
impl PartialEq for Frame<Empty> {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}
impl<T: Payload> Default for Frame<T> {
    fn default() -> Self {
        Self {
            inner: T::new_buf(),
            len: 0,
        }
    }
}

impl<T: Payload> Frame<T> {
    fn new(mac: [u8; 6], flags: u8, raw_nonce: [u8; 5], epoch: [u8; 4]) -> Result<Self, Error> {
        let mut frame = Self::default();
        frame.extend_from_slice(&mac)?;
        frame.push(flags)?;
        frame.extend_from_slice(&raw_nonce)?;
        frame.extend_from_slice(&epoch)?;
        Ok(frame)
    }

    fn payload_mut_slice(&mut self) -> &mut [u8] {
        &mut self.inner.as_mut()[HEADER_SIZE..]
    }
    fn finalize(&mut self, payload_len: usize, tag: [u8; 16]) -> Result<(), Error> {
        self.len += payload_len;
        self.extend_from_slice(&tag)
    }
    pub fn bytes(&self) -> &[u8] {
        &self.inner.as_ref()[..self.len]
    }

    fn push(&mut self, byte: u8) -> Result<(), Error> {
        if self.len >= self.inner.as_ref().len() {
            return Err(Error::BufferOverflow);
        }
        self.inner.as_mut()[self.len] = byte;
        self.len += 1;
        Ok(())
    }

    fn extend_from_slice(&mut self, iter: &[u8]) -> Result<(), Error> {
        if iter.len() + self.len > self.inner.as_ref().len() {
            return Err(Error::BufferOverflow);
        }
        self.inner.as_mut()[self.len..self.len + iter.len()].copy_from_slice(iter);
        self.len += iter.len();
        Ok(())
    }
}

/// Represents the raw data fields to be packaged securely into an encrypted frame.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct PacketData<T>
where
    T: Payload,
{
    /// Protocol or routing control flags.
    pub flags: u8,
    /// payload to be serialized and encrypted.
    pub payload: T,
}

impl<T: Payload> PacketData<T> {
    /// Instantiates a new packet data structure ready for processing.
    /// The first 2 dominant bits are reserved
    pub fn new(flags: u8, payload: T) -> Result<Self, Error> {
        if (flags & 0b_11_00_0000) != 0 {
            return Err(Error::ReservedBitOverride);
        };
        Ok(Self { flags, payload })
    }
}
impl PacketData<Empty> {
    fn new_resync() -> Self {
        Self {
            flags: RESYNC_FLAG,
            payload: Empty,
        }
    }
}

/// A standard 6-byte media access control (MAC) address.
#[derive(Debug)]
pub struct MacAddr {
    inner: [u8; 6],
}

impl MacAddr {
    /// Creates a new MAC address from individual octets.
    pub fn new(f1: u8, f2: u8, f3: u8, f4: u8, f5: u8, f6: u8) -> Self {
        Self {
            inner: [f1, f2, f3, f4, f5, f6],
        }
    }
}

impl Default for MacAddr {
    /// Defaults to the broadcast hardware address (`FF:FF:FF:FF:FF:FF`).
    fn default() -> Self {
        MacAddr {
            inner: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        }
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(value: [u8; 6]) -> Self {
        Self { inner: value }
    }
}

impl IntoIterator for MacAddr {
    type Item = u8;
    type IntoIter = core::array::IntoIter<u8, 6>;
    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl Deref for MacAddr {
    type Target = [u8; 6];

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// A 5-byte counter nonce to safeguard transactions against replay attacks.
struct Nonce {
    counter: u64,
}

impl Nonce {
    /// Increments the internal counter state and returns it formatted into a 5-byte array.
    ///
    /// # Errors
    ///
    /// Returns `Err(Error::AESCounterOverflow)` if the counter overflows
    /// the maximum 5-byte threshold (`0xFF_FF_FF_FF_FF`).
    fn inc(&mut self) -> Result<[u8; 5], Error> {
        const MAX_5_BYTES: u64 = 0xFF_FF_FF_FF_FF;
        if self.counter >= MAX_5_BYTES {
            return Err(Error::AESCounterOverflow);
        }
        self.counter += 1;

        let bytes = self.counter.to_be_bytes();
        let mut result = [0_u8; 5];
        result.copy_from_slice(&bytes[3..8]);

        Ok(result)
    }

    /// Sets the underlying counter directly. Typically used when synchronizing with a peer.
    fn set(&mut self, new_counter: u64) {
        self.counter = new_counter;
    }
}

pub struct PacketView<'a> {
    bytes: &'a [u8],
}

impl<'a> PacketView<'a> {
    /// Creates a new `PacketView` from a raw byte slice.
    ///
    /// This performs basic validation via `TryFrom<[u8]>` implementation.
    ///
    /// # Errors
    ///
    /// Returns `Error` if the buffer is too small or malformed.
    pub fn new(bytes: &'a [u8]) -> Result<Self, Error> {
        Self::try_from(bytes)
    }

    /// Returns the 6-byte MAC address from the packet.
    pub fn mac(&self) -> [u8; 6] {
        self.bytes[MAC_OFFSET..MAC_OFFSET + 6].try_into().unwrap()
    }

    /// Returns the packet flags byte.
    pub fn flags(&self) -> u8 {
        self.bytes[FLAGS_IDX]
    }

    /// Returns the raw 5-byte nonce field.
    pub fn raw_nonce(&self) -> [u8; 5] {
        self.bytes[NONCE_OFFSET..NONCE_OFFSET + 5]
            .try_into()
            .unwrap()
    }

    /// Returns the 4-byte epoch field.
    pub fn epoch(&self) -> u32 {
        u32::from_be_bytes(
            self.bytes[EPOCH_OFFSET..EPOCH_OFFSET + 4]
                .try_into()
                .unwrap(),
        )
    }

    /// Returns the raw nonce as a 64-bit integer in be format.
    pub fn nonce(&self) -> u64 {
        let raw_nonce = self.raw_nonce();
        u64::from_be_bytes([
            0,
            0,
            0,
            raw_nonce[0],
            raw_nonce[1],
            raw_nonce[2],
            raw_nonce[3],
            raw_nonce[4],
        ])
    }
}

impl<'a> TryFrom<&'a [u8]> for PacketView<'a> {
    type Error = Error;

    /// Attempts to parse a slice of over-the-air bytes into an organized packet view layout.
    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        if bytes.len() < HEADER_SIZE + TAG_SIZE {
            return Err(Error::InvalidFormat);
        }
        Ok(Self { bytes })
    }
}

/// An immutable, parsed representation of a received over-the-air raw frame.
struct Parts {
    pub mac: [u8; 6],
    pub flags: u8,
    pub raw_nonce: [u8; 5],
    pub epoch: u32,
    pub payload_len: usize,
    pub tag: [u8; TAG_SIZE],
}

impl Parts {
    /// Decodes the 5-byte raw nonce segment into a standard 64-bit unsigned integer counter.
    fn nonce(&self) -> u64 {
        u64::from_be_bytes([
            0,
            0,
            0,
            self.raw_nonce[0],
            self.raw_nonce[1],
            self.raw_nonce[2],
            self.raw_nonce[3],
            self.raw_nonce[4],
        ])
    }
}

impl TryFrom<&[u8]> for Parts {
    type Error = Error;

    /// Attempts to parse a slice of over-the-air bytes into an organized packet view layout.
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() < HEADER_SIZE + TAG_SIZE {
            return Err(Error::InvalidFormat);
        }
        let mac: [u8; 6] = bytes[MAC_OFFSET..MAC_OFFSET + 6].try_into().unwrap();
        let raw_nonce: [u8; 5] = bytes[NONCE_OFFSET..NONCE_OFFSET + 5].try_into().unwrap();
        let epoch = u32::from_be_bytes(bytes[EPOCH_OFFSET..EPOCH_OFFSET + 4].try_into().unwrap());
        let payload_len = bytes.len() - TAG_SIZE - PAYLOAD_OFFSET;

        let tag: [u8; TAG_SIZE] = bytes[bytes.len() - TAG_SIZE..].try_into().unwrap();

        let flags = bytes[FLAGS_IDX];
        Ok(Self {
            mac,
            flags,
            raw_nonce,
            epoch,
            payload_len,
            tag,
        })
    }
}

/// The Associated Data (AD) header layout utilized during authenticating AES-CCM blocks.
pub struct AdHeader {
    inner: [u8; HEADER_SIZE],
}

impl AdHeader {
    /// Creates a new Associated Data header wrapping destination address,
    /// flag configuration, nonce state, and the current epoch.
    pub fn new(dst_addr: &[u8; 6], flags: u8, nonce: &[u8; 5], epoch: u32) -> Self {
        let mut inner = [0_u8; HEADER_SIZE];
        inner[0..6].copy_from_slice(dst_addr);
        inner[6] = flags;
        inner[7..12].copy_from_slice(nonce);
        inner[12..].copy_from_slice(&epoch.to_be_bytes());
        Self { inner }
    }

    /// Serializes the size of the Associated Data header into a 2-byte big-endian format.
    fn u16_be_len(&self) -> [u8; 2] {
        (self.inner.len() as u16).to_be_bytes()
    }
}

impl IntoIterator for AdHeader {
    type Item = u8;
    type IntoIter = core::array::IntoIter<u8, HEADER_SIZE>;
    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl Deref for AdHeader {
    type Target = [u8; HEADER_SIZE];
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// The primary AES-CCM engine context carrying encryption keys, active nonces, and the peripheral driver.
pub struct PeerChannel<E>
where
    E: Encrypt,
{
    peer_mac: MacAddr,
    host_mac: MacAddr,
    rx_nonce: Nonce,
    tx_nonce: Nonce,
    is_peer_synced: bool,
    key_manager: KeyManager,
    aes: E,
}
impl<E> PeerChannel<E>
where
    E: Encrypt,
{
    /// Creates a new AES-CCM peripheral engine using a key and an hardware peripheral implementation.
    pub fn new(aes: E, root_key: [u8; 32], host_mac: MacAddr, peer_mac: MacAddr) -> Self {
        PeerChannel {
            peer_mac,
            host_mac,
            rx_nonce: Nonce { counter: 0 },
            tx_nonce: Nonce { counter: 0 },
            is_peer_synced: false,
            key_manager: KeyManager::new(root_key, 1), // Will be pulled from flash in the future to survive reboots but starts at 1
            aes,
        }
    }
    /// Encrypts and serializes a packet for transmission to the peer.
    ///
    /// Advances the internal TX nonce for each call. If the nonce space for the
    /// current epoch is exhausted, the epoch is automatically incremented and the
    /// nonce resets to `0` before the frame is built — the caller does not need
    /// to manage epoch rollover manually.
    ///
    /// The returned [`Frame`] contains the fully authenticated-encrypted packet
    /// (header + ciphertext payload + tag), ready to be sent over the air via
    /// [`Frame::bytes`].
    ///
    /// # Errors
    ///
    /// - [`Error::EpochExhaustion`] — the TX nonce space was exhausted *and* the
    ///   epoch counter is already at `u32::MAX`, so it cannot be incremented further.
    ///   Recovering requires re-flashing a new root key.
    /// - [`Error::PostcardError`] — the payload failed to serialize.
    /// - [`Error::LengthPrefixOverflow`] — the serialized payload exceeds `u16::MAX` bytes.
    /// - [`Error::BufferOverflow`] — the frame's fixed-size buffer (`T::FrameBuf`)
    ///   was too small to hold the header, payload, or tag.
    /// - [`Error::AESCounterOverflow`] — the payload required more than `u32::MAX`
    ///   AES-CTR blocks (payload larger than ~64 GiB — should never occur in practice).
    pub fn encrypt<T>(&mut self, packet_data: &PacketData<T>) -> Result<Frame<T>, Error>
    where
        T: Payload,
    {
        let raw_nonce = match self.tx_nonce.inc() {
            Ok(nonce) => nonce,
            Err(_) => {
                if self.key_manager.current_epoch() == u32::MAX {
                    return Err(Error::EpochExhaustion);
                }
                self.inc_epoch();
                [0u8; 5]
            }
        };
        let mut frame = Frame::new(
            *self.peer_mac,
            packet_data.flags,
            raw_nonce,
            self.key_manager.current_epoch().to_be_bytes(),
        )?;

        let mut payload = postcard::to_slice(&packet_data.payload, frame.payload_mut_slice())
            .map_err(|_| Error::PostcardError)?;

        let payload_len = payload.len();

        if payload_len as u16 > u16::MAX {
            return Err(LengthPrefixOverflow);
        }

        let mut block_buf = [0_u8; 16];

        let b_block = Self::write_b_block(
            &mut block_buf,
            *self.peer_mac,
            raw_nonce,
            payload_len as u16,
        );

        let ad_header = AdHeader::new(
            &*self.peer_mac,
            packet_data.flags,
            &raw_nonce,
            self.key_manager.current_epoch(),
        );

        let mut tag = self.gen_raw_tag(b_block, ad_header, payload, self.key_manager.current_key());

        let a_block = Self::write_a_block(&mut block_buf, *self.peer_mac, raw_nonce);

        self.xor_tag(&mut tag, a_block, self.key_manager.current_key());

        self.xor_payload(&mut payload, a_block, self.key_manager.current_key())?;

        frame.finalize(payload_len, tag)?;

        Ok(frame)
    }

    /// Authenticates, decrypts, and deserializes a received over-the-air frame.
    ///
    /// On success, this also advances internal state to track the peer: the RX
    /// nonce is updated, and if this is the first packet seen from the peer at
    /// the current epoch, [`PeerChannel::is_peer_synced`] becomes `true`.
    ///
    /// If the packet's epoch is ahead of ours, we silently "jump" our epoch
    /// forward to match the peer and reset our TX nonce — this lets the peer
    /// drive epoch rotation without an explicit handshake.
    ///
    /// If the packet is a resync frame (peer requesting we catch up after
    /// falling behind), this returns [`Error::SuccessfulResync`] rather than a
    /// deserialized payload — the epoch/nonce state has already been updated by
    /// this point, so the resync has effectively already happened by the time
    /// the caller sees this error.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidFormat`] — `bytes` is smaller than `HEADER_SIZE + TAG_SIZE`,
    ///   or the decrypted payload failed to deserialize.
    /// - [`Error::Duplicate`] — the packet's nonce is at or behind our current RX
    ///   nonce for the current epoch (replay). Not raised for cross-epoch packets.
    /// - [`Error::Corrupted`] — the recomputed authentication tag did not match
    ///   the one in the packet (tampering, or wrong key for this epoch).
    /// - [`Error::PeerDesynced`] — the packet's epoch has fallen outside our key
    ///   window (the peer is stale). The enclosed [`Frame<Empty>`] is a resync
    ///   frame the caller should transmit back to the peer.
    /// - [`Error::SuccessfulResync`] — the received packet was itself a resync
    ///   frame; our epoch/nonce state has now been caught up to the peer's.
    /// - [`Error::ReservedBitOverride`] — the packet's flags byte set one of the
    ///   two reserved high bits.
    pub fn decrypt<T>(&mut self, bytes: &mut [u8]) -> Result<PacketData<T>, Error>
    where
        T: Payload,
    {
        let parts = Parts::try_from(&*bytes)?;

        if parts.mac != *self.host_mac {
            return Err(Error::InvalidMac);
        }

        if parts.epoch == self.key_manager.current_epoch()
            && parts.nonce() <= self.rx_nonce.counter
            && self.is_peer_synced
        {
            return Err(Error::Duplicate);
        }

        let key_to_use = match self.key_manager.cached_key(parts.epoch) {
            Some(key) => key,
            // TODO: There will need to be a limit of checks / second to not get a DDOS
            None => KeyManager::derive_key(&self.key_manager.root_key, parts.epoch),
        };

        let mut payload = &mut bytes[PAYLOAD_OFFSET..PAYLOAD_OFFSET + parts.payload_len];

        let mut block_buf = [0_u8; 16];
        let a_block = Self::write_a_block(&mut block_buf, parts.mac, parts.raw_nonce);
        let mut tag = parts.tag;

        self.xor_tag(&mut tag, a_block, key_to_use);

        self.xor_payload(&mut payload, a_block, key_to_use)?;

        let b_block = Self::write_b_block(
            &mut block_buf,
            parts.mac,
            parts.raw_nonce,
            parts.payload_len as u16,
        );
        let ad_header = AdHeader::new(&parts.mac, parts.flags, &parts.raw_nonce, parts.epoch);

        let tag_cmp = self.gen_raw_tag(b_block, ad_header, payload, key_to_use);
        if !Self::is_tag_match_const_time(&tag, &tag_cmp) {
            return Err(Error::Authentication);
        }

        if self.key_manager.window.is_epoch_outdated(parts.epoch) {
            let resync = &PacketData::new_resync();
            let frame = self.encrypt(resync)?;
            return Err(Error::PeerDesynced(frame));
        }

        if parts.epoch > self.key_manager.current_epoch() {
            self.key_manager.jump_to_epoch(parts.epoch);
            self.tx_nonce.counter = 0;
            self.rx_nonce.counter = parts.nonce();
        } else if parts.epoch == self.key_manager.current_epoch() && self.is_peer_synced == false {
            self.rx_nonce.counter = parts.nonce();
            self.is_peer_synced = true;
        }
        if parts.flags == RESYNC_FLAG {
            return Err(Error::SuccessfulResync);
        }

        let serialized_payload =
            postcard::from_bytes::<T>(&payload).map_err(|_| Error::InvalidFormat)?;

        let packet_data = PacketData::new(parts.flags, serialized_payload)?;
        self.rx_nonce.set(parts.nonce());
        Ok(packet_data)
    }

    /// Populates and returns a formatted A-block (encryption initialization vector block).
    fn write_a_block<'b>(
        buf: &'b mut [u8; 16],
        mac: [u8; 6],
        raw_nonce: [u8; 5],
    ) -> &'b mut [u8; 16] {
        const A_NONCE_OFFSET: usize = 7;
        const A_MAC_OFFSET: usize = 1;
        buf.fill(0);

        buf[0] = 1; // payload length field size - 1: (2 - 1) = 1
        buf[A_MAC_OFFSET..A_MAC_OFFSET + 6].copy_from_slice(&mac);
        buf[A_NONCE_OFFSET..A_NONCE_OFFSET + 5].copy_from_slice(&raw_nonce);
        buf
    }

    /// Populates and returns a formatted B-block (authentication vector block).
    fn write_b_block<'b>(
        buf: &'b mut [u8; 16],
        mac: [u8; 6],
        raw_nonce: [u8; 5],
        payload_len: u16,
    ) -> &'b mut [u8; 16] {
        const B0_FLAGS: u8 = 0b0_1_111_001;
        buf[..6].copy_from_slice(&mac);
        buf[6] = B0_FLAGS;
        buf[7..12].copy_from_slice(&raw_nonce);
        buf[12..14].copy_from_slice(&(payload_len).to_be_bytes());
        buf[14] = 0;
        buf[15] = 0;
        buf
    }

    /// Generates the raw, unencrypted verification tag from input blocks, headers, and payload.
    fn gen_raw_tag(
        &mut self,
        b_block: &mut [u8; 16],
        ad_header: AdHeader,
        payload: &[u8],
        key_to_use: [u8; 16],
    ) -> [u8; TAG_SIZE] {
        let mut padded_header = [0_u8; HEADER_SIZE + 2];
        padded_header[0..2].copy_from_slice(&ad_header.u16_be_len());
        padded_header[2..].copy_from_slice(&*ad_header);

        let mut key_stream_buf = [0_u8; 16];
        self.aes.encrypt(&mut key_stream_buf, b_block, key_to_use);
        key_stream_buf
            .iter_mut()
            .zip(&padded_header)
            .for_each(|(b, h)| *b ^= h);
        self.aes.encrypt(b_block, &mut key_stream_buf, key_to_use);
        let (chunks, remainder) = payload.as_chunks::<16>();
        for chunk in chunks {
            b_block.iter_mut().zip(chunk).for_each(|(b, p)| *b ^= p);
            self.aes.encrypt(&mut key_stream_buf, b_block, key_to_use);
        }
        key_stream_buf
            .iter_mut()
            .zip(remainder)
            .for_each(|(b, r)| *b ^= r);
        self.aes.encrypt(b_block, &mut key_stream_buf, key_to_use);

        b_block[..TAG_SIZE].try_into().unwrap()
    }

    /// XOR encrypts or decrypts the 16-byte authentication tag using the first key stream block.
    fn xor_tag(&mut self, tag: &mut [u8; TAG_SIZE], a_block: &mut [u8; 16], key_to_use: [u8; 16]) {
        let mut key_stream_buf = [0_u8; 16];
        self.aes.encrypt(&mut key_stream_buf, a_block, key_to_use);
        for i in 0..TAG_SIZE {
            tag[i] ^= key_stream_buf[i];
        }
    }

    /// XORs the data payload with sequential keystream blocks to encrypt or decrypt in-place.
    ///
    /// # Errors
    ///
    /// Returns `Err(Error::AESCounterOverflow)` if the sequential block count overflows.
    fn xor_payload(
        &mut self,
        payload: &mut [u8],
        mut a_block: &mut [u8; 16],
        key_to_use: [u8; 16],
    ) -> Result<(), Error> {
        let mut key_stream_buf = [0_u8; 16];
        let mut counter = 0_u32;
        let (chunks, remainder) = payload.as_chunks_mut::<16>();
        for chunk in chunks {
            counter = counter.checked_add(1).ok_or(Error::AESCounterOverflow)?;
            [a_block[12], a_block[13], a_block[14], a_block[15]] = counter.to_be_bytes();

            self.aes
                .encrypt(&mut key_stream_buf, &mut a_block, key_to_use);
            chunk
                .iter_mut()
                .zip(key_stream_buf)
                .for_each(|(c, k)| *c ^= k);
        }
        counter = counter.checked_add(1).ok_or(Error::AESCounterOverflow)?;
        [a_block[12], a_block[13], a_block[14], a_block[15]] = counter.to_be_bytes();
        self.aes
            .encrypt(&mut key_stream_buf, &mut a_block, key_to_use);
        remainder
            .iter_mut()
            .zip(key_stream_buf)
            .for_each(|(r, a)| *r ^= a);
        Ok(())
    }

    /// Constant-time array comparison to mitigate timing side-channel attacks on authentication tags.
    fn is_tag_match_const_time(tag_a: &[u8; TAG_SIZE], tag_b: &[u8; TAG_SIZE]) -> bool {
        let mut acc = 0;

        for i in 0..TAG_SIZE {
            acc |= tag_a[i] ^ tag_b[i];
        }
        acc == 0
    }

    fn inc_epoch(&mut self) {
        self.key_manager.inc_epoch();
        self.tx_nonce.counter = 0;
        self.is_peer_synced = false;
    }
}
/// Testing API
#[cfg(feature = "test-util")]
impl MacAddr {
    pub fn peer() -> Self {
        Self { inner: [0xEE; 6] }
    }
}
#[cfg(feature = "test-util")]
impl<E> PeerChannel<E>
where
    E: Encrypt,
{
    pub fn set_raw_tx_nonce(&mut self, raw_nonce: [u8; 5]) {
        let nonce = u64::from_be_bytes([
            0,
            0,
            0,
            raw_nonce[0],
            raw_nonce[1],
            raw_nonce[2],
            raw_nonce[3],
            raw_nonce[4],
        ]);
        self.tx_nonce = Nonce { counter: nonce };
    }
    pub fn set_tx_nonce(&mut self, nonce: u64) {
        self.tx_nonce = Nonce { counter: nonce };
    }

    pub fn set_rx_nonce(&mut self, nonce: u64) {
        self.rx_nonce = Nonce { counter: nonce };
    }

    pub fn rx_nounce(&self) -> u64 {
        self.rx_nonce.counter
    }
    pub fn tx_nounce(&self) -> u64 {
        self.tx_nonce.counter
    }

    pub fn key(&self) -> [u8; 16] {
        self.key_manager.current_key()
    }

    pub fn key_manager(&self) -> &KeyManager {
        &self.key_manager
    }
    pub fn is_peer_synced(&self) -> bool {
        self.is_peer_synced
    }

    pub fn jump_to_epoch(&mut self, epoch: u32) {
        self.key_manager.jump_to_epoch(epoch);
    }

    pub fn inc_curr_epoch(&mut self) {
        self.inc_epoch();
    }

    pub fn epoch(&self) -> u32 {
        self.key_manager.epoch()
    }
}
#[cfg(feature = "test-util")]
impl KeyManager {
    pub fn epoch(&self) -> u32 {
        self.current_epoch()
    }
}
#[cfg(feature = "test-util")]
impl<T: Payload> Frame<T> {
    pub fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.inner.as_mut()[..self.len]
    }
}
// IN DEV =====================================================

const SALT: [u8; 32] = *b"mcu_comms_hkdf_salt_v1_padded32b";
use hkdf::Hkdf;
use sha2::Sha256;
// Will be private In the future
pub struct KeyManager {
    root_key: [u8; 32],
    window: KeyWindow,
}
impl KeyManager {
    fn new(root_key: [u8; 32], epoch: u32) -> Self {
        Self {
            root_key,
            window: Self::derive_keys(root_key, epoch),
        }
    }
    fn jump_to_epoch(&mut self, epoch: u32) {
        if epoch <= self.current_epoch() {
            return;
        }
        self.window = Self::derive_keys(self.root_key, epoch)
    }
    fn derive_keys(root_key: [u8; 32], epoch: u32) -> KeyWindow {
        let hks = Hkdf::<Sha256>::new(Some(&SALT), &root_key);
        let mut keys = [[0u8; 16]; 3];
        for (i, e) in [epoch.wrapping_sub(1), epoch, epoch.wrapping_add(1)]
            .iter()
            .enumerate()
        {
            let mut info = *b"mcu_comms_epoch_\0\0\0\0_1";
            info[16..20].copy_from_slice(&e.to_be_bytes());
            hks.expand(&info, &mut keys[i]).expect("32 <= 255*32");
        }
        KeyWindow {
            prev: keys[0],
            curr: keys[1],
            next: keys[2],
            epoch,
        }
    }

    fn inc_epoch(&mut self) {
        /* TODO: Older cached epochs will need to keep track of the rx nonce not to get replayed
         * if the epoch is too old and not cached, drop the packet and send a rekey packet
         */
        let new_epoch = self.window.epoch.wrapping_add(1);
        self.window.epoch = new_epoch;
        self.window.prev = self.window.curr;
        self.window.curr = self.window.next;
        self.window.next = Self::derive_key(&self.root_key, new_epoch.wrapping_add(1));
    }
    fn derive_key(root_key: &[u8; 32], epoch: u32) -> [u8; 16] {
        let hks = Hkdf::<Sha256>::new(Some(&SALT), root_key);
        let mut key = [0u8; 16];
        let mut info = *b"mcu_comms_epoch_\0\0\0\0_1";
        info[16..20].copy_from_slice(&epoch.to_be_bytes());
        hks.expand(&info, &mut key).expect("32 <= 255*32");
        key
    }
    fn cached_key(&self, epoch: u32) -> Option<[u8; 16]> {
        self.window.cached_key(epoch)
    }
    fn current_key(&self) -> [u8; 16] {
        self.window.curr
    }
    fn current_epoch(&self) -> u32 {
        self.window.epoch
    }
}
/// A sliding window of three consecutive epoch keys (`epoch - 1`, `epoch`,
/// `epoch + 1`), allowing decryption to succeed even if a peer's packet
/// arrives slightly out of sync with our current epoch.
struct KeyWindow {
    prev: [u8; 16],
    curr: [u8; 16],
    next: [u8; 16],
    epoch: u32,
}
impl KeyWindow {
    fn cached_key(&self, epoch: u32) -> Option<[u8; 16]> {
        if epoch == self.epoch.wrapping_sub(1) {
            Some(self.prev)
        } else if epoch == self.epoch {
            Some(self.curr)
        } else if epoch == self.epoch.wrapping_add(1) {
            Some(self.next)
        } else {
            None
        }
    }
    /// Returns `true` if `epoch` is older than the window can decode — i.e. more
    /// than one epoch behind [`KeyWindow::epoch`] (the current epoch).
    ///
    /// Note this only checks the *lower* bound; an epoch that is far in the
    /// future is instead handled by [`KeyManager::jump_to_epoch`] in
    /// [`PeerChannel::decrypt`], not by this function.
    fn is_epoch_outdated(&self, epoch: u32) -> bool {
        epoch < self.epoch.wrapping_sub(1)
    }
}
