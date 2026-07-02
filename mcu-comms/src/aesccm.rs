//! # AES-CCM Embedded Packet Cryptography Crate
//!
//! This crate provides a lightweight, `no_std`-compatible implementation of AES-CCM
//! (Counter with CBC-MAC) tailored for resource-constrained microcontrollers.
//! It handles packet serialization, MAC address validation, nonce tracking,
//! and hardware-accelerated encrypt/decrypt operations through a custom HAL trait.
use core::ops::Deref;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

// Package-wide global constants to prevent repetition
const HEADER_SIZE: usize = 12;
const MAX_PAYLOAD_SIZE: usize = 64;
const TAG_SIZE: usize = 16;
const FLAGS_IDX: usize = 6;
const NONCE_OFFSET: usize = 7;
const MAC_OFFSET: usize = 0;
const PAYLOAD_OFFSET: usize = HEADER_SIZE;

/// Errors that can occur during packet construction, serialization, or decryption.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Cryptographic verification failed (tampered payload or invalid key).
    Authentication,
    /// The packet does not match the expected structure or is too small.
    InvalidFormat,
    /// Postcard serialization exceeded the internal packet buffers.
    BufferOverflow,
    /// The 5-byte AES counter exceeded its maximum value ($2^{40} - 1$).
    AESCounterOverflow,
    /// Received a packet with a duplicate or older nonce (replay attack protection).
    Duplicate,
    /// General payload corruption.
    Corrupted,
    /// If the flag used overrides some reserved bytes
    ReservedBytesOverride,
    ///
    Postcard(postcard::Error),
}

/// A HAL trait to allow different MCUs with AES hardware acceleration to hook onto the AES-CCM implementation.
///
/// # Example
///
/// Example usage with the `esp_hal` crate (compatible with `~1.1.0`):
///
/// ```rust,ignore
/// use aesccm::Encrypt;
///
///pub struct AesHal(esp_hall::aes::Aes<'static>);
///impl Encrypt for AesHal {
///    fn encrypt(&mut self, key_stream_buf: &mut [u8; 16], a_block: &mut [u8; 16], key: [u8; 16]) {
///        key_stream_buf.copy_from_slice(a_block);
///        self.0.encrypt(key_stream_buf, key);
///    }
///}
/// ```
pub trait Encrypt {
    /// Encrypts the given 16-byte buffer with the given key using the MCU's AES hardware peripheral.
    fn encrypt(&mut self, key_stream_buf: &mut [u8; 16], block: &mut [u8; 16], key: [u8; 16]);
}

/// A stack-allocated serialized packet buffer optimized for `no_std` environments.
#[derive(Debug)]
pub struct Frame {
    inner: [u8; HEADER_SIZE + 4 + MAX_PAYLOAD_SIZE + TAG_SIZE],
    len: usize,
}
impl Default for Frame {
    fn default() -> Self {
        Self {
            inner: [0_u8; HEADER_SIZE + 4 + MAX_PAYLOAD_SIZE + TAG_SIZE],
            len: 0,
        }
    }
}
impl Frame {
    fn new(mac: [u8; 6], flags: u8, raw_nonce: [u8; 5]) -> Result<Self, Error> {
        let mut frame = Self::default();
        frame.extend_from_slice(&mac)?;
        frame.push(flags)?;
        frame.extend_from_slice(&raw_nonce)?;
        Ok(frame)
    }

    fn payload_mut_slice(&mut self) -> &mut [u8] {
        &mut self.inner[HEADER_SIZE..]
    }
    fn finalize(&mut self, payload_len: usize, tag: [u8; 16]) -> Result<(), Error> {
        self.len += payload_len;
        self.extend_from_slice(&tag)
    }
    pub fn bytes(&self) -> &[u8] {
        &self.inner[..self.len]
    }

    pub fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.inner[..self.len]
    }

    fn push(&mut self, byte: u8) -> Result<(), Error> {
        if self.len >= self.inner.len() {
            return Err(Error::BufferOverflow);
        }
        self.inner[self.len] = byte;
        self.len += 1;
        Ok(())
    }

    fn extend_from_slice(&mut self, iter: &[u8]) -> Result<(), Error> {
        if iter.len() + self.len > self.inner.len() {
            return Err(Error::BufferOverflow);
        }
        self.inner[self.len..self.len + iter.len()].copy_from_slice(iter);
        self.len += iter.len();
        Ok(())
    }
}

/// Represents the raw data fields to be packaged securely into an encrypted frame.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct PacketData<T>
where
    T: Serialize + DeserializeOwned,
{
    /// Destination MAC address.
    pub dst: MacAddr,
    /// Protocol or routing control flags.
    pub flags: u8,
    /// payload to be serialized and encrypted.
    pub payload: T,
}

impl<T> PacketData<T>
where
    T: Serialize + DeserializeOwned,
{
    /// Instantiates a new packet data structure ready for processing.
    /// The first 2 dominant bytes are reserved for key rotation and WILL be overritten
    pub fn new(dst: MacAddr, mut flags: u8, payload: T) -> Self {
        flags &= 0b_00_111111;
        Self {
            dst,
            flags,
            payload,
        }
    }
}

/// A standard 6-byte media access control (MAC) address.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
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
    /// Returns `Err(PacketError::AESCounterOverflow)` if the counter overflows
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

/// A zero-copy view into a raw packet buffer.
///
/// `PacketView` does not own the underlying data. It simply interprets a
/// byte slice according to the expected packet layout.
///
/// This is useful in embedded or `no_std` environments where copying or
/// allocating packets is undesirable.
///
/// # Packet layout
///
/// The expected layout of the underlying buffer is assumed to be:
///
/// ```text
/// +----------------+----------------+----------------+
/// | MAC (6 bytes)  | FLAGS (1 byte) | NONCE (5 bytes) | ...
/// +----------------+----------------+----------------+
/// ```
///
/// Offsets are defined by constants such as `MAC_OFFSET`, `FLAGS_IDX`,
/// and `NONCE_OFFSET`.
///
/// # Safety / Panics
///
/// This type uses `unwrap()` internally when extracting fixed-size fields.
/// Therefore:
///
/// - The input slice **must be large enough**
/// - Invalid or truncated buffers will cause a panic
///
/// In embedded contexts, ensure packet validation happens before constructing
/// a `PacketView`.
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
    /// Returns `PacketError` if the buffer is too small or malformed.
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
        if bytes.len() <= HEADER_SIZE + TAG_SIZE {
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
        if bytes.len() <= HEADER_SIZE + TAG_SIZE {
            return Err(Error::InvalidFormat);
        }
        let mac: [u8; 6] = bytes[MAC_OFFSET..MAC_OFFSET + 6].try_into().unwrap();
        let raw_nonce: [u8; 5] = bytes[NONCE_OFFSET..NONCE_OFFSET + 5].try_into().unwrap();
        let payload_len = bytes.len() - TAG_SIZE - PAYLOAD_OFFSET;

        let tag: [u8; TAG_SIZE] = bytes[bytes.len() - TAG_SIZE..].try_into().unwrap();

        let flags = bytes[FLAGS_IDX];
        Ok(Self {
            mac,
            flags,
            raw_nonce,
            payload_len,
            tag,
        })
    }
}

/// The Associated Data (AD) header layout utilized during authenticating AES-CCM blocks.
pub struct AdHeader {
    inner: [u8; 12],
}

impl AdHeader {
    /// Creates a new Associated Data header wrapping destination address, flag configuration, and nonce state.
    pub fn new(dst_addr: &[u8; 6], flags: u8, nonce: &[u8; 5]) -> Self {
        let mut inner = [0_u8; 12];
        inner[0..6].copy_from_slice(dst_addr);
        inner[6] = flags;
        inner[7..].copy_from_slice(nonce);
        Self { inner }
    }

    /// Serializes the size of the Associated Data header into a 2-byte big-endian format.
    fn u16_be_len(&self) -> [u8; 2] {
        (self.inner.len() as u16).to_be_bytes()
    }
}

impl From<[u8; 16]> for AdHeader {
    fn from(value: [u8; 16]) -> Self {
        Self {
            inner: value[2..14].try_into().unwrap(),
        }
    }
}

impl IntoIterator for AdHeader {
    type Item = u8;
    type IntoIter = core::array::IntoIter<u8, 12>;
    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl Deref for AdHeader {
    type Target = [u8; 12];
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// The primary AES-CCM engine context carrying encryption keys, active nonces, and the peripheral driver.
pub struct AESCCM<E>
where
    E: Encrypt,
{
    rx_nonce: Nonce,
    tx_nonce: Nonce,
    key: [u8; 16],
    aes: E,
}
impl<E> AESCCM<E>
where
    E: Encrypt,
{
    /// Creates a new AES-CCM peripheral engine using a key and an hardware peripheral implementation.
    pub fn new(aes: E, key: [u8; 16]) -> Self {
        AESCCM {
            rx_nonce: Nonce { counter: 0 },
            tx_nonce: Nonce { counter: 0 },
            key,
            aes,
        }
    }

    /// Encrypts packet data into a lightweight, authenticated over-the-air AES-CCM format.
    ///
    /// ```text
    /// +-----------------------------------------------------------------------+
    /// |                        OVER-THE-AIR FRAME                             |
    /// +--------------------------+--------------------+-----------------------+
    /// |       dst (6 Bytes)      |   flags (1 Byte)   |      ctr (5 Bytes)    | -> HEADER (12 Bytes)
    /// +--------------------------+--------------------+-----------------------+
    /// | Ciphertext (N Bytes)                                                  | -> PAYLOAD
    /// +-----------------------------------------------------------------------+
    /// | Tag (16 Bytes)                                                         | -> MAC/TAG
    /// +-----------------------------------------------------------------------+
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `Err(PacketError::BufferOverflow)` if serialization fails or
    /// `Err(PacketError::AESCounterOverflow)` if the nonce limits are exceeded.
    pub fn encrypt<T>(&mut self, packet_data: &PacketData<T>) -> Result<Frame, Error>
    where
        T: Serialize + DeserializeOwned,
    {
        let mac = *packet_data.dst;
        let raw_nonce = self.tx_nonce.inc()?;
        let mut frame = Frame::new(mac, packet_data.flags, raw_nonce)?;

        let mut payload = postcard::to_slice(&packet_data.payload, frame.payload_mut_slice())
            .map_err(|e| Error::Postcard(e))?;

        let payload_len = payload.len();

        let mut block_buf = [0_u8; 16];

        let b_block = Self::write_b_block(&mut block_buf, mac, raw_nonce, payload_len);

        let ad_header = AdHeader::new(&mac, packet_data.flags, &raw_nonce);

        let mut tag = self.gen_raw_tag(b_block, ad_header, payload);

        let a_block = Self::write_a_block(&mut block_buf, mac, raw_nonce);

        self.xor_tag(&mut tag, a_block);

        self.xor_payload(&mut payload, a_block)?;

        frame.finalize(payload_len, tag)?;

        Ok(frame)
    }

    /// Decrypts and authenticates an incoming packet from a mutable slice buffer in-place.
    ///
    /// # Errors
    ///
    /// Returns:
    /// - `PacketError::InvalidFormat` if parsing fails.
    /// - `PacketError::Duplicate` if a potential replay attack is intercepted.
    /// - `PacketError::Corrupted` if the tag verification fails.
    pub fn decrypt<T>(&mut self, bytes: &mut [u8]) -> Result<PacketData<T>, Error>
    where
        T: Serialize + DeserializeOwned,
    {
        let parts = Parts::try_from(&*bytes)?;
        if parts.nonce() <= self.rx_nonce.counter {
            return Err(Error::Duplicate);
        }

        let mut payload = &mut bytes[PAYLOAD_OFFSET..PAYLOAD_OFFSET + parts.payload_len];

        let mut block_buf = [0_u8; 16];
        let a_block = Self::write_a_block(&mut block_buf, parts.mac, parts.raw_nonce);
        let mut tag = parts.tag;

        self.xor_tag(&mut tag, a_block);

        self.xor_payload(&mut payload, a_block)?;

        let b_block = Self::write_b_block(
            &mut block_buf,
            parts.mac,
            parts.raw_nonce,
            parts.payload_len,
        );
        let ad_header = AdHeader::new(&parts.mac, parts.flags, &parts.raw_nonce);

        let tag_cmp = self.gen_raw_tag(b_block, ad_header, payload);
        if !Self::is_tag_match_const_time(&tag, &tag_cmp) {
            return Err(Error::Corrupted);
        }

        let serialized_payload =
            postcard::from_bytes::<T>(&payload).map_err(|_| Error::InvalidFormat)?;
        let packet_data = PacketData::new(parts.mac.into(), parts.flags, serialized_payload);
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
        buf[0] = 4;
        buf[A_MAC_OFFSET..A_MAC_OFFSET + 6].copy_from_slice(&mac);
        buf[A_NONCE_OFFSET..A_NONCE_OFFSET + 5].copy_from_slice(&raw_nonce);
        buf
    }

    /// Populates and returns a formatted B-block (authentication vector block).
    fn write_b_block<'b>(
        buf: &'b mut [u8; 16],
        mac: [u8; 6],
        raw_nonce: [u8; 5],
        payload_len: usize,
    ) -> &'b mut [u8; 16] {
        const B0_FLAGS: u8 = 0b0_1_111_011;
        buf[..6].copy_from_slice(&mac);
        buf[6] = B0_FLAGS;
        buf[7..=11].copy_from_slice(&raw_nonce);
        buf[12..].copy_from_slice(&(payload_len as u32).to_be_bytes());
        buf
    }

    /// Generates the raw, unencrypted verification tag from input blocks, headers, and payload.
    fn gen_raw_tag(
        &mut self,
        b_block: &mut [u8; 16],
        ad_header: AdHeader,
        payload: &[u8],
    ) -> [u8; TAG_SIZE] {
        let mut padded_header = [0_u8; 16];
        padded_header[0..2].copy_from_slice(&ad_header.u16_be_len());
        padded_header[2..14].copy_from_slice(&*ad_header);

        let mut key_stream_buf = [0_u8; 16];
        self.aes.encrypt(&mut key_stream_buf, b_block, self.key);
        key_stream_buf
            .iter_mut()
            .zip(&padded_header)
            .for_each(|(b, h)| *b ^= h);
        self.aes.encrypt(b_block, &mut key_stream_buf, self.key);
        let (chunks, remainder) = payload.as_chunks::<16>();
        for chunk in chunks {
            b_block.iter_mut().zip(chunk).for_each(|(b, p)| *b ^= p);
            self.aes.encrypt(&mut key_stream_buf, b_block, self.key);
        }
        key_stream_buf
            .iter_mut()
            .zip(remainder)
            .for_each(|(b, r)| *b ^= r);
        self.aes.encrypt(b_block, &mut key_stream_buf, self.key);

        b_block[..TAG_SIZE].try_into().unwrap()
    }

    /// XOR encrypts or decrypts the 16-byte authentication tag using the first key stream block.
    fn xor_tag(&mut self, tag: &mut [u8; TAG_SIZE], a_block: &mut [u8; 16]) {
        let mut key_stream_buf = [0_u8; 16];
        self.aes.encrypt(&mut key_stream_buf, a_block, self.key);
        for i in 0..TAG_SIZE {
            tag[i] ^= key_stream_buf[i];
        }
    }

    /// XORs the data payload with sequential keystream blocks to encrypt or decrypt in-place.
    ///
    /// # Errors
    ///
    /// Returns `Err(PacketError::AESCounterOverflow)` if the sequential block count overflows.
    fn xor_payload(&mut self, payload: &mut [u8], mut a_block: &mut [u8; 16]) -> Result<(), Error> {
        let mut key_stream_buf = [0_u8; 16];
        let mut counter = 0_u32;
        let (chunks, remainder) = payload.as_chunks_mut::<16>();
        for chunk in chunks {
            counter = counter.checked_add(1).ok_or(Error::AESCounterOverflow)?;
            [a_block[12], a_block[13], a_block[14], a_block[15]] = counter.to_be_bytes();

            self.aes
                .encrypt(&mut key_stream_buf, &mut a_block, self.key);
            chunk
                .iter_mut()
                .zip(key_stream_buf)
                .for_each(|(c, k)| *c ^= k);
        }
        counter = counter.checked_add(1).ok_or(Error::AESCounterOverflow)?;
        [a_block[12], a_block[13], a_block[14], a_block[15]] = counter.to_be_bytes();
        self.aes
            .encrypt(&mut key_stream_buf, &mut a_block, self.key);
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
}
