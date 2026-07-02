mcu-comms

A lightweight, no_std-compatible communication framing and packet encryption utility library designed for resource-constrained microcontrollers.

It provides secure AES-CCM (Counter with CBC-MAC) authenticated encryption, sliding window/nonce replay protection, and command serialization utilizing zero-allocation containers.

Features

no_std First: Zero dynamic allocations, leveraging heapless::Vec for static safety.

Hardware Acceleration Friendly: Defines a simple, customizable Encrypt hardware abstraction layer (HAL) trait to hook directly into your MCU's AES hardware peripheral.

Replay Protection: Built-in 5-byte rising counter nonce verification to completely prevent packet replay attacks.

Compact Over-the-Air Frame: Efficient packing optimized.
Over-The-Air Frame Layout

+-----------------------------------------------------------------------+
| OVER-THE-AIR FRAME |
+--------------------------+--------------------+-----------------------+
| dst (6 Bytes) | flags (1 Byte) | ctr (5 Bytes) | -> HEADER (12 Bytes)
+--------------------------+--------------------+-----------------------+
| Ciphertext (N Bytes) | -> PAYLOAD (Max 64 Bytes)
+-----------------------------------------------------------------------+
| Tag (8 Bytes) | -> MAC/TAG (8 Bytes)
+-----------------------------------------------------------------------+

Installation

Add this to your Cargo.toml dependencies:

[dependencies]
mcu-comms = "0.1.0"
serde = { version = "1.0", default-features = false, features = ["derive"] }
postcard = { version = "1.1", default-features = false }
heapless = "0.9"

Usage Example

1. Implement the Encrypt trait for your hardware

Below is an example of implementing the trait using a hardware peripheral (such as esp-hal):

use mcu_comms::Encrypt;

struct MyHardwareAes;

impl Encrypt for MyHardwareAes {
fn encrypt(&mut self, key_stream_buf: &mut [u8; 16], a_block: &mut [u8; 16], key: [u8; 16]) {
// Copy the initialization vector/block
key_stream_buf.copy_from_slice(a_block);

        // Execute hardware-based AES-128 encryption in-place on key_stream_buf
        // aes_peripheral.encrypt_block(key_stream_buf, key);
    }

}

2. Encrypt and Decrypt Packets

use mcu_comms::{AESCCM, PacketData, MacAddr, Command, Component};

fn main() {
let my_aes_driver = MyHardwareAes;
let key = [0u8; 16]; // Your 128-bit secret key

    // Initialize the AES-CCM Engine
    let mut ccm = AESCCM::new(my_aes_driver, key);

    // Create a command payload to send
    let packet = PacketData::new(
        MacAddr::new(0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC),
        0x01, // Flags
        Command::Toggle(Component::Led(2)),
    );

    // Encrypt the packet
    let encrypted_packet = ccm.encrypt(packet).expect("Encryption failed");
    let mut ota_bytes = encrypted_packet.inner;

    // ... transmit ota_bytes over the air ...

    // Decrypt the packet on the receiving node
    let decrypted_data = ccm.decrypt(&mut ota_bytes).expect("Decryption failed");
    println!("Received Command: {:?}", decrypted_data.cmd);

}

License

Licensed under the Apache License, Version 2.0 (LICENSE or http://www.apache.org/licenses/LICENSE-2.0).
