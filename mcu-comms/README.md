mcu-comms

A lightweight, no_std-compatible communication framing and packet encryption utility library designed for resource-constrained microcontrollers.

It provides secure AES-CCM (Counter with CBC-MAC) authenticated encryption, sliding window/nonce replay protection, and command serialization utilizing zero-allocation containers.

Features

no_std First: Zero dynamic allocations.

Hardware Acceleration Friendly: Defines a simple, customizable Encrypt hardware abstraction layer (HAL) trait to hook directly into your MCU's AES hardware peripheral.

Replay Protection: Built-in 5-byte rising counter nonce verification to completely prevent packet replay attacks.

Compact Over-the-Air Frame: Efficient packing optimized.
Over-The-Air Frame Layout

                        | OVER-THE-AIR FRAME |

+--------------------------+--------------------+-----------------------+
| dst (6 Bytes) | flags (1 Byte) | ctr (5 Bytes) | -> HEADER (12 Bytes)
+--------------------------+--------------------+-----------------------+
| Ciphertext (N Bytes) | -> PAYLOAD
+-----------------------------------------------------------------------+
| Tag (16 Bytes) | -> MAC/TAG (16 Bytes)
+-----------------------------------------------------------------------+

Installation

Add this to your Cargo.toml dependencies:

[dependencies]
mcu-comms = `latest version`

check the /examples folder for examples

License

Licensed under the Apache License, Version 2.0 (LICENSE or http://www.apache.org/licenses/LICENSE-2.0).
