# mcu-comms-macros

An internal procedural macro library for `mcu-comms` that provides the `#[payload]` macro.

This macro automatically generates `Payload` trait implementations for your types. Crucially, it calculates the maximum possible serialized size of your type at compile time, generating an optimal static buffer size and completely eliminating the need to manually define a `MAX_PAYLOAD_SIZE`.

`usize`/`isize` are disallowed in payload structs to support cross-compilation.

## Usage

Do not depend on this crate directly. Instead, use the re-exports provided in the main [mcu-comms](https://crates.io/crates/mcu-comms) crate.
