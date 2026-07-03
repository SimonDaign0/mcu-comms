# mcu-comms

This repository contains the `mcu-comms` ecosystem, a lightweight, `no_std` communication library for resource-constrained microcontrollers.

## Repository layout

### `/mcu-comms`

The main library crate. It provides communication framing, authenticated packet encryption, serialization support, and utilities for defining portable payload types.

See the crate's own `README.md` for detailed documentation.

### `/mcu-comms-macros`

An internal procedural macro crate used by `mcu-comms`. It provides the `#[payload]` attribute macro for defining payload types with automatic serialization and compile-time size calculations.

This crate is an implementation detail and is not intended to be used directly.

### `/examples`

Example projects demonstrating how to use `mcu-comms`.

## Installation

Add `mcu-comms` to your `Cargo.toml`:

```toml
[dependencies]
mcu-comms = "<latest version>"
```
