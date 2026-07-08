#![cfg_attr(not(test), no_std)]
mod common;
use common::prelude::*;

#[cfg(test)]
const RESYNC_FLAG: u8 = 0b1000_0000;
const RESERVED_FLAG: u8 = 0b0100_0000;
#[test]
fn bit_override() {
    assert!(PacketData::new(RESYNC_FLAG, Sensor::default()).is_err());

    assert!(PacketData::new(RESERVED_FLAG, Sensor::default()).is_err());

    assert!(PacketData::new(RESERVED_FLAG | RESYNC_FLAG, Sensor::default()).is_err());

    assert!(PacketData::new(REG_FLAGS, Sensor::default()).is_ok());
}
