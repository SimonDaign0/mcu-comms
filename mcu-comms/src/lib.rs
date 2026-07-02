#![no_std]
pub mod aesccm;
pub mod payload_size;
pub use crate::payload_size::{MaxPayloadSize, MaxSize, Payload};
pub use aesccm::{AESCCM, Encrypt, MacAddr, PacketData, PacketView};
pub use mcu_comms_macros::payload;
pub use serde;
pub mod prelude {
    pub use crate::aesccm::{AESCCM, Encrypt, MacAddr, PacketData, PacketView};
    pub use crate::payload_size::prelude::*;
    pub use mcu_comms_macros::payload;
    pub use serde;
}
