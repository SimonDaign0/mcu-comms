#![no_std]
pub mod aesccm;
pub use aesccm::{Encrypt, MacAddr, PacketData, PacketView, AESCCM};
pub use serde::{Deserialize, Serialize};

pub mod prelude {
    pub use crate::aesccm::{Encrypt, MacAddr, PacketData, PacketView, AESCCM};
}
