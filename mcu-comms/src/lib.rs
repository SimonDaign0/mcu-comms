#![no_std]
pub mod payload_size;
pub mod peer_channel;
pub use crate::payload_size::{MaxPayloadSize, MaxSize, Payload};
pub use mcu_comms_macros::payload;
pub use peer_channel::{Encrypt, Frame, MacAddr, PacketData, PacketView, PeerChannel};
pub use serde;
pub mod prelude {
    pub use crate::payload_size::prelude::*;
    pub use crate::peer_channel::{
        Encrypt, Error, Frame, MacAddr, PacketData, PacketView, PeerChannel,
    };
    pub use mcu_comms_macros::payload;
    pub use serde;
}
