pub mod prelude {
    pub use crate::payload_size::{MaxPayloadSize, MaxSize, Payload};
}

pub trait MaxPayloadSize: MaxSize {
    const FRAME_SIZE: usize;
    type FrameBuf: AsRef<[u8]> + AsMut<[u8]>;
    fn new_buf() -> Self::FrameBuf;
}

use serde::{Serialize, de::DeserializeOwned};
pub trait Payload: Serialize + DeserializeOwned + MaxPayloadSize {}

#[cfg(target_pointer_width = "16")]
impl MaxSize for isize {
    const MAX_SIZE: usize = 3;
}
#[cfg(target_pointer_width = "16")]
impl MaxSize for usize {
    const MAX_SIZE: usize = 3;
}
#[cfg(target_pointer_width = "32")]
impl MaxSize for isize {
    const MAX_SIZE: usize = 5;
}
#[cfg(target_pointer_width = "32")]
impl MaxSize for usize {
    const MAX_SIZE: usize = 5;
}
#[cfg(target_pointer_width = "64")]
impl MaxSize for isize {
    const MAX_SIZE: usize = 10;
}
#[cfg(target_pointer_width = "64")]
impl MaxSize for usize {
    const MAX_SIZE: usize = 10;
}

pub trait MaxSize {
    const MAX_SIZE: usize;
}
impl MaxSize for bool {
    const MAX_SIZE: usize = 1;
}
impl MaxSize for u8 {
    const MAX_SIZE: usize = 1;
}
impl MaxSize for u16 {
    const MAX_SIZE: usize = 3;
}
impl MaxSize for u32 {
    const MAX_SIZE: usize = 5;
}
impl MaxSize for u64 {
    const MAX_SIZE: usize = 10;
}
impl MaxSize for u128 {
    const MAX_SIZE: usize = 19;
}
impl MaxSize for i8 {
    const MAX_SIZE: usize = u8::MAX_SIZE;
}
impl MaxSize for i16 {
    const MAX_SIZE: usize = u16::MAX_SIZE;
}
impl MaxSize for i32 {
    const MAX_SIZE: usize = u32::MAX_SIZE;
}
impl MaxSize for i64 {
    const MAX_SIZE: usize = u64::MAX_SIZE;
}
impl MaxSize for i128 {
    const MAX_SIZE: usize = u128::MAX_SIZE;
}
impl MaxSize for f32 {
    const MAX_SIZE: usize = 4;
}
impl MaxSize for f64 {
    const MAX_SIZE: usize = 8;
}

impl MaxSize for char {
    const MAX_SIZE: usize = 5;
}
impl MaxSize for () {
    const MAX_SIZE: usize = 0;
}

impl<T: MaxSize, const N: usize> MaxSize for [T; N] {
    const MAX_SIZE: usize = T::MAX_SIZE * N;
}

impl<T: MaxSize, E: MaxSize> MaxSize for Result<T, E> {
    const MAX_SIZE: usize = 1 + T::MAX_SIZE + E::MAX_SIZE;
}

macro_rules! impl_max_size_tuple {
    ($($t:ident),+) => {
        impl<$($t: MaxSize),+> MaxSize for ($($t,)+) {
            const MAX_SIZE: usize = 0 $(+ $t::MAX_SIZE)+;
        }
    };
}

impl_max_size_tuple!(A);
impl_max_size_tuple!(A, B);
impl_max_size_tuple!(A, B, C);
impl_max_size_tuple!(A, B, C, D);
