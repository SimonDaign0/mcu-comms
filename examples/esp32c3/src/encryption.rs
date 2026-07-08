#![no_std]
#![no_main]

use esp_backtrace as _;
use esp_println as _;
esp_bootloader_esp_idf::esp_app_desc!();
use esp_hal::{aes::Aes, clock::CpuClock};

use defmt::info;
use mcu_comms::prelude::*;

/// This example was made with an Esp32c3. See the cargo.toml in /examples for info about the imports.
/// You will, however, want to get your mcu's specific Aes hal.
struct AesHal(esp_hal::aes::Aes<'static>);
impl Encrypt for AesHal {
    fn encrypt(&mut self, key_stream_buf: &mut [u8; 16], block: &mut [u8; 16], key: [u8; 16]) {
        key_stream_buf.copy_from_slice(block);
        self.0.encrypt(key_stream_buf, key);
    }
}

#[derive(Debug, PartialEq, Eq)]
#[payload]
struct SensorReading {
    temp: i16,
    temp_type: TempType,
    battery_mv: u16,
    flags: u8,
}

#[derive(Debug, PartialEq, Eq)]
#[payload]
enum TempType {
    C,
    F,
}

#[esp_hal::main]
fn main() -> ! {
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    //You generally do not want to hard code your root key on an actual system but it's fine for testing.
    let root_key = [0u8; 32];

    // Get the mcu's Hardware accelerated AES peripheral
    let aes = Aes::new(peripherals.AES);
    let mut channel = PeerChannel::new(
        AesHal(aes),
        root_key,
        MacAddr::default(), // host mac address
        MacAddr::default(), // peer mac adress
    );

    let payload = SensorReading {
        temp: 20,
        temp_type: TempType::C,
        battery_mv: 30,
        flags: 0b00_10_1100,
    };
    let packet_data = PacketData::new(
        0b00_10_0100, // Your own custom flags, can be whatever you want except first 2 dominant bits are reserved for key rotation
        payload,
    )
    .unwrap();

    let mut frame = channel.encrypt(&packet_data).unwrap();

    let bytes = frame.bytes();
    // Data over air transmition...
    //
    let view = PacketView::try_from(bytes).unwrap();

    let _mac = view.mac(); // check the fields before decrypting..

    let decrypted = channel.decrypt(frame.bytes_mut()).unwrap();

    assert_eq!(packet_data, decrypted);

    info!("Successful decryption!");

    examples::util::do_something();
}
