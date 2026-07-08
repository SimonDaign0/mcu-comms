pub mod prelude {
    use mcu_comms::{MacAddr, PeerChannel};
    // Arbitrary values on the state on a channel
    pub const PEER_START_TX: u64 = 1234;
    pub const CHANNEL_START_TX: u64 = 123456;
    //
    pub const EPOCH_WINDOW: usize = 1;

    // simulates a regular packet being sent
    pub fn send_frame_to<T: Payload>(
        mut frame: Frame<T>,
        receiver: &mut PeerChannel<AesHal>,
    ) -> Result<PacketData<Sensor>, Error> {
        let decrypted = receiver.decrypt::<Sensor>(frame.bytes_mut())?;
        Ok(decrypted)
    }

    // simulates a regular packet being sent
    pub fn send_regular_frame(
        sender: &mut PeerChannel<AesHal>,
        receiver: &mut PeerChannel<AesHal>,
    ) -> Result<PacketData<Sensor>, Error> {
        let packet_data = PacketData::new(REG_FLAGS, Sensor::default())?;
        let mut frame = sender.encrypt(&packet_data)?;
        let decrypted = receiver.decrypt::<Sensor>(frame.bytes_mut())?;
        Ok(decrypted)
    }

    pub fn send_frame_printed(
        sender: &mut PeerChannel<AesHal>,
        receiver: &mut PeerChannel<AesHal>,
    ) -> Result<PacketData<Sensor>, Error> {
        let packet_data = PacketData::new(REG_FLAGS, Sensor::default())?;
        let mut frame = sender.encrypt(&packet_data)?;
        let decrypted = receiver.decrypt::<Sensor>(frame.bytes_mut())?;
        Ok(decrypted)
    }

    pub fn setup_synced_pair() -> (PeerChannel<AesHal>, PeerChannel<AesHal>) {
        let mut channel = PeerChannel::new(AesHal, ROOT_KEY, MacAddr::default(), MacAddr::peer());
        let mut peer_channel =
            PeerChannel::new(AesHal, ROOT_KEY, MacAddr::peer(), MacAddr::default());
        channel.set_tx_nonce(CHANNEL_START_TX);
        channel.set_rx_nonce(PEER_START_TX);
        peer_channel.set_tx_nonce(PEER_START_TX);
        peer_channel.set_rx_nonce(CHANNEL_START_TX);
        send_regular_frame(&mut peer_channel, &mut channel).unwrap();
        (channel, peer_channel)
    }

    pub fn setup_desynced_pair() -> (PeerChannel<AesHal>, PeerChannel<AesHal>) {
        let (mut channel, peer_channel) = setup_synced_pair();
        channel.inc_curr_epoch();
        (channel, peer_channel)
    }

    pub fn setup_stale_epoch_pair() -> (PeerChannel<AesHal>, PeerChannel<AesHal>) {
        let (mut channel, peer_channel) = setup_synced_pair();
        // Push channel's epoch beyond peer_channel's acceptance window
        // (window size is EPOCH_WINDOW; +1 guarantees staleness regardless of window size)
        for _ in 0..=EPOCH_WINDOW {
            channel.inc_curr_epoch();
        }
        (channel, peer_channel)
    }

    pub use aes::Aes128;
    pub use aes::cipher::{BlockCipherEncrypt, KeyInit};

    pub fn print_view<T: Payload>(frame: &Frame<T>) -> Result<(), Error> {
        let view = PacketView::try_from(frame.bytes())?;
        println!("==================");
        println!("mac: {:?}", view.mac());
        println!("flags: {:b}", view.flags());
        println!("nonce: {}", view.nonce());
        println!("epoch: {}", view.epoch());
        println!("==================");
        Ok(())
    }

    pub use mcu_comms::prelude::*;
    pub const ROOT_KEY: [u8; 32] = [0u8; 32];
    pub const REG_FLAGS: u8 = 0b00_11_1111;

    pub const TAG_SIZE: usize = mcu_comms::peer_channel::TAG_SIZE;
    pub const MAX_NONCE: [u8; 5] = [0xFFu8; 5];

    #[derive(Debug, Clone)]
    pub struct AesHal;

    impl Encrypt for AesHal {
        fn encrypt(&mut self, out_block: &mut [u8; 16], in_block: &mut [u8; 16], key: [u8; 16]) {
            let aes = Aes128::new(&key.into());
            let mut buf = *in_block;
            aes.encrypt_block((&mut buf).into());
            *out_block = buf;
        }
    }

    #[derive(Debug, PartialEq, Eq, Clone)]
    #[payload]
    pub struct Sensor {
        temp: i16,
        temp_type: TempType,
        bat_low: bool,
    }

    #[derive(Debug, PartialEq, Eq, Clone)]
    #[payload]
    pub enum TempType {
        C,
        F,
    }

    impl Default for Sensor {
        fn default() -> Self {
            Self {
                temp: 20,
                temp_type: TempType::C,
                bat_low: false,
            }
        }
    }
}
