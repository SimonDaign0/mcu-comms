#![cfg_attr(not(test), no_std)]
mod common;
use common::prelude::*;
// ============================================================================================================

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn epoch_bump_desyncs_peer() {
        let (mut channel, _peer) = setup_synced_pair();
        assert!(channel.is_peer_synced());

        channel.inc_curr_epoch();

        assert!(!channel.is_peer_synced());
    }

    #[test]
    fn resync_after_packet_loss() {
        let (mut channel, mut peer_channel) = setup_desynced_pair();

        // simulate lost packets: tx jumps ahead without peer seeing intermediate frames
        channel.set_tx_nonce(12);

        send_regular_frame(&mut channel, &mut peer_channel).unwrap();

        assert_eq!(
            peer_channel.epoch(),
            2,
            "peer should adopt new epoch on resync frame"
        );
        assert_eq!(peer_channel.rx_nounce(), 13);
        assert!(
            !channel.is_peer_synced(),
            "channel doesn't know peer synced until it hears back"
        );

        send_regular_frame(&mut peer_channel, &mut channel).unwrap();

        assert!(channel.is_peer_synced());
    }

    #[test]
    fn resync_after_out_of_window() {
        // the peer's channel is the stale one
        let (mut channel, mut peer_channel) = setup_stale_epoch_pair();

        let resync_frame = match send_regular_frame(&mut peer_channel, &mut channel) {
            Err(Error::PeerDesynced(frame)) => frame,
            _ => panic!("a peer out of window should return a resync and not be accepted"),
        };

        match send_frame_to(resync_frame, &mut peer_channel) {
            Err(Error::SuccessfulResync) => (),
            _ => panic!("no actual errors or packetdata should be returned from a resync frame"),
        };

        assert_eq!(channel.epoch(), peer_channel.epoch());

        assert!(
            !channel.is_peer_synced(),
            "channel doesn't know peer synced until it hears back"
        );
        send_regular_frame(&mut peer_channel, &mut channel).unwrap();
        assert!(
            channel.is_peer_synced(),
            "channel should be synced since it heard back from peer"
        );
    }
}
