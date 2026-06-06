//! Brutal congestion control.
//!
//! Port of `core/internal/congestion/brutal/brutal.go` onto quinn's
//! `congestion::Controller`. Brutal sends at a fixed, operator-set bandwidth and
//! deliberately ignores loss as a rate signal: it sizes the congestion window
//! from `bandwidth × RTT`, scaled up by an ACK-rate estimate so loss inflates
//! (rather than shrinks) the window.
//!
//! # Two deliberate differences from the Go original
//!
//! Both need validating/tuning against the reference server at conformance:
//!
//! 1. **Pacing.** quic-go let Brutal install a custom token-bucket pacer
//!    (`common.Pacer`) emitting at exactly `bandwidth / ack_rate`. quinn exposes
//!    no per-controller pacing hook — it paces internally at roughly
//!    `1.25 × window / rtt`. Brutal is therefore expressed purely through
//!    [`window`](BrutalSender::window); the achieved send rate is emergent from
//!    quinn's pacer. The Go `common.Pacer` is intentionally not ported.
//! 2. **Loss counting.** Go counted lost *packets* (`len(lostPackets)`); quinn's
//!    `on_congestion_event` reports only lost *bytes*, so the count is
//!    approximated as `ceil(lost_bytes / max_datagram_size)`.

use std::any::Any;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use quinn_proto::RttEstimator;
use quinn_proto::congestion::Controller;
use quinn_proto::congestion::ControllerFactory;

/// Slot index is seconds-based, so this is effectively how many seconds we
/// sample over.
const PKT_INFO_SLOT_COUNT: usize = 5;
const MIN_SAMPLE_COUNT: u64 = 50;
const MIN_ACK_RATE: f64 = 0.8;
const CONGESTION_WINDOW_MULTIPLIER: f64 = 2.0;

/// Congestion window used until the first RTT sample arrives (Go's `rtt <= 0`
/// fallback in `GetCongestionWindow`), and the controller's `initial_window`.
const INITIAL_WINDOW: u64 = 10240;

#[derive(Clone, Copy, Default)]
struct PktInfo {
    timestamp: i64,
    ack_count: u64,
    loss_count: u64,
}

/// A fixed-bandwidth `congestion::Controller`. Build it via [`BrutalConfig`].
#[derive(Clone)]
pub struct BrutalSender {
    bps: u64,
    max_datagram_size: u64,
    /// Cached smoothed RTT. Go read it from an `RTTStatsProvider`; quinn passes a
    /// `RttEstimator` to `on_ack`, so we snapshot it there.
    rtt: Duration,
    pkt_info_slots: [PktInfo; PKT_INFO_SLOT_COUNT],
    ack_rate: f64,
    /// Base instant so event times become whole seconds, like Go's monotime
    /// seconds. Only differences and the modulo matter.
    base: Instant,
}

impl BrutalSender {
    /// Create a sender targeting `bps` bytes/second.
    #[must_use]
    pub fn new(bps: u64, now: Instant, current_mtu: u16) -> Self {
        Self {
            bps,
            max_datagram_size: u64::from(current_mtu),
            rtt: Duration::ZERO,
            pkt_info_slots: [PktInfo::default(); PKT_INFO_SLOT_COUNT],
            ack_rate: 1.0,
            base: now,
        }
    }

    /// Whole seconds since construction (Go's `eventTime / time.Second`).
    fn seconds_since_base(&self, now: Instant) -> i64 {
        i64::try_from(now.saturating_duration_since(self.base).as_secs()).unwrap_or(i64::MAX)
    }

    /// Record `ack_count` acked and `loss_count` lost packets at time `now`, then
    /// recompute the ACK rate. Mirrors `OnCongestionEventEx` + `updateAckRate`.
    #[expect(
        clippy::cast_possible_wrap,
        reason = "PKT_INFO_SLOT_COUNT (5) fits i64"
    )]
    fn add_samples(&mut self, now: Instant, ack_count: u64, loss_count: u64) {
        let current = self.seconds_since_base(now);
        let slot = usize::try_from(current % PKT_INFO_SLOT_COUNT as i64).unwrap_or(0);
        if self.pkt_info_slots[slot].timestamp == current {
            self.pkt_info_slots[slot].loss_count += loss_count;
            self.pkt_info_slots[slot].ack_count += ack_count;
        } else {
            // Uninitialized slot or too old: reset.
            self.pkt_info_slots[slot] = PktInfo {
                timestamp: current,
                ack_count,
                loss_count,
            };
        }
        self.update_ack_rate(current);
    }

    #[expect(
        clippy::cast_precision_loss,
        clippy::cast_possible_wrap,
        reason = "sample counts are small; PKT_INFO_SLOT_COUNT (5) fits i64"
    )]
    fn update_ack_rate(&mut self, current: i64) {
        let min_timestamp = current - PKT_INFO_SLOT_COUNT as i64;
        let mut ack_count = 0u64;
        let mut loss_count = 0u64;
        for info in &self.pkt_info_slots {
            if info.timestamp < min_timestamp {
                continue;
            }
            ack_count += info.ack_count;
            loss_count += info.loss_count;
        }
        if ack_count + loss_count < MIN_SAMPLE_COUNT {
            self.ack_rate = 1.0;
            return;
        }
        let rate = ack_count as f64 / (ack_count + loss_count) as f64;
        self.ack_rate = rate.max(MIN_ACK_RATE);
    }

    /// Go's `GetCongestionWindow`: `bandwidth × rtt × multiplier / ack_rate`,
    /// floored at one datagram, or [`INITIAL_WINDOW`] before any RTT sample.
    #[expect(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        reason = "congestion-control math over f64"
    )]
    fn congestion_window(&self) -> u64 {
        let rtt = self.rtt.as_secs_f64();
        if rtt <= 0.0 {
            return INITIAL_WINDOW;
        }
        let cwnd = (self.bps as f64 * rtt * CONGESTION_WINDOW_MULTIPLIER / self.ack_rate) as u64;
        cwnd.max(self.max_datagram_size)
    }
}

impl Controller for BrutalSender {
    fn on_ack(
        &mut self,
        now: Instant,
        _sent: Instant,
        _bytes: u64,
        _app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.rtt = rtt.get();
        // quinn calls on_ack once per acked packet, so one ack per call.
        self.add_samples(now, 1, 0);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        if lost_bytes == 0 {
            // ECN-only event: no lost bytes to translate into a packet count.
            return;
        }
        let lost_packets = lost_bytes.div_ceil(self.max_datagram_size.max(1));
        self.add_samples(now, 0, lost_packets);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.max_datagram_size = u64::from(new_mtu);
    }

    fn window(&self) -> u64 {
        self.congestion_window()
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        INITIAL_WINDOW
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// Factory for [`BrutalSender`], installed via
/// `TransportConfig::congestion_controller_factory` (Go's `UseBrutal`).
#[derive(Debug, Clone)]
pub struct BrutalConfig {
    /// Target bandwidth in bytes/second.
    pub bps: u64,
}

impl ControllerFactory for BrutalConfig {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(BrutalSender::new(self.bps, now, current_mtu))
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    const MTU: u16 = 1200;

    fn sender() -> BrutalSender {
        BrutalSender::new(1_000_000, Instant::now(), MTU)
    }

    #[test]
    fn window_before_any_rtt_is_the_initial_window() {
        let s = sender();
        assert_eq!(s.window(), INITIAL_WINDOW, "no RTT yet ⇒ initial window");
        assert_eq!(s.initial_window(), INITIAL_WINDOW, "initial_window matches");
    }

    #[test]
    fn window_is_bandwidth_delay_product_times_multiplier() {
        let mut s = sender();
        s.rtt = Duration::from_millis(100);
        // 1_000_000 B/s × 0.1 s × 2 / 1.0 = 200_000.
        assert_eq!(s.window(), 200_000, "cwnd = bps · rtt · 2 / ack_rate");
    }

    #[test]
    fn window_is_floored_at_one_datagram() {
        let mut s = BrutalSender::new(1, Instant::now(), MTU);
        s.rtt = Duration::from_millis(1);
        assert_eq!(
            s.window(),
            u64::from(MTU),
            "cwnd never drops below one datagram"
        );
    }

    #[test]
    fn ack_rate_stays_one_below_the_sample_threshold() {
        let mut s = sender();
        let now = Instant::now();
        // 15 < MIN_SAMPLE_COUNT (50): not enough data, rate pinned to 1.0.
        s.add_samples(now, 10, 5);
        assert!(
            (s.ack_rate - 1.0).abs() < f64::EPSILON,
            "too few samples ⇒ rate 1.0"
        );
    }

    #[test]
    fn ack_rate_tracks_the_loss_fraction() {
        let mut s = sender();
        let now = Instant::now();
        // 90 acked / 100 total ⇒ 0.9 (above the 0.8 floor).
        s.add_samples(now, 90, 10);
        assert!(
            (s.ack_rate - 0.9).abs() < 1e-9,
            "rate follows ack fraction: {}",
            s.ack_rate
        );
    }

    #[test]
    fn ack_rate_is_clamped_to_the_floor() {
        let mut s = sender();
        let now = Instant::now();
        // 10 acked / 100 total = 0.1, clamped up to MIN_ACK_RATE (0.8).
        s.add_samples(now, 10, 90);
        assert!(
            (s.ack_rate - MIN_ACK_RATE).abs() < 1e-9,
            "rate clamped to floor"
        );
    }

    #[test]
    fn a_lower_ack_rate_inflates_the_window() {
        let mut s = sender();
        s.rtt = Duration::from_millis(100);
        s.ack_rate = MIN_ACK_RATE;
        // 1_000_000 × 0.1 × 2 / 0.8 = 250_000 (> the loss-free 200_000).
        assert_eq!(s.window(), 250_000, "loss inflates the window via ack_rate");
    }

    #[test]
    fn on_congestion_event_translates_bytes_to_packets_and_clamps() {
        let mut s = sender();
        let now = Instant::now();
        // 60 datagrams' worth of loss, zero acks ⇒ rate 0/60, clamped to 0.8.
        s.on_congestion_event(now, now, false, u64::from(MTU) * 60);
        assert!(
            (s.ack_rate - MIN_ACK_RATE).abs() < 1e-9,
            "pure loss clamps to floor"
        );
    }

    #[test]
    fn ecn_only_event_records_nothing() {
        let mut s = sender();
        let now = Instant::now();
        s.on_congestion_event(now, now, false, 0);
        assert!(
            (s.ack_rate - 1.0).abs() < f64::EPSILON,
            "lost_bytes 0 ⇒ no samples"
        );
    }

    #[test]
    fn stale_samples_are_evicted_after_the_window() {
        let base = Instant::now();
        let mut s = BrutalSender::new(1_000_000, base, MTU);
        // Second 0: a clean batch that on its own would give rate 1.0.
        s.add_samples(base, 100, 0);
        // Second 6: beyond PKT_INFO_SLOT_COUNT, so the second-0 batch is now
        // older than `current - 5` and must be excluded from the rate.
        s.add_samples(base + Duration::from_secs(6), 90, 10);
        assert!(
            (s.ack_rate - 0.9).abs() < 1e-9,
            "stale samples excluded ⇒ rate from second 6 only (0.9), got {}",
            s.ack_rate,
        );
    }

    #[test]
    fn samples_in_the_same_second_accumulate() {
        let base = Instant::now();
        let mut s = BrutalSender::new(1_000_000, base, MTU);
        // Two batches in the same second must sum, not overwrite: 45+5 acks and
        // 5 losses ⇒ 50/55 = 0.909 (above the floor). A reset-instead-of-add bug
        // would leave only the second batch (10 samples < threshold ⇒ rate 1.0).
        s.add_samples(base, 45, 0);
        s.add_samples(base, 5, 5);
        assert!(
            (s.ack_rate - (50.0 / 55.0)).abs() < 1e-9,
            "same-second batches accumulate, got {}",
            s.ack_rate,
        );
    }

    #[test]
    fn mtu_update_changes_the_window_floor() {
        let mut s = BrutalSender::new(1, Instant::now(), MTU);
        s.rtt = Duration::from_millis(1);
        s.on_mtu_update(1400);
        assert_eq!(s.window(), 1400, "window floor follows the MTU");
    }
}
