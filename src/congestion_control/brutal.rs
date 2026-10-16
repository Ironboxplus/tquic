// Copyright (c) 2026 The TQUIC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Brutal congestion control (MP_SQM_PLAN.md S2.4).
//!
//! Ported from Hysteria's `core/internal/congestion/brutal/brutal.go`: TQUIC
//! has no equivalent, so this is a new module rather than a modification of
//! an existing one. Unlike every other algorithm in this crate, Brutal does
//! not infer a send rate from RTT/loss measurements -- it sends at an
//! externally supplied rate, self-compensating for measured loss by inflating
//! its congestion window/pacing rate proportionally, unless that compensation
//! is disabled. The rate is the MP optimizer's resource-graph max-flow
//! allocation for the path (`Path::set_scheduler_target_rate` ->
//! `set_target_rate`), which follows the egress's autorate estimate; the
//! configured `bps` (`up_mbps`) is only the rate before an allocation exists,
//! as it is autorate's starting point. What bounds the rate from above is the
//! egress budget the allocation is cut from (autorate within the user's
//! static ceiling) and the peer's announced receive rate.
//!
//! Unlike the Go original, this does not own a pacer: TQUIC already has a
//! single shared RFC 9002 pacer per path (`congestion_control::pacing::Pacer`,
//! driven by `recovery.rs` from `congestion_window()`/`pacing_rate()`), so
//! Brutal only needs to report the right numbers into that existing
//! machinery instead of scheduling sends itself.
//!
//! Two TQUIC-side differences are compensated so the send gate matches the
//! Go original exactly:
//! - Hysteria's `CanSend` is `bytesInFlight <= cwnd`; TQUIC's
//!   `Recovery::can_send` blocks at `bytes_in_flight >= congestion_window()`.
//!   `congestion_window()` therefore reports Hysteria's window plus one byte.
//!   This matters at the one-datagram floor (small RTT): with `<` only one
//!   packet is ever in flight, the receiver holds its ACK for max_ack_delay,
//!   and throughput collapses far below `bps`.
//! - Hysteria's floor is the connection's current datagram size
//!   (`SetMaxDatagramSize`); here it starts from `RecoveryConfig::
//!   max_datagram_size` and follows `set_max_datagram_size`.

use std::time::Duration;
use std::time::Instant;

use super::CongestionController;
use super::CongestionStats;
use crate::connection::rtt::RttEstimator;
use crate::connection::space::SentPacket;
use crate::RecoveryConfig;

/// How many one-second slots of ack/loss counts are kept -- also, therefore,
/// how many seconds of history `ack_rate` is computed over.
const PKT_INFO_SLOT_COUNT: usize = 5;

/// Below this many combined acked+lost samples in the window, there isn't
/// enough signal to trust a measured ack rate; stay at `1.0` (no
/// compensation) rather than react to noise.
const MIN_SAMPLE_COUNT: u64 = 50;

/// `ack_rate` never drops below this floor, however bad measured loss gets:
/// an unbounded compensation multiplier could inflate the window/pacing rate
/// without limit on a badly lossy link.
const MIN_ACK_RATE: f64 = 0.8;

/// `congestion_window = bps * srtt * multiplier / ack_rate`.
const CONGESTION_WINDOW_MULTIPLIER: f64 = 2.0;

/// Congestion window used before any RTT sample exists yet, in bytes.
const NO_RTT_CONGESTION_WINDOW: u64 = 10240;

#[derive(Debug, Default, Clone, Copy)]
struct PktInfo {
    /// Which one-second bucket (seconds since this controller's construction)
    /// this slot's counts belong to. Compared against the slot's own index
    /// modulo `PKT_INFO_SLOT_COUNT` to detect "this slot is stale/uninitialized
    /// for the current second" vs. "still the same second, just add to it".
    timestamp: i64,
    ack_count: u64,
    loss_count: u64,
}

/// Brutal Configuration.
#[derive(Debug, Clone, Copy)]
pub struct BrutalConfig {
    /// Send rate before any target is installed, in bytes/sec.
    pub bps: u64,

    /// Disable ack-rate loss compensation: when `true`, `ack_rate` stays
    /// pinned at `1.0` regardless of measured loss.
    pub disable_loss_compensation: bool,

    /// Initial maximum datagram size, the window floor.
    pub max_datagram_size: u64,
}

impl BrutalConfig {
    pub fn from(conf: &RecoveryConfig) -> Self {
        Self {
            bps: conf.brutal_bps,
            disable_loss_compensation: conf.brutal_disable_loss_compensation,
            max_datagram_size: conf.max_datagram_size as u64,
        }
    }
}

impl Default for BrutalConfig {
    fn default() -> Self {
        Self {
            bps: 0,
            disable_loss_compensation: false,
            max_datagram_size: crate::DEFAULT_SEND_UDP_PAYLOAD_SIZE as u64,
        }
    }
}

/// Brutal is a fixed-rate congestion controller that self-compensates for
/// measured loss (MP_SQM_PLAN.md S2.4). See the module doc for the port
/// rationale and TQUIC-specific adaptations.
#[derive(Debug)]
pub struct Brutal {
    /// The rate this path starts at (`up_mbps`, converted to bytes/sec), used
    /// until `set_target_rate` installs one -- see `effective_bps`.
    start_bps: u64,

    /// Last value passed to `set_target_rate`. `None` means "no external
    /// target installed, use `start_bps` natively" -- the same meaning
    /// `Path::set_scheduler_target_rate(None)` documents ("restores the
    /// scheduler's native congestion-control/RTT policy"). See
    /// `effective_bps` for how `Some(0)` is handled.
    external_target: Option<u64>,

    max_datagram_size: u64,

    /// Ack-rate compensation multiplier in `(MIN_ACK_RATE, 1.0]`, `1.0` when
    /// compensation is disabled or not enough samples exist yet.
    ack_rate: f64,

    disable_loss_compensation: bool,

    slots: [PktInfo; PKT_INFO_SLOT_COUNT],

    /// Wall-clock reference this controller was constructed at, used only to
    /// bucket `slots` into one-second windows (see `PktInfo::timestamp`'s
    /// doc) -- never compared against any other controller's or path's own
    /// notion of time.
    epoch: Instant,

    /// Most recent smoothed RTT sample (from `on_ack`), used by
    /// `congestion_window` -- the trait's `congestion_window(&self)` has no
    /// live `RttEstimator` to read at call time, so it must be cached from
    /// the last callback that did have one, exactly like the Go original
    /// reads `rttStats.SmoothedRTT()` directly. Starts at zero, matching the
    /// Go original's `if rtt <= 0 { return 10240 }` no-RTT-yet case.
    srtt: Duration,

    stats: CongestionStats,
}

impl Brutal {
    pub fn new(conf: BrutalConfig) -> Self {
        Self {
            start_bps: conf.bps,
            external_target: None,
            max_datagram_size: conf.max_datagram_size,
            ack_rate: 1.0,
            disable_loss_compensation: conf.disable_loss_compensation,
            slots: [PktInfo::default(); PKT_INFO_SLOT_COUNT],
            epoch: Instant::now(),
            srtt: Duration::ZERO,
            stats: CongestionStats::default(),
        }
    }

    /// The rate `congestion_window`/`pacing_rate` actually use: whatever
    /// `set_target_rate` last installed, else `start_bps`. `Some(0)` --
    /// "exclude this path from scheduling" -- is
    /// handled by TQUIC's own `Path::active` flag (set by the same
    /// `set_scheduler_target_rate` call that reaches `set_target_rate`), so
    /// treating it as "no target" here (rather than actually zeroing the
    /// window/pacing math) avoids reporting a degenerate all-zero cwnd/pacing
    /// rate for a path that is merely paused, not gone.
    fn effective_bps(&self) -> u64 {
        match self.external_target {
            Some(0) | None => self.start_bps,
            Some(target) => target,
        }
    }

    /// The wire rate after loss compensation (`effective_bps / ack_rate`,
    /// Hysteria's rule). An installed target is a goodput rate like
    /// `start_bps` -- the allocator's share of the egress budget, capped
    /// by the peer's announced receive rate, which is a goodput rate too --
    /// so compensation applies on top of it. What bounds the wire is the
    /// egress governor, and autorate backs the budget off if the compensated
    /// rate bloats the link.
    fn send_rate(&self) -> f64 {
        self.effective_bps() as f64 / self.ack_rate
    }

    /// Hysteria's `GetCongestionWindow`: `bps * srtt * 2 / ack_rate`, at least
    /// one datagram; 10240 bytes before any RTT sample.
    fn hysteria_cwnd(&self) -> u64 {
        if self.srtt.is_zero() {
            return NO_RTT_CONGESTION_WINDOW;
        }
        let cwnd = (self.send_rate() * self.srtt.as_secs_f64() * CONGESTION_WINDOW_MULTIPLIER) as u64;
        cwnd.max(self.max_datagram_size)
    }

    fn current_timestamp(&self, now: Instant) -> i64 {
        now.saturating_duration_since(self.epoch).as_secs() as i64
    }

    /// Record `count` newly-acked packets at `now`, and recompute `ack_rate`.
    /// Split out from `on_ack` (which always records exactly one packet) so
    /// the ackRate-table unit tests below can drive an arbitrary sample count
    /// in a single call, matching how the ported Go test
    /// (`brutal_test.go`'s batched `OnCongestionEventEx`) exercises this.
    fn record_ack(&mut self, now: Instant, count: u64) {
        self.record_slot(now, count, 0);
    }

    /// Record `count` newly-lost packets at `now`, and recompute `ack_rate`.
    fn record_loss(&mut self, now: Instant, count: u64) {
        self.record_slot(now, 0, count);
    }

    fn record_slot(&mut self, now: Instant, ack_count: u64, loss_count: u64) {
        let current_timestamp = self.current_timestamp(now);
        let slot = (current_timestamp.rem_euclid(PKT_INFO_SLOT_COUNT as i64)) as usize;
        if self.slots[slot].timestamp == current_timestamp {
            self.slots[slot].ack_count += ack_count;
            self.slots[slot].loss_count += loss_count;
        } else {
            // Uninitialized slot, or one left over from a previous lap
            // around the ring (stale): reset it to just this sample.
            self.slots[slot] = PktInfo {
                timestamp: current_timestamp,
                ack_count,
                loss_count,
            };
        }
        self.update_ack_rate(current_timestamp);
    }

    fn update_ack_rate(&mut self, current_timestamp: i64) {
        if self.disable_loss_compensation {
            self.ack_rate = 1.0;
            return;
        }
        let min_timestamp = current_timestamp - PKT_INFO_SLOT_COUNT as i64;
        let (mut ack_count, mut loss_count) = (0u64, 0u64);
        for info in &self.slots {
            if info.timestamp < min_timestamp {
                continue;
            }
            ack_count += info.ack_count;
            loss_count += info.loss_count;
        }
        let total = ack_count + loss_count;
        if total < MIN_SAMPLE_COUNT {
            self.ack_rate = 1.0;
            return;
        }
        let rate = ack_count as f64 / total as f64;
        self.ack_rate = rate.max(MIN_ACK_RATE);
    }
}

impl CongestionController for Brutal {
    fn name(&self) -> &str {
        "BRUTAL"
    }

    fn on_sent(&mut self, _now: Instant, packet: &mut SentPacket, bytes_in_flight: u64) {
        let sent_bytes = packet.sent_size as u64;
        self.stats.bytes_in_flight = bytes_in_flight;
        self.stats.bytes_sent_in_total = self.stats.bytes_sent_in_total.saturating_add(sent_bytes);
    }

    fn begin_ack(&mut self, _now: Instant, _bytes_in_flight: u64) {
        // Do nothing: unlike a window-based algorithm, Brutal has no
        // per-round batch state to open here -- each acked packet is
        // recorded independently in `on_ack`.
    }

    fn on_ack(
        &mut self,
        packet: &mut SentPacket,
        now: Instant,
        _app_limited: bool,
        rtt: &RttEstimator,
        bytes_in_flight: u64,
    ) {
        let acked_bytes = packet.sent_size as u64;
        self.stats.bytes_in_flight = bytes_in_flight;
        self.stats.bytes_acked_in_total =
            self.stats.bytes_acked_in_total.saturating_add(acked_bytes);
        self.srtt = rtt.smoothed_rtt();
        self.record_ack(now, 1);
    }

    fn end_ack(&mut self) {
        // Do nothing; see `begin_ack`.
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        _packet: &SentPacket,
        _is_persistent_congestion: bool,
        lost_bytes: u64,
        bytes_in_flight: u64,
    ) {
        self.stats.bytes_lost_in_total = self.stats.bytes_lost_in_total.saturating_add(lost_bytes);
        self.stats.bytes_in_flight = bytes_in_flight;
        self.record_loss(now, 1);
    }

    fn in_slow_start(&self) -> bool {
        false
    }

    fn in_recovery(&self, _sent_time: Instant) -> bool {
        false
    }

    fn congestion_window(&self) -> u64 {
        // +1: TQUIC's `can_send` is `in_flight < window`, Hysteria's is
        // `in_flight <= cwnd` (see the module doc).
        self.hysteria_cwnd() + 1
    }

    fn pacing_rate(&self) -> Option<u64> {
        Some(self.send_rate() as u64)
    }

    fn initial_window(&self) -> u64 {
        self.congestion_window()
    }

    fn minimal_window(&self) -> u64 {
        self.max_datagram_size
    }

    fn stats(&self) -> &CongestionStats {
        &self.stats
    }

    fn min_pacing_rate(&self) -> Option<u64> {
        None
    }

    fn set_target_rate(&mut self, bps: Option<u64>) {
        self.external_target = bps;
    }

    fn set_max_datagram_size(&mut self, max_datagram_size: u64) {
        self.max_datagram_size = max_datagram_size;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn brutal(bps: u64, disable_loss_compensation: bool) -> Brutal {
        Brutal::new(BrutalConfig {
            bps,
            disable_loss_compensation,
            ..BrutalConfig::default()
        })
    }

    /// Ported from `upstream/hysteria/core/internal/congestion/brutal/
    /// brutal_test.go`'s `TestBrutalLossCompensation` table (MP_SQM_PLAN.md
    /// S2.4's RED spec, verbatim): no loss -> 1.0; 20% loss -> 0.8; 50% loss
    /// clamps to the 0.8 floor; too few samples stays 1.0 regardless of the
    /// observed ratio; and with compensation disabled, every case stays 1.0.
    #[test]
    fn ack_rate_table_matches_the_ported_go_test() {
        let cases: [(&str, u64, u64, f64); 4] = [
            ("no loss", 100, 0, 1.0),
            ("20% loss", 80, 20, 0.8),
            ("50% loss clamps to floor", 50, 50, MIN_ACK_RATE),
            ("few samples stays 1", 10, 5, 1.0),
        ];
        for (name, ack, loss, want) in cases {
            let mut compensated = brutal(1_000_000, false);
            let now = compensated.epoch + Duration::from_secs(5);
            compensated.record_ack(now, ack);
            compensated.record_loss(now, loss);
            assert_eq!(
                compensated.ack_rate, want,
                "{name}: compensation on, ack_rate"
            );

            let mut uncompensated = brutal(1_000_000, true);
            let now = uncompensated.epoch + Duration::from_secs(5);
            uncompensated.record_ack(now, ack);
            uncompensated.record_loss(now, loss);
            assert_eq!(
                uncompensated.ack_rate, 1.0,
                "{name}: compensation off must stay pinned at 1.0"
            );
        }
    }

    #[test]
    fn congestion_window_uses_the_no_rtt_floor_before_any_ack() {
        let b = brutal(1_000_000, false);
        assert!(b.srtt.is_zero());
        assert_eq!(b.hysteria_cwnd(), NO_RTT_CONGESTION_WINDOW);
    }

    #[test]
    fn congestion_window_and_pacing_rate_follow_the_documented_formula() {
        let mut b = brutal(1_000_000, false);
        b.srtt = Duration::from_millis(100);
        // No loss recorded yet: ack_rate stays at its initial 1.0.
        assert_eq!(b.ack_rate, 1.0);
        assert_eq!(
            b.hysteria_cwnd(),
            (1_000_000.0_f64 * 0.1 * CONGESTION_WINDOW_MULTIPLIER) as u64
        );
        assert_eq!(b.pacing_rate(), Some(1_000_000));

        // Force a below-floor ack_rate directly (rather than feeding 50
        // samples) to check the formula's use of it in isolation.
        b.ack_rate = MIN_ACK_RATE;
        assert_eq!(
            b.hysteria_cwnd(),
            (1_000_000.0_f64 * 0.1 * CONGESTION_WINDOW_MULTIPLIER / MIN_ACK_RATE) as u64
        );
        assert_eq!(b.pacing_rate(), Some((1_000_000.0_f64 / MIN_ACK_RATE) as u64));
    }

    #[test]
    fn congestion_window_never_drops_below_one_datagram() {
        let mut b = brutal(1, false);
        b.srtt = Duration::from_millis(1);
        assert_eq!(b.hysteria_cwnd(), b.max_datagram_size);
    }

    /// TQUIC's `Recovery::can_send` blocks at `in_flight >= congestion_window()`,
    /// Hysteria's `CanSend` at `in_flight > cwnd`. At the one-datagram floor
    /// (8 Mbit/s over a ~0.1 ms loopback RTT) Hysteria still lets a second
    /// packet out while one is in flight -- which is what makes the receiver
    /// ACK immediately instead of after max_ack_delay. The reported window
    /// must reproduce that gate exactly.
    #[test]
    fn send_gate_matches_hysteria_at_the_one_datagram_floor() {
        let mut b = brutal(1_000_000, false);
        b.set_max_datagram_size(1472);
        b.srtt = Duration::from_micros(100);
        let cwnd = b.hysteria_cwnd();
        assert_eq!(cwnd, 1472, "floor is the current datagram size");
        let tquic_can_send = |in_flight: u64| in_flight < b.congestion_window();
        let hysteria_can_send = |in_flight: u64| in_flight <= cwnd;
        for in_flight in [0, 1, 1471, 1472, 1473, 2944] {
            assert_eq!(
                tquic_can_send(in_flight),
                hysteria_can_send(in_flight),
                "in_flight={in_flight}"
            );
        }
        assert!(tquic_can_send(1472), "a second datagram may follow the first");
    }

    #[test]
    fn datagram_size_follows_the_config_and_later_updates() {
        let b = Brutal::new(BrutalConfig::from(&RecoveryConfig {
            max_datagram_size: 1350,
            ..RecoveryConfig::default()
        }));
        assert_eq!(b.minimal_window(), 1350);
        let mut b = b;
        b.set_max_datagram_size(1452);
        assert_eq!(b.minimal_window(), 1452);
    }

    #[test]
    fn slot_rollover_forgets_samples_older_than_the_window() {
        let mut b = brutal(1_000_000, false);
        let t0 = b.epoch;
        // 50 lost packets at t=0 alone would clamp ack_rate to the floor...
        b.record_loss(t0, 50);
        assert_eq!(b.ack_rate, MIN_ACK_RATE);
        // ...but once every slot has rolled over (more than
        // PKT_INFO_SLOT_COUNT seconds later), that old sample must no
        // longer count, and a single fresh ack with nothing else in window
        // must read back as "not enough samples" (1.0), not "all acked".
        let t1 = t0 + Duration::from_secs(PKT_INFO_SLOT_COUNT as u64 + 1);
        b.record_ack(t1, 1);
        assert_eq!(b.ack_rate, 1.0);
    }

    /// The configured rate is where a path starts; an installed target
    /// replaces it whether lower or higher (it is the allocation from the
    /// egress's autorate estimate, which climbs past the start once the link
    /// carries more), and `None` -- TQUIC's "clear the external target,
    /// restore native policy" call -- goes back to the start, not to zero.
    #[test]
    fn an_installed_target_replaces_the_start_rate_and_none_restores_it() {
        let mut b = brutal(1_000_000, false);
        assert_eq!(b.pacing_rate(), Some(1_000_000), "starts at start_bps");

        b.set_target_rate(Some(400_000));
        assert_eq!(b.pacing_rate(), Some(400_000));

        b.set_target_rate(Some(5_000_000));
        assert_eq!(
            b.pacing_rate(),
            Some(5_000_000),
            "a target above the start rate is the rate"
        );

        b.set_target_rate(None);
        assert_eq!(b.pacing_rate(), Some(1_000_000));
    }

    /// An installed target is a goodput rate: loss compensation applies on
    /// top of it exactly as on `start_bps` (Hysteria's rule).
    #[test]
    fn loss_compensation_applies_on_top_of_an_installed_target() {
        let mut b = brutal(1_000_000, false);
        b.srtt = Duration::from_millis(100);
        b.ack_rate = MIN_ACK_RATE;
        let compensated = |bps: f64| (bps / MIN_ACK_RATE) as u64;
        assert_eq!(b.pacing_rate(), Some(compensated(1_000_000.0)));

        b.set_target_rate(Some(600_000));
        assert_eq!(b.pacing_rate(), Some(compensated(600_000.0)));
        assert_eq!(
            b.hysteria_cwnd(),
            (600_000.0 / MIN_ACK_RATE * 0.1 * CONGESTION_WINDOW_MULTIPLIER) as u64
        );

        b.set_target_rate(Some(5_000_000));
        assert_eq!(b.pacing_rate(), Some(compensated(5_000_000.0)));
    }

    /// `Some(0)` means "exclude this path" via TQUIC's own `Path::active`
    /// flag (set by the same `set_scheduler_target_rate` call before it ever
    /// reaches `set_target_rate`); Brutal itself must keep reporting its
    /// normal configured cwnd/pacing rather than a degenerate all-zero one,
    /// since nothing here actually stops packets from being scheduled -- that
    /// is `Path::active`'s job, not the congestion controller's.
    #[test]
    fn set_target_rate_some_zero_does_not_zero_the_window_math() {
        let mut b = brutal(1_000_000, false);
        b.srtt = Duration::from_millis(100);
        let baseline_cwnd = b.congestion_window();
        assert!(baseline_cwnd > b.max_datagram_size);

        b.set_target_rate(Some(0));

        assert_eq!(b.pacing_rate(), Some(1_000_000));
        assert_eq!(b.congestion_window(), baseline_cwnd);
    }

    /// MP_SQM_PLAN.md S2.4 RED requirement: "TQUIC 测试夹具注入 10% 丢包时吞吐
    /// 不低于目标 90%". Simulates a steady 10% i.i.d. loss rate across enough
    /// one-second slots to fill the window, then checks that the *delivered*
    /// throughput (what actually arrives, i.e. `pacing_rate * (1 - loss_rate)`
    /// -- the resend/inflated portion of `pacing_rate` is exactly what does
    /// not arrive) still meets the target `bps`, proving loss compensation
    /// (not just "some cwnd/pacing formula") actually holds up delivered
    /// throughput near target under real loss, not merely at/above the 90%
    /// floor as a coincidence.
    #[test]
    fn loss_compensated_pacing_delivers_at_least_90_percent_of_target_bps_under_10_percent_loss() {
        let target_bps = 20_000_000u64;
        let mut b = brutal(target_bps, false);
        let packets_per_second = 100u64;
        let loss_rate = 0.10;
        let lost_per_second = (packets_per_second as f64 * loss_rate) as u64;
        let acked_per_second = packets_per_second - lost_per_second;

        // Feed several seconds so the 5-slot window is full of a stable 10%
        // loss rate (well past MIN_SAMPLE_COUNT per window).
        for second in 0..(PKT_INFO_SLOT_COUNT as u64 + 2) {
            let now = b.epoch + Duration::from_secs(second);
            b.record_ack(now, acked_per_second);
            b.record_loss(now, lost_per_second);
        }

        assert!(
            b.ack_rate >= MIN_ACK_RATE,
            "ack_rate {} unexpectedly below its own floor",
            b.ack_rate
        );
        // 10% loss keeps ack_rate at 0.9, above the 0.8 floor, so this should
        // hold with real compensation, not the floor clamp.
        assert!(
            (b.ack_rate - 0.9).abs() < 1e-9,
            "expected ack_rate 0.9 for steady 10% loss, got {}",
            b.ack_rate
        );

        let pacing_rate = b.pacing_rate().unwrap() as f64;
        let delivered_bps = pacing_rate * (1.0 - loss_rate);
        assert!(
            delivered_bps >= target_bps as f64 * 0.9,
            "delivered {delivered_bps} bps below 90% of target {target_bps} bps"
        );
    }

    /// Same 10% loss scenario as the test above, but driven through the real
    /// `CongestionController` trait callbacks (`on_sent`/`begin_ack`/`on_ack`/
    /// `end_ack`/`on_congestion_event`) instead of calling the private
    /// `record_ack`/`record_loss` helpers directly -- proving the wiring a
    /// live `Path`/`Recovery` actually drives, not just the internal counting
    /// logic those helpers implement, reaches the same `ack_rate`/`pacing_
    /// rate` (MP_SQM_PLAN.md S2.4 review item 5).
    #[test]
    fn real_on_ack_and_on_congestion_event_calls_converge_to_the_same_ack_rate_and_pacing() {
        let target_bps = 20_000_000u64;
        let mut b = brutal(target_bps, false);
        let rtt_estimator = RttEstimator::new(Duration::from_millis(20));
        let packets_per_second = 100u64;
        let lost_per_second = 10u64; // 10%
        let acked_per_second = packets_per_second - lost_per_second;

        for second in 0..(PKT_INFO_SLOT_COUNT as u64 + 2) {
            let now = b.epoch + Duration::from_secs(second);
            for _ in 0..acked_per_second {
                let mut packet = SentPacket {
                    sent_size: 1200,
                    ack_eliciting: true,
                    in_flight: true,
                    ..SentPacket::default()
                };
                b.on_sent(now, &mut packet, 0);
                b.begin_ack(now, 0);
                b.on_ack(&mut packet, now, false, &rtt_estimator, 0);
                b.end_ack();
            }
            for _ in 0..lost_per_second {
                let mut packet = SentPacket {
                    sent_size: 1200,
                    ack_eliciting: true,
                    in_flight: true,
                    ..SentPacket::default()
                };
                b.on_sent(now, &mut packet, 0);
                b.on_congestion_event(now, &packet, false, packet.sent_size as u64, 0);
            }
        }

        assert!(
            (b.ack_rate - 0.9).abs() < 1e-9,
            "expected ack_rate ~0.9 for steady 10% loss driven through the real callbacks, got {}",
            b.ack_rate
        );
        let expected_pacing = (target_bps as f64 / 0.9) as u64;
        assert_eq!(b.pacing_rate(), Some(expected_pacing));
    }

    #[test]
    fn name_and_recovery_state_are_fixed() {
        let b = brutal(1_000_000, false);
        assert_eq!(b.name(), "BRUTAL");
        assert!(!b.in_slow_start());
        assert!(!b.in_recovery(Instant::now()));
        assert_eq!(b.min_pacing_rate(), None);
        assert_eq!(b.minimal_window(), b.max_datagram_size);
    }
}
