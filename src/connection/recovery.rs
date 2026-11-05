// Copyright (c) 2023 The TQUIC Authors.
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

use std::cmp;
use std::collections::VecDeque;
use std::ops::Range;
use std::time;
use std::time::Duration;
use std::time::Instant;

use log::*;

use super::rtt::RttEstimator;
use super::space::AckedPacket;
use super::space::PacketNumSpace;
use super::space::PacketNumSpaceMap;
use super::space::SentPacket;
use super::space::SpaceId;
use super::space::SpaceId::*;
use super::Connection;
use super::HandshakeStatus;
use crate::congestion_control;
use crate::congestion_control::CongestionController;
use crate::congestion_control::Pacer;
use crate::connection::Timer;
use crate::frame;
#[cfg(feature = "qlog")]
use crate::qlog;
#[cfg(feature = "qlog")]
use crate::qlog::events::EventData;
use crate::ranges::RangeSet;
use crate::Error;
use crate::PathStats;
use crate::RecoveryConfig;
use crate::Result;
use crate::TIMER_GRANULARITY;

const INITIAL_PACKET_THRESHOLD: u64 = 3;

/// The time threshold as the time allowed beyond an RTT, in eighths of an RTT:
/// RFC 9002's kTimeThreshold of 9/8 at first, doubled up to two RTTs while
/// reordering outlasts it (quic-go's `timeThresholdEighths`).
const DEFAULT_TIME_THRESHOLD_EIGHTHS: u32 = 1;
const MAX_TIME_THRESHOLD_EIGHTHS: u32 = 8;

const MAX_PTO_PROBES_COUNT: usize = 2;

/// Prevents overflow of the probe timeout backoff in extreme circumstances
/// (noq `MAX_BACKOFF_EXPONENT`).
const MAX_BACKOFF_EXPONENT: u32 = 16;

/// Consecutive timeouts the limited probe timeout is iterated over: far more
/// than any connection sees before its idle timeout.
const MAX_PTO_BACKOFF_STEPS: u32 = 4096;

/// Whether `space_id` is an application data packet number space.
fn is_app_data(space_id: SpaceId) -> bool {
    space_id != SpaceId::Initial && space_id != SpaceId::Handshake
}

/// Loss detection thresholds and probe timeout computation.
///
/// Everything else in `Recovery` (packet bookkeeping, timers, congestion
/// control hooks) is shared; an implementation only decides when a packet
/// counts as lost and how long a probe timeout is.
pub(crate) trait LossDetection {
    /// Name shown in runtime status.
    fn name(&self) -> &'static str;

    /// Time after which an unacknowledged packet sent before an
    /// acknowledged one is declared lost. `app_data`: the packet is in an
    /// application data space, where the thresholds follow the reordering
    /// seen.
    fn loss_delay(&self, latest_rtt: Duration, smoothed_rtt: Duration, app_data: bool) -> Duration;

    /// Whether a packet is declared lost by the reordering threshold.
    fn lost_by_reordering(&self, pkt_num: u64, largest_acked: u64, app_data: bool) -> bool;

    /// An application data packet was sent.
    fn on_app_data_sent(&mut self, pkt_num: u64);

    /// Application data packets declared lost were acknowledged after all:
    /// each one's packet number and how long after it was sent the peer
    /// received it.
    fn on_spurious_losses(
        &mut self,
        losses: &[(u64, Duration)],
        latest_rtt: Duration,
        smoothed_rtt: Duration,
    );

    /// Probe timeout after `pto_count` consecutive timeouts.
    fn pto(&self, pto_base: Duration, pto_count: usize, smoothed_rtt: Duration) -> Duration;

    /// Probe timeout of the Application Data space, which also waits for the
    /// peer's `max_ack_delay`. `duration` is [`LossDetection::pto`] of
    /// `pto_base`.
    fn pto_with_ack_delay(
        &self,
        duration: Duration,
        pto_base: Duration,
        max_ack_delay: Duration,
        pto_count: usize,
        smoothed_rtt: Duration,
    ) -> Duration;
}

/// Loss detection as specified in RFC 9002 Section 6, with the thresholds of
/// the application data spaces raised after spurious losses as Section 6.1
/// allows. As in quic-go (`sentPacketHandler.detectSpuriousLosses`): once a
/// packet declared lost is acknowledged after all, the packet threshold no
/// longer applies, and the time threshold doubles, up to two RTTs, whenever
/// such a packet arrived later than it allowed. Reordering then costs a wait
/// of the time threshold instead of a retransmission and a congestion event.
pub(crate) struct Rfc9002 {
    /// Maximum reordering in packets before packet threshold loss detection
    /// considers a packet lost.
    pkt_thresh: u64,

    /// A spurious loss was seen: application data is declared lost by the
    /// time threshold only.
    pkt_thresh_disabled: bool,

    /// Time allowed beyond an RTT before an application data packet is
    /// declared lost, in eighths of an RTT.
    time_thresh_eighths: u32,

    /// The first application data packet sent since the time threshold last
    /// grew. Only packets from it on may make it grow again: earlier ones were
    /// judged by the shorter threshold.
    min_pkt_num_to_relax: Option<u64>,

    /// The endpoint do not backoff the first `pto_linear_factor` consecutive probe timeouts.
    pto_linear_factor: u64,

    /// Upper limit of probe timeout.
    max_pto: Duration,

    /// Upper limit of the growth of the probe timeout between two consecutive
    /// timeouts, `None` for plain exponential backoff.
    max_pto_interval: Option<Duration>,
}

impl Rfc9002 {
    pub(crate) fn new(conf: &RecoveryConfig) -> Self {
        Rfc9002 {
            pkt_thresh: INITIAL_PACKET_THRESHOLD,
            pkt_thresh_disabled: false,
            time_thresh_eighths: DEFAULT_TIME_THRESHOLD_EIGHTHS,
            min_pkt_num_to_relax: None,
            pto_linear_factor: conf.pto_linear_factor,
            max_pto: conf.max_pto,
            max_pto_interval: conf.max_pto_interval,
        }
    }

    fn backoff_factor(&self, pto_count: usize) -> u32 {
        pto_count.saturating_sub(self.pto_linear_factor as usize) as u32
    }

    /// The probe timeout of `pto_base` after `pto_count` consecutive timeouts
    /// when the growth between two of them is limited to `max_interval`:
    /// exponential backoff while that is shorter than the previous timeout
    /// plus the limit, linear after that. As noq does
    /// (`noq-proto/src/connection/mod.rs`, `pto_time_and_space`), iterating
    /// through the probes instead of one closed form, so a long outage is
    /// probed at a steady pace until the idle timeout. A link whose
    /// `1.5 * smoothed_rtt` exceeds the limit steps by that instead, so the
    /// probes do not fill its pipe.
    fn capped_pto(
        &self,
        pto_base: Duration,
        pto_count: usize,
        smoothed_rtt: Duration,
        max_interval: Duration,
    ) -> Duration {
        let max_interval = cmp::max(max_interval, smoothed_rtt * 3 / 2);
        let steps = cmp::min(self.backoff_factor(pto_count), MAX_PTO_BACKOFF_STEPS);
        let mut duration = pto_base;
        for i in 1..=steps {
            let exponential = pto_base * 2_u32.saturating_pow(cmp::min(i, MAX_BACKOFF_EXPONENT));
            duration = cmp::min(exponential, duration.saturating_add(max_interval));
        }
        cmp::min(duration, self.max_pto)
    }
}

impl LossDetection for Rfc9002 {
    fn name(&self) -> &'static str {
        "tquic-rfc9002"
    }

    fn loss_delay(&self, latest_rtt: Duration, smoothed_rtt: Duration, app_data: bool) -> Duration {
        let eighths = if app_data {
            self.time_thresh_eighths
        } else {
            DEFAULT_TIME_THRESHOLD_EIGHTHS
        };
        let loss_delay = cmp::max(latest_rtt, smoothed_rtt) * (8 + eighths) / 8;
        cmp::max(loss_delay, TIMER_GRANULARITY)
    }

    fn lost_by_reordering(&self, pkt_num: u64, largest_acked: u64, app_data: bool) -> bool {
        if app_data && self.pkt_thresh_disabled {
            return false;
        }
        pkt_num + self.pkt_thresh <= largest_acked
    }

    fn on_app_data_sent(&mut self, pkt_num: u64) {
        self.min_pkt_num_to_relax.get_or_insert(pkt_num);
    }

    fn on_spurious_losses(
        &mut self,
        losses: &[(u64, Duration)],
        latest_rtt: Duration,
        smoothed_rtt: Duration,
    ) {
        if losses.is_empty() {
            return;
        }
        self.pkt_thresh_disabled = true;
        let max_time_reordering = losses
            .iter()
            .filter(|(pkt_num, _)| self.min_pkt_num_to_relax.is_some_and(|min| *pkt_num >= min))
            .map(|(_, reordering)| *reordering)
            .max();
        let loss_delay = self.loss_delay(latest_rtt, smoothed_rtt, true);
        if max_time_reordering.is_some_and(|reordering| reordering > loss_delay)
            && self.time_thresh_eighths < MAX_TIME_THRESHOLD_EIGHTHS
        {
            self.time_thresh_eighths = cmp::min(2 * self.time_thresh_eighths, MAX_TIME_THRESHOLD_EIGHTHS);
            self.min_pkt_num_to_relax = None;
        }
    }

    fn pto(&self, pto_base: Duration, pto_count: usize, smoothed_rtt: Duration) -> Duration {
        if let Some(max_interval) = self.max_pto_interval {
            return self.capped_pto(pto_base, pto_count, smoothed_rtt, max_interval);
        }
        cmp::min(
            pto_base * 2_u32.saturating_pow(self.backoff_factor(pto_count)),
            self.max_pto,
        )
    }

    fn pto_with_ack_delay(
        &self,
        duration: Duration,
        pto_base: Duration,
        max_ack_delay: Duration,
        pto_count: usize,
        smoothed_rtt: Duration,
    ) -> Duration {
        if let Some(max_interval) = self.max_pto_interval {
            return self.capped_pto(
                pto_base + max_ack_delay,
                pto_count,
                smoothed_rtt,
                max_interval,
            );
        }
        cmp::min(
            duration + max_ack_delay * 2_u32.saturating_pow(self.backoff_factor(pto_count)),
            self.max_pto,
        )
    }
}

/// An implementation of the loss detection mechanisms described in
/// RFC 9002 Section 6 and Appendix A.
pub struct Recovery {
    /// The maximum amount of time by which the receiver intends to delay
    /// acknowledgments for packets in the Application Data packet number space.
    /// It is used for PTO calculation.
    pub max_ack_delay: Duration,

    /// The validated maximum size of outgoing UDP payloads in bytes.
    pub max_datagram_size: usize,

    /// Loss thresholds and probe timeout computation.
    loss_detection: Box<dyn LossDetection>,

    /// The number of times a PTO has been sent without receiving an
    /// acknowledgment. It is used for PTO calculation.
    pto_count: usize,

    /// Multi-modal timer used for loss detection. The duration of the timer is
    /// based on the timer's mode, which is set in the packet and timer events.
    loss_detection_timer: Option<Instant>,

    /// The sum of the size in bytes of all sent packets that contain at least
    /// one ack-eliciting or PADDING frame and have not been acknowledged or
    /// declared lost. The size does not include IP or UDP overhead.
    pub bytes_in_flight: usize,

    /// Number of ack-eliciting packets in flight.
    pub ack_eliciting_in_flight: u64,

    /// RTT estimation for the corresponding path.
    pub rtt: RttEstimator,

    /// Congestion controller for the corresponding path.
    pub congestion: Box<dyn CongestionController>,

    /// Pacing.
    pub pacer: Pacer,

    /// Next pacer tick
    pub pacer_timer: Option<Instant>,

    /// Cache pkt size
    pub cache_pkt_size: usize,

    /// The time for last congestion window event
    last_cwnd_limited_time: Option<Instant>,

    /// Path level Statistics.
    pub stats: PathStats,

    /// PMTU black hole detection (RFC 8899 Section 4.3), see
    /// `BlackHoleDetector`.
    black_hole: BlackHoleDetector,

    /// It tracks the last metrics used for emitting qlog RecoveryMetricsUpdated
    /// event.
    #[cfg(feature = "qlog")]
    last_metrics: RecoveryMetrics,

    /// Trace id.
    trace_id: String,
}

/// Maximum number of suspicious loss bursts that will not trigger black hole
/// detection.
const BLACK_HOLE_THRESHOLD: usize = 3;

/// Judges whether packet loss might indicate a drop in PMTU (RFC 8899
/// Section 4.3).
///
/// Ported from Quinn's `BlackHoleDetector` (MIT OR Apache-2.0),
/// quinn-rs/quinn main @ b0afb6e6f, `quinn-proto/src/connection/mtud.rs`,
/// with the packet sizes and packet numbers fed in by TQUIC's loss recovery.
/// Compared with quinn-proto 0.11.12 it includes two upstream commits:
/// a43918cfe (2025-09-29, "Fix some comparisons in the black hole detector")
/// and b0afb6e6f (2026-08-20, #2792, an equal-size delivery counts as
/// evidence against a preceding loss burst).
///
/// The detection scheme is a heuristic based on the order in which packets
/// were sent (the packet number order), their sizes, and which are deemed
/// lost.
///
/// First, contiguous groups of lost packets ("loss bursts") are aggregated,
/// because a group of packets all lost together were probably lost for the
/// same reason.
///
/// A loss burst is deemed "suspicious" if it contains no packets that are (a)
/// not larger than the minimum MTU or (b) not larger than a more recent
/// acknowledged packet, because such a burst could be fully explained by a
/// reduction in MTU.
///
/// When the number of suspicious loss bursts exceeds `BLACK_HOLE_THRESHOLD`,
/// the evidence for a PMTU black hole is judged sufficient.
#[derive(Clone)]
struct BlackHoleDetector {
    /// Packet loss bursts currently considered suspicious.
    suspicious_loss_bursts: Vec<LossBurst>,

    /// Loss burst currently being aggregated, if any.
    current_loss_burst: Option<CurrentLossBurst>,

    /// Packet number of the biggest packet larger than `min_mtu` which we've
    /// received acknowledgment of more recently than any suspicious loss
    /// burst, if any.
    largest_post_loss_packet: u64,

    /// The maximum of `min_mtu` and the size of `largest_post_loss_packet`, or
    /// exactly `min_mtu` if no larger packets have been received since the
    /// most recent loss burst.
    acked_mtu: u16,

    /// The UDP payload size guaranteed to be supported by the network.
    min_mtu: u16,
}

impl BlackHoleDetector {
    fn new(min_mtu: u16) -> Self {
        Self {
            suspicious_loss_bursts: Vec::with_capacity(BLACK_HOLE_THRESHOLD + 1),
            current_loss_burst: None,
            largest_post_loss_packet: 0,
            acked_mtu: min_mtu,
            min_mtu,
        }
    }

    fn on_probe_acked(&mut self, pn: u64, len: u16) {
        // MTU probes are always larger than the previous MTU, so no previous
        // loss bursts are suspicious. At most one MTU probe is in flight at a
        // time, so we don't need to worry about reordering between them.
        self.suspicious_loss_bursts.clear();
        self.acked_mtu = len;
        // This might go backwards, but that's okay: a successful ACK means we
        // haven't yet judged a more recently sent packet lost, and we just
        // want to track the largest packet that's been successfully delivered
        // more recently than a loss.
        self.largest_post_loss_packet = pn;
    }

    fn on_non_probe_acked(&mut self, pn: u64, len: u16) {
        if len < self.acked_mtu {
            // We've already seen a larger packet since the most recent
            // suspicious loss burst; nothing to do.
            return;
        }
        if len == self.acked_mtu {
            // Another delivery of the largest size seen since the most recent
            // suspicious loss burst. It doesn't raise `acked_mtu`, but loss
            // bursts that precede it cannot be explained by an MTU reduction
            // either, so remember it as the newest such delivery.
            self.largest_post_loss_packet = self.largest_post_loss_packet.max(pn);
            return;
        }
        self.acked_mtu = len;
        // This might go backwards, but that's okay as described in
        // `on_probe_acked`.
        self.largest_post_loss_packet = pn;
        // Loss bursts packets smaller than this are retroactively deemed
        // non-suspicious.
        self.suspicious_loss_bursts
            .retain(|burst| burst.smallest_packet_size > len);
    }

    fn on_non_probe_lost(&mut self, pn: u64, len: u16) {
        // A loss burst is a group of consecutive packets that are declared
        // lost, so a distance greater than 1 indicates a new burst.
        let end_last_burst = self
            .current_loss_burst
            .as_ref()
            .is_some_and(|current| pn - current.latest_non_probe != 1);

        if end_last_burst {
            self.finish_loss_burst();
        }

        self.current_loss_burst = Some(CurrentLossBurst {
            latest_non_probe: pn,
            smallest_packet_size: self
                .current_loss_burst
                .map_or(len, |prev| cmp::min(prev.smallest_packet_size, len)),
        });
    }

    fn black_hole_detected(&mut self) -> bool {
        self.finish_loss_burst();

        if self.suspicious_loss_bursts.len() <= BLACK_HOLE_THRESHOLD {
            return false;
        }

        self.suspicious_loss_bursts.clear();

        true
    }

    /// Marks the end of the current loss burst, checking whether it was
    /// suspicious.
    fn finish_loss_burst(&mut self) {
        let Some(burst) = self.current_loss_burst.take() else {
            return;
        };
        // If a loss burst contains a packet smaller than the minimum MTU or a
        // more recently transmitted packet, it is not suspicious.
        if burst.smallest_packet_size <= self.min_mtu
            || (burst.latest_non_probe < self.largest_post_loss_packet
                && burst.smallest_packet_size <= self.acked_mtu)
        {
            return;
        }
        // The loss burst is now deemed suspicious.

        // A suspicious loss burst more recent than `largest_post_loss_packet`
        // invalidates it. This makes `acked_mtu` a conservative approximation.
        // Ideally we'd update `safe_mtu` and `largest_post_loss_packet` to
        // describe the largest acknowledged packet sent later than this
        // burst, but that would require tracking the size of an unpredictable
        // number of recently acknowledged packets, and erring on the side of
        // false positives is safe.
        if burst.latest_non_probe > self.largest_post_loss_packet {
            self.acked_mtu = self.min_mtu;
        }

        let burst = LossBurst {
            smallest_packet_size: burst.smallest_packet_size,
        };

        if self.suspicious_loss_bursts.len() <= BLACK_HOLE_THRESHOLD {
            self.suspicious_loss_bursts.push(burst);
            return;
        }

        // To limit memory use, only track the most suspicious loss bursts.
        let smallest = self
            .suspicious_loss_bursts
            .iter_mut()
            .min_by_key(|prev| prev.smallest_packet_size)
            .filter(|prev| prev.smallest_packet_size < burst.smallest_packet_size);
        if let Some(smallest) = smallest {
            *smallest = burst;
        }
    }

    #[cfg(test)]
    fn suspicious_loss_burst_count(&self) -> usize {
        self.suspicious_loss_bursts.len()
    }

    #[cfg(test)]
    fn largest_non_probe_lost(&self) -> Option<u64> {
        self.current_loss_burst.as_ref().map(|x| x.latest_non_probe)
    }
}

#[derive(Copy, Clone)]
struct LossBurst {
    smallest_packet_size: u16,
}

#[derive(Copy, Clone)]
struct CurrentLossBurst {
    smallest_packet_size: u16,
    latest_non_probe: u64,
}

impl Recovery {
    pub(super) fn new(conf: &RecoveryConfig) -> Self {
        Recovery {
            max_ack_delay: conf.max_ack_delay,
            max_datagram_size: crate::DEFAULT_SEND_UDP_PAYLOAD_SIZE,
            loss_detection: Box::new(Rfc9002::new(conf)),
            pto_count: 0,
            loss_detection_timer: None,
            bytes_in_flight: 0,
            ack_eliciting_in_flight: 0,
            rtt: RttEstimator::new(conf.initial_rtt),
            congestion: congestion_control::build_congestion_controller(conf),
            pacer: Pacer::build_pacer_controller(conf),
            pacer_timer: None,
            cache_pkt_size: conf.max_datagram_size,
            last_cwnd_limited_time: None,
            stats: PathStats::default(),
            black_hole: BlackHoleDetector::new(crate::DEFAULT_SEND_UDP_PAYLOAD_SIZE as u16),
            #[cfg(feature = "qlog")]
            last_metrics: RecoveryMetrics::default(),
            trace_id: String::from(""),
        }
    }

    /// Set trace id.
    pub fn set_trace_id(&mut self, trace_id: &str) {
        self.trace_id = trace_id.to_string();
    }

    /// Handle packet sent event.
    ///
    /// See RFC 9002 Section A.5. On Sending a Packet
    pub(super) fn on_packet_sent(
        &mut self,
        mut pkt: SentPacket,
        space_id: SpaceId,
        spaces: &mut PacketNumSpaceMap,
        handshake_status: HandshakeStatus,
        now: Instant,
    ) {
        let in_flight = pkt.in_flight;
        let ack_eliciting = pkt.ack_eliciting;
        let pacing = pkt.pacing;
        let sent_size = pkt.sent_size;

        pkt.time_sent = now;
        let space = match spaces.get_mut(space_id) {
            Some(space) => space,
            None => return,
        };
        if is_app_data(space_id) {
            self.loss_detection.on_app_data_sent(pkt.pkt_num);
        }
        if in_flight {
            // notify congestion controller of the sent event
            if space_id != SpaceId::Initial && space_id != SpaceId::Handshake {
                self.congestion
                    .on_sent(now, &mut pkt, self.bytes_in_flight as u64);
                trace!(
                    "now={:?} {} {} ON_SENT {:?} inflight={} cwnd={}",
                    now,
                    self.trace_id,
                    self.congestion.name(),
                    pkt,
                    self.bytes_in_flight,
                    self.congestion.congestion_window()
                );
            }
        }
        space.sent.push_back(pkt);

        // An endpoint that sends only non-ack-eliciting packets might not
        // receive an acknowledgment for a long period of time.
        // It should count the number of such packets so as to elicit an ACK
        // from the peer.
        if ack_eliciting {
            space.consecutive_non_ack_eliciting_sent = 0;
        } else {
            space.consecutive_non_ack_eliciting_sent += 1;
        }

        if in_flight {
            if ack_eliciting {
                space.time_of_last_sent_ack_eliciting_pkt = Some(now);
                space.loss_probes = space.loss_probes.saturating_sub(1);
                space.ack_eliciting_in_flight += 1;
                self.ack_eliciting_in_flight += 1;
            }

            space.bytes_in_flight += sent_size;
            self.bytes_in_flight += sent_size;
            self.cache_pkt_size = sent_size;

            self.set_loss_detection_timer(space_id, spaces, handshake_status, now);
        }

        // Update pacing tokens number.
        if pacing {
            self.pacer.on_sent(sent_size as u64);
        }
    }

    /// Handle packet acknowledgment event.
    ///
    /// See RFC 9002 Section A.7. On Receiving an Acknowledgment.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn on_ack_received(
        &mut self,
        ranges: &RangeSet,
        ack_delay: u64,
        space_id: SpaceId,
        spaces: &mut PacketNumSpaceMap,
        handshake_status: HandshakeStatus,
        #[cfg(feature = "qlog")] qlog: Option<&mut qlog::QlogWriter>,
        now: Instant,
    ) -> Result<(u64, u64)> {
        let space = spaces.get_mut(space_id).ok_or(Error::InternalError)?;

        // Update the largest packet number acknowledged in the space
        let largest_acked_pkt = ranges.max().unwrap();
        if space.largest_acked_pkt == u64::MAX {
            space.largest_acked_pkt = largest_acked_pkt;
        } else {
            space.largest_acked_pkt = cmp::max(space.largest_acked_pkt, largest_acked_pkt);
        }

        if space_id != SpaceId::Initial && space_id != SpaceId::Handshake {
            self.congestion.begin_ack(now, self.bytes_in_flight as u64);
        }
        trace!(
            "now={:?} {} {} BEGIN_ACK inflight={} cwnd={}",
            now,
            self.trace_id,
            self.congestion.name(),
            self.bytes_in_flight,
            self.congestion.congestion_window()
        );

        // Detect acked packets
        let mut newly_acked_pkts = Vec::<AckedPacket>::new();
        let mut spuriously_lost = Vec::new();
        let rtt_sample = self.detect_acked_packets(
            ranges,
            space,
            &mut newly_acked_pkts,
            &mut spuriously_lost,
            now,
        );

        // Update RTT estimation
        // TODO: check ack_delay against amx_ack_delay
        if let Some(rtt) = rtt_sample {
            // When adjusting an RTT sample using peer-reported acknowledgment
            // delays, an endpoint:
            // - MAY ignore the acknowledgment delay for Initial packets, since
            // these acknowledgments are not delayed by the peer.
            // - SHOULD ignore the peer's max_ack_delay until the handshake is
            // confirmed.
            // - MUST use the lesser of the acknowledgment delay and the peer's
            // max_ack_delay after the handshake is confirmed;
            // See RFC 9000 Section 5.3
            let ack_delay = Duration::from_micros(ack_delay);
            if !rtt.is_zero() {
                self.rtt.update(ack_delay, rtt);
            }
        }

        if is_app_data(space_id) && !spuriously_lost.is_empty() {
            // When the peer received them: the ACK left after its ack delay.
            let received = now - cmp::min(Duration::from_micros(ack_delay), self.max_ack_delay);
            let losses: Vec<(u64, Duration)> = spuriously_lost
                .iter()
                .map(|(pkt_num, time_sent)| (*pkt_num, received.saturating_duration_since(*time_sent)))
                .collect();
            for (pkt_num, reordering) in &losses {
                trace!(
                    "now={:?} {} {} SPURIOUS_LOSS pn={} time_reordering={:?}",
                    now,
                    self.trace_id,
                    self.congestion.name(),
                    pkt_num,
                    reordering
                );
            }
            self.loss_detection
                .on_spurious_losses(&losses, self.rtt.latest_rtt(), self.rtt.smoothed_rtt());
        }

        if newly_acked_pkts.is_empty() {
            return Ok((0, 0));
        }

        // Detect lost packets
        let (lost_packets, lost_bytes) = self.detect_lost_packets(
            space,
            #[cfg(feature = "qlog")]
            qlog,
            now,
        );

        // Remove acked or lost packets from sent queue in batch.
        self.drain_sent_packets(space, now, self.rtt.smoothed_rtt());

        // Notify the congestion controller of acked event
        if space_id != SpaceId::Initial && space_id != SpaceId::Handshake {
            self.congestion.end_ack();
        }

        self.pto_count = 0;
        self.set_loss_detection_timer(space_id, spaces, handshake_status, now);
        Ok((lost_packets, lost_bytes))
    }

    /// Detect acknowledged packets.
    ///
    /// It return the latest RTT sample, if any. Packets acknowledged after
    /// they were declared lost go to `spuriously_lost` (packet number, time
    /// sent) instead of `newly_acked`.
    fn detect_acked_packets(
        &mut self,
        ranges: &RangeSet,
        space: &mut PacketNumSpace,
        newly_acked: &mut Vec<AckedPacket>,
        spuriously_lost: &mut Vec<(u64, Instant)>,
        now: Instant,
    ) -> Option<Duration> {
        let mut largest_newly_acked_pkt_num = 0;
        let mut largest_newly_acked_sent_time = now;
        let mut newly_ack_eliciting_pkt_acked = false;

        let mut idx = 0;
        'ranges_loop: for r in ranges.iter() {
            'sent_pkt_loop: while idx < space.sent.len() {
                let sent_pkt = space.sent.get_mut(idx).unwrap();
                // Find an unacked sent packet which matches the current ACK range.
                // Note: The packet numbers in ranges and space.sent are in ascending order.
                if sent_pkt.pkt_num < r.start || sent_pkt.time_acked.is_some() {
                    idx += 1;
                    continue 'sent_pkt_loop;
                }
                if sent_pkt.pkt_num >= r.end {
                    continue 'ranges_loop;
                }

                sent_pkt.time_acked = Some(now);
                if sent_pkt.time_lost.is_some() {
                    // A spurious loss (RFC 9002 Section 6.1). The packet left
                    // flight and its frames were queued for retransmission
                    // when it was declared lost; only loss detection learns
                    // from it.
                    spuriously_lost.push((sent_pkt.pkt_num, sent_pkt.time_sent));
                    idx += 1;
                    continue 'sent_pkt_loop;
                }

                // TODO: update rtt.

                largest_newly_acked_pkt_num = sent_pkt.pkt_num;
                largest_newly_acked_sent_time = sent_pkt.time_sent;
                if sent_pkt.ack_eliciting {
                    newly_ack_eliciting_pkt_acked = true
                }
                if is_app_data(space.id) {
                    let len = u16::try_from(sent_pkt.sent_size).unwrap_or(u16::MAX);
                    if sent_pkt.pmtu_probe {
                        self.black_hole.on_probe_acked(sent_pkt.pkt_num, len);
                    } else {
                        self.black_hole.on_non_probe_acked(sent_pkt.pkt_num, len);
                    }
                }

                if sent_pkt.in_flight {
                    space.bytes_in_flight =
                        space.bytes_in_flight.saturating_sub(sent_pkt.sent_size);
                    self.bytes_in_flight = self.bytes_in_flight.saturating_sub(sent_pkt.sent_size);

                    if sent_pkt.ack_eliciting {
                        space.ack_eliciting_in_flight =
                            space.ack_eliciting_in_flight.saturating_sub(1);
                        self.ack_eliciting_in_flight =
                            self.ack_eliciting_in_flight.saturating_sub(1);
                    }
                }

                // Process each acked packet in congestion controller and update delivery
                // rate sample.
                if space.id != SpaceId::Initial && space.id != SpaceId::Handshake {
                    self.congestion.on_ack(
                        sent_pkt,
                        now,
                        false,
                        &self.rtt,
                        self.bytes_in_flight as u64,
                    );
                }

                trace!(
                    "now={:?} {} {} ON_ACK {:?} inflight={} cwnd={}",
                    now,
                    self.trace_id,
                    self.congestion.name(),
                    sent_pkt,
                    self.bytes_in_flight,
                    self.congestion.congestion_window()
                );
                self.stat_acked_event(1, sent_pkt.sent_size as u64);

                space.acked.append(&mut sent_pkt.frames);
                newly_acked.push(AckedPacket {
                    pkt_num: sent_pkt.pkt_num,
                    time_sent: sent_pkt.time_sent,
                    rtt: now.saturating_duration_since(sent_pkt.time_sent),
                });

                // Process next sent packet.
                idx += 1;
                if idx == space.sent.len() {
                    break 'ranges_loop;
                }
            }
        }

        // An endpoint generates an RTT sample on receiving an ACK frame that
        // meets the following two conditions:
        // * the largest acknowledged packet number is newly acknowledged
        // * at least one of the newly acknowledged packets was ack-eliciting
        if largest_newly_acked_pkt_num == space.largest_acked_pkt && newly_ack_eliciting_pkt_acked {
            let latest_rtt = now.saturating_duration_since(largest_newly_acked_sent_time);
            Some(latest_rtt)
        } else {
            None
        }
    }

    /// Check whether in persistent congestion.
    ///
    /// When a sender establishes loss of all packets sent over a long enough duration,
    /// the network is considered to be experiencing persistent congestion.
    /// See https://www.rfc-editor.org/rfc/rfc9002.html#name-persistent-congestion
    fn in_persistent_congestion(&self) -> bool {
        // todo: Check whether in persistent congestion.
        false
    }

    /// Detect lost packets from the sent packets.
    ///
    /// It is called every time an ACK is received or the time threshold loss
    /// detection timer expires.
    /// See RFC 9002 Section A.10. Detecting Lost Packets
    fn detect_lost_packets(
        &mut self,
        space: &mut PacketNumSpace,
        #[cfg(feature = "qlog")] mut qlog: Option<&mut qlog::QlogWriter>,
        now: Instant,
    ) -> (u64, u64) {
        space.loss_time = None;

        let mut lost_packets = 0;
        let mut lost_bytes = 0;
        let mut lost_probe_bytes = 0;
        let mut latest_lost_packet = None;

        let app_data = is_app_data(space.id);
        let loss_delay =
            self.loss_detection
                .loss_delay(self.rtt.latest_rtt(), self.rtt.smoothed_rtt(), app_data);
        let lost_send_time = now - loss_delay;

        let unacked_iter = space
            .sent
            .iter_mut()
            .take_while(|p| p.pkt_num <= space.largest_acked_pkt)
            .filter(|p| p.time_acked.is_none() && p.time_lost.is_none());
        for unacked in unacked_iter {
            // A packet is declared lost if it meets all of the following
            // conditions:
            // * The packet is unacknowledged, in flight, and was sent prior to
            //   an acknowledged packet.
            // * The packet was sent kPacketThreshold packets before an
            //   acknowledged packet, or it was sent long enough in the past.
            // See RFC 9002 Section 6.1
            if unacked.time_sent <= lost_send_time
                || self
                    .loss_detection
                    .lost_by_reordering(unacked.pkt_num, space.largest_acked_pkt, app_data)
            {
                space.lost.append(&mut unacked.frames);
                unacked.time_lost = Some(now);
                if app_data && !unacked.pmtu_probe {
                    let len = u16::try_from(unacked.sent_size).unwrap_or(u16::MAX);
                    self.black_hole.on_non_probe_lost(unacked.pkt_num, len);
                }

                lost_packets += 1;
                if unacked.in_flight {
                    lost_bytes += unacked.sent_size as u64;
                    if unacked.pmtu_probe {
                        lost_probe_bytes += unacked.sent_size as u64;
                    }
                    space.bytes_in_flight = space.bytes_in_flight.saturating_sub(unacked.sent_size);
                    self.bytes_in_flight = self.bytes_in_flight.saturating_sub(unacked.sent_size);

                    if unacked.ack_eliciting {
                        space.ack_eliciting_in_flight =
                            space.ack_eliciting_in_flight.saturating_sub(1);
                        self.ack_eliciting_in_flight =
                            self.ack_eliciting_in_flight.saturating_sub(1);
                    }
                }
                // Loss of a QUIC packet that is carried in a PMTU probe is not
                // a reliable indication of congestion and SHOULD NOT trigger a
                // congestion control reaction
                if !unacked.pmtu_probe {
                    latest_lost_packet = Some(unacked.clone());
                }
                #[cfg(feature = "qlog")]
                if let Some(qlog) = qlog.as_mut() {
                    self.qlog_recovery_packet_lost(qlog, unacked);
                }
                trace!(
                    "now={:?} {} {} ON_LOST {:?} inflight={} cwnd={}",
                    now,
                    self.trace_id,
                    self.congestion.name(),
                    unacked,
                    self.bytes_in_flight,
                    self.congestion.congestion_window()
                );
            } else {
                let loss_time = match space.loss_time {
                    None => unacked.time_sent + loss_delay,
                    Some(loss_time) => cmp::min(loss_time, unacked.time_sent + loss_delay),
                };
                space.loss_time = Some(loss_time);
            }
        }

        // Notify congestion controller of the lost event
        if let Some(lost_packet) = latest_lost_packet {
            if space.id != SpaceId::Initial && space.id != SpaceId::Handshake {
                self.congestion.on_congestion_event(
                    now,
                    &lost_packet,
                    self.in_persistent_congestion(),
                    lost_bytes,
                    self.bytes_in_flight as u64,
                );
                trace!(
                    "now={:?} {} {} ON_CONGESTION_EVENT lost_size={} inflight={} cwnd={}",
                    now,
                    self.trace_id,
                    self.congestion.name(),
                    lost_bytes,
                    self.bytes_in_flight,
                    self.congestion.congestion_window()
                );
            }
        }

        self.stat_lost_event(lost_packets, lost_bytes);
        self.stats.lost_data_bytes = self
            .stats
            .lost_data_bytes
            .saturating_add(lost_bytes - lost_probe_bytes);
        (lost_packets, lost_bytes)
    }

    // Remove acked or lost packet from the packet sent queue in batch.
    //
    // Removing packets from the middle would require copying to compact the vec.
    // So it only remove a contiguous range of packets from the start of the vec.
    fn drain_sent_packets(&mut self, space: &mut PacketNumSpace, now: Instant, rtt: Duration) {
        let mut lowest_non_expired_pkt_index = space.sent.len();
        for (i, pkt) in space.sent.iter().enumerate() {
            // find the first element that is neither acked nor lost.
            if pkt.time_acked.is_none() && pkt.time_lost.is_none() {
                lowest_non_expired_pkt_index = i;
                break;
            }
            if let Some(time_lost) = pkt.time_lost {
                if time_lost + rtt > now {
                    lowest_non_expired_pkt_index = i;
                    break;
                }
            }
        }
        space.sent.drain(..lowest_non_expired_pkt_index);
    }

    // Set timer for loss detection.
    //
    // See RFC 9002 A.8. Setting the Loss Detection Timer
    fn set_loss_detection_timer(
        &mut self,
        space_id: SpaceId,
        spaces: &mut PacketNumSpaceMap,
        handshake_status: HandshakeStatus,
        now: Instant,
    ) {
        // Loss timer.
        let (earliest_loss_time, _) = self.get_loss_time_and_space(space_id, spaces);
        if earliest_loss_time.is_some() {
            // Time threshold loss detection.
            self.loss_detection_timer = earliest_loss_time;
            return;
        }

        // TODO: The server's timer is not set if nothing can be sent.

        if self.ack_eliciting_in_flight == 0 && handshake_status.peer_verified_address {
            // There is nothing to detect lost, so no timer is set.
            // However, the client needs to arm the timer if the
            // server might be blocked by the anti-amplification limit.
            self.loss_detection_timer = None;
            return;
        }

        // PTO timer.
        let (timeout, _) = self.get_pto_time_and_space(space_id, spaces, handshake_status, now);
        self.loss_detection_timer = timeout;
    }

    /// Consecutive PTOs without an acknowledgment on this path.
    pub(super) fn pto_count(&self) -> usize {
        self.pto_count
    }

    /// Whether the loss history indicates a PMTU black hole, see
    /// `BlackHoleDetector`. Consumes the evidence.
    pub(super) fn take_pmtu_black_hole(&mut self) -> bool {
        self.black_hole.black_hole_detected()
    }

    /// Return expiration time of loss timer
    pub(super) fn loss_detection_timer(&self) -> Option<Instant> {
        self.loss_detection_timer
    }

    /// Handles timeout event.
    ///
    /// When the loss detection timer expires, the timer's mode determines the
    /// action to be performed.
    /// See RFC 9002 Section A.10. On Timeout
    pub(super) fn on_loss_detection_timeout(
        &mut self,
        space_id: SpaceId,
        spaces: &mut PacketNumSpaceMap,
        handshake_status: HandshakeStatus,
        #[cfg(feature = "qlog")] qlog: Option<&mut qlog::QlogWriter>,
        now: Instant,
    ) -> (u64, u64) {
        let (earliest_loss_time, sid) = self.get_loss_time_and_space(space_id, spaces);
        let space = match spaces.get_mut(sid) {
            Some(space) => space,
            None => return (0, 0),
        };

        // Loss timer mode
        if earliest_loss_time.is_some() {
            // Time threshold loss detection.
            let (lost_packets, lost_bytes) = self.detect_lost_packets(
                space,
                #[cfg(feature = "qlog")]
                qlog,
                now,
            );
            self.drain_sent_packets(space, now, self.rtt.smoothed_rtt());
            self.set_loss_detection_timer(space_id, spaces, handshake_status, now);
            return (lost_packets, lost_bytes);
        }

        // PTO timer mode
        let sid = if self.ack_eliciting_in_flight > 0 {
            // Send new data if available, else retransmit old data. If neither
            // is available, send a single PING frame.
            let (_, e) = self.get_pto_time_and_space(space_id, spaces, handshake_status, now);
            e
        } else {
            // Client sends an anti-deadlock packet: Initial is padded to earn
            // more anti-amplification credit, a Handshake packet proves address
            // ownership.
            if handshake_status.derived_handshake_keys {
                Handshake
            } else {
                Initial
            }
        };
        let space = match spaces.get_mut(sid) {
            Some(space) => space,
            None => return (0, 0),
        };
        self.pto_count += 1;

        space.loss_probes = match sid {
            Initial | Handshake => 1,
            _ => cmp::min(self.pto_count, MAX_PTO_PROBES_COUNT),
        };

        // An endpoint SHOULD include new data in packets that are sent on PTO
        // expiration. Previously sent data MAY be sent if no new data can be
        // sent. However, we only try to retransmit the oldest unacked data.
        let unacked_iter = space
            .sent
            .iter_mut()
            .filter(|p| p.has_data && p.time_acked.is_none() && p.time_lost.is_none())
            .take(space.loss_probes);

        for unacked in unacked_iter {
            // A PTO timer expiration event does not indicate packet loss and
            // MUST NOT cause prior unacknowledged packets to be marked as lost.
            // DATAGRAM frames are never retransmitted, so they are skipped.
            space.lost.extend(
                unacked
                    .frames
                    .iter()
                    .filter(|f| !matches!(f, frame::Frame::Datagram { .. }))
                    .cloned(),
            );
        }

        self.set_loss_detection_timer(space_id, spaces, handshake_status, now);
        (0, 0)
    }

    /// Return the min loss time and the corresponding space
    fn get_loss_time_and_space(
        &mut self,
        space_id: SpaceId,
        spaces: &PacketNumSpaceMap,
    ) -> (Option<Instant>, SpaceId) {
        let candidates = if space_id != Initial && space_id != Handshake {
            [Initial, Handshake, space_id]
        } else {
            [Initial, Handshake, Data]
        };

        let mut sid = Initial;
        let mut time = None;
        for s in candidates {
            let space = match spaces.get(s) {
                Some(space) => space,
                None => continue,
            };
            let new_time = space.loss_time;
            if time.is_none() || (new_time.is_some() && new_time < time) {
                time = new_time;
                sid = s;
            }
        }

        (time, sid)
    }

    /// Calculate the probe timeout.
    fn calculate_pto(&self) -> Duration {
        self.loss_detection
            .pto(self.rtt.pto_base(), self.pto_count, self.rtt.smoothed_rtt())
    }

    /// Calculate the probe timeout include `max_ack_delay`.
    fn pto_with_ack_delay(&self, duration: Duration) -> Duration {
        self.loss_detection.pto_with_ack_delay(
            duration,
            self.rtt.pto_base(),
            self.max_ack_delay,
            self.pto_count,
            self.rtt.smoothed_rtt(),
        )
    }

    /// Name of the loss detection in use.
    pub(crate) fn loss_detection_name(&self) -> &'static str {
        self.loss_detection.name()
    }

    /// Return the min pto time and the corresponding space
    fn get_pto_time_and_space(
        &self,
        space_id: SpaceId,
        spaces: &mut PacketNumSpaceMap,
        handshake_status: HandshakeStatus,
        now: Instant,
    ) -> (Option<Instant>, SpaceId) {
        let mut duration = self.calculate_pto();

        // Arm PTO from now when there are no ack-eliciting packets inflight.
        if self.ack_eliciting_in_flight == 0 {
            if handshake_status.derived_handshake_keys {
                return (Some(now + duration), SpaceId::Handshake);
            } else {
                return (Some(now + duration), SpaceId::Initial);
            }
        }

        let candidates = if space_id != Initial && space_id != Handshake {
            [Initial, Handshake, space_id]
        } else {
            [Initial, Handshake, Data]
        };

        let mut pto_timeout = None;
        let mut pto_space = Initial;

        for sid in candidates {
            let space = match spaces.get_mut(sid) {
                Some(space) => space,
                None => continue,
            };
            if space.ack_eliciting_in_flight == 0 {
                continue;
            }

            if sid == Data {
                // An endpoint MUST NOT set its PTO timer for the Application
                // Data packet number space until the handshake is confirmed.
                if !handshake_status.completed {
                    return (pto_timeout, pto_space);
                }
                // Include max_ack_delay and backoff for Application Data.
                duration = self.pto_with_ack_delay(duration);
            }

            let new_time = space
                .time_of_last_sent_ack_eliciting_pkt
                .map(|t| t + duration);
            if pto_timeout.is_none() || new_time < pto_timeout {
                pto_timeout = new_time;
                pto_space = sid;
            }
        }
        (pto_timeout, pto_space)
    }

    /// Handles event of dropping Initial or Handshake keys
    ///
    /// When Initial or Handshake keys are discarded, packets from the space
    /// are discarded and loss detection state is updated.
    /// See RFC 9002 Section A.11. Upon Dropping Initial or Handshake keys
    pub(super) fn on_pkt_num_space_discarded(
        &mut self,
        space_id: SpaceId,
        spaces: &mut PacketNumSpaceMap,
        handshake_status: HandshakeStatus,
        now: Instant,
    ) {
        let space = match spaces.get_mut(space_id) {
            Some(space) => space,
            None => return,
        };

        // Removing discarded packets from bytes in flight
        self.remove_from_bytes_in_flight(space);

        // Clear packet queue
        space.sent.clear();
        space.lost.clear();
        space.acked.clear();

        // Reset loss detection timer
        space.time_of_last_sent_ack_eliciting_pkt = None;
        space.loss_time = None;
        space.loss_probes = 0;
        space.bytes_in_flight = 0;
        space.ack_eliciting_in_flight = 0;
        self.set_loss_detection_timer(space_id, spaces, handshake_status, now);
    }

    /// Removing Discarded Packets from Bytes in Flight
    ///
    /// When Initial or Handshake keys are discarded, packets sent in that
    /// space no longer count toward bytes in flight.
    fn remove_from_bytes_in_flight(&mut self, space: &PacketNumSpace) {
        for pkt in &space.sent {
            if !pkt.in_flight || pkt.time_acked.is_some() || pkt.time_lost.is_some() {
                continue;
            }

            self.bytes_in_flight = self.bytes_in_flight.saturating_sub(pkt.sent_size);
            if pkt.ack_eliciting {
                self.ack_eliciting_in_flight = self.ack_eliciting_in_flight.saturating_sub(1);
            }
        }
    }

    /// Update maximum datagram size
    ///
    /// If `is_upper` is true, `max_datagram_size` is the upper limit of maximum datagram size.
    /// If `is_upper` is false, `max_datagram_size` is the new maximum datagram size.
    pub(super) fn update_max_datagram_size(
        &mut self,
        mut max_datagram_size: usize,
        is_upper: bool,
    ) {
        if is_upper {
            max_datagram_size = cmp::min(self.max_datagram_size, max_datagram_size);
        }

        // The pacer is handed `max_datagram_size` on every `schedule` call.
        self.congestion.set_max_datagram_size(max_datagram_size as u64);

        self.max_datagram_size = max_datagram_size;
    }

    /// Check whether this path can still send packets.
    pub(crate) fn can_send(&mut self) -> bool {
        // Check congestion controller
        if self.bytes_in_flight >= self.congestion.congestion_window() as usize {
            trace!(
                "{} sending is limited by congestion controller, inflight {}, window {}",
                self.trace_id,
                self.bytes_in_flight,
                self.congestion.congestion_window()
            );
            return false;
        }

        // Check pacer
        if self.pacer.enabled() && !self.can_pacing() {
            trace!(
                "{} sending is limited by pacer, pacing timer {:?}",
                self.trace_id,
                self.pacer_timer
                    .map(|t| t.saturating_duration_since(Instant::now()))
            );
            return false;
        }

        true
    }

    /// The connection has nothing more to send on this path. If neither the
    /// congestion window nor the pacer held it back, the path is
    /// application-limited (draft-cheng-iccrg-delivery-rate-estimation
    /// Section 3.4): the congestion controller must not read the delivery
    /// rate of what is in flight now as the path's bandwidth.
    pub(crate) fn on_nothing_to_send(&mut self) {
        let window_limited = self.bytes_in_flight >= self.congestion.congestion_window() as usize;
        let pacing_limited =
            self.pacer.enabled() && self.pacer_timer.is_some_and(|t| t > Instant::now());
        if !window_limited && !pacing_limited {
            self.congestion.on_app_limited();
        }
    }

    /// Whether the pacer allows sending now, ignoring the congestion window.
    pub(crate) fn can_pace(&mut self) -> bool {
        !self.pacer.enabled() || self.can_pacing()
    }

    fn can_pacing(&mut self) -> bool {
        let now = time::Instant::now();
        let cwnd = self.congestion.congestion_window();
        let srtt = self.rtt.smoothed_rtt() as Duration;

        if let Some(pr) = self.congestion.pacing_rate() {
            self.pacer_timer = self.pacer.schedule(
                self.cache_pkt_size as u64,
                pr,
                srtt,
                cwnd,
                self.max_datagram_size as u64,
                now,
            );
        }

        self.pacer_timer.is_none()
    }

    /// Update statistics for the packet sent event
    pub(crate) fn stat_sent_event(&mut self, sent_pkts: u64, sent_bytes: u64) {
        self.stats.sent_count = self.stats.sent_count.saturating_add(sent_pkts);
        self.stats.sent_bytes = self.stats.sent_bytes.saturating_add(sent_bytes);
        self.stat_cwnd_updated();
    }

    /// Update statistics for the packet recv event
    pub(crate) fn stat_recv_event(&mut self, recv_pkts: u64, recv_bytes: u64) {
        self.stats.recv_count = self.stats.recv_count.saturating_add(recv_pkts);
        self.stats.recv_bytes = self.stats.recv_bytes.saturating_add(recv_bytes);
    }

    /// Update statistics for the packet acked event
    pub(crate) fn stat_acked_event(&mut self, acked_pkts: u64, acked_bytes: u64) {
        self.stats.acked_count = self.stats.acked_count.saturating_add(acked_pkts);
        self.stats.acked_bytes = self.stats.acked_bytes.saturating_add(acked_bytes);
    }

    /// Update statistics for the packet loss event
    pub(crate) fn stat_lost_event(&mut self, lost_pkts: u64, lost_bytes: u64) {
        self.stats.lost_count = self.stats.lost_count.saturating_add(lost_pkts);
        self.stats.lost_bytes = self.stats.lost_bytes.saturating_add(lost_bytes);
    }

    /// Update statistics for the congestion_window
    pub(crate) fn stat_cwnd_updated(&mut self) {
        let cwnd = self.congestion.congestion_window();
        if self.stats.init_cwnd == 0 {
            self.stats.init_cwnd = cwnd;
            self.stats.min_cwnd = cwnd;
            self.stats.max_cwnd = cwnd;
        }
        self.stats.final_cwnd = cwnd;
        if self.stats.max_cwnd < cwnd {
            self.stats.max_cwnd = cwnd;
        }
        if self.stats.min_cwnd > cwnd {
            self.stats.min_cwnd = cwnd;
        }
        let bytes_in_flight = self.bytes_in_flight as u64;
        if self.stats.max_inflight < bytes_in_flight {
            self.stats.max_inflight = bytes_in_flight;
        }
    }

    /// Update statistics for the congestion window limited event
    pub(crate) fn stat_cwnd_limited(&mut self) {
        let is_cwnd_limited = self.bytes_in_flight >= self.congestion.congestion_window() as usize;
        let now = Instant::now();
        if let Some(last_cwnd_limited_time) = self.last_cwnd_limited_time {
            // Update duration timely, in case it stays in cwnd limited all the time.
            let duration = now.saturating_duration_since(last_cwnd_limited_time);
            let duration = duration.as_millis() as u64;
            self.stats.cwnd_limited_duration =
                self.stats.cwnd_limited_duration.saturating_add(duration);
            if is_cwnd_limited {
                self.last_cwnd_limited_time = Some(now);
            } else {
                self.last_cwnd_limited_time = None;
            }
        } else if is_cwnd_limited {
            // A new cwnd limited event
            self.stats.cwnd_limited_count = self.stats.cwnd_limited_count.saturating_add(1);
            self.last_cwnd_limited_time = Some(now);
        }
    }

    /// Update with the latest values from recovery.
    pub(crate) fn stat_lazy_update(&mut self) {
        self.stats.min_rtt = self.rtt.min_rtt().as_micros() as u64;
        self.stats.windowed_min_rtt = self.rtt.windowed_min_rtt().as_micros() as u64;
        self.stats.max_rtt = self.rtt.max_rtt().as_micros() as u64;
        self.stats.srtt = self.rtt.smoothed_rtt().as_micros() as u64;
        self.stats.rttvar = self.rtt.rttvar().as_micros() as u64;
        self.stats.in_slow_start = self.congestion.in_slow_start();
        self.stats.pacing_rate = self.congestion.pacing_rate().unwrap_or_default();
        self.stats.min_pacing_rate = self.congestion.min_pacing_rate().unwrap_or_default();
        match self.congestion.bandwidth_metrics() {
            Some(metrics) => {
                self.stats.bandwidth_model_valid = true;
                self.stats.btlbw = metrics.btlbw;
                self.stats.latest_delivery_rate = metrics.latest_delivery_rate;
                self.stats.delivery_rate_sample_app_limited = metrics.sample_app_limited;
                self.stats.congestion_control_state = metrics.state;
                match metrics.sample_time {
                    Some(sample_time) => {
                        self.stats.delivery_rate_sample_time_valid = true;
                        self.stats.delivery_rate_sample_age = Instant::now()
                            .saturating_duration_since(sample_time)
                            .as_micros()
                            as u64;
                    }
                    None => {
                        self.stats.delivery_rate_sample_time_valid = false;
                        self.stats.delivery_rate_sample_age = 0;
                    }
                }
            }
            None => {
                self.stats.bandwidth_model_valid = false;
                self.stats.btlbw = 0;
                self.stats.latest_delivery_rate = 0;
                self.stats.delivery_rate_sample_app_limited = false;
                self.stats.delivery_rate_sample_time_valid = false;
                self.stats.delivery_rate_sample_age = 0;
                self.stats.congestion_control_state = crate::CongestionControlState::Unknown;
            }
        }
        self.stats.pto_count = self.pto_count as u64;
    }

    /// Write a qlog RecoveryMetricsUpdated event if any recovery metric is updated.
    #[cfg(feature = "qlog")]
    pub(crate) fn qlog_recovery_metrics_updated(&mut self, qlog: &mut qlog::QlogWriter) {
        let mut updated = false;

        let mut min_rtt = None;
        if self.last_metrics.min_rtt != self.rtt.min_rtt() {
            self.last_metrics.min_rtt = self.rtt.min_rtt();
            min_rtt = Some(self.last_metrics.min_rtt.as_secs_f32() * 1000.0);
            updated = true;
        }

        let mut smoothed_rtt = None;
        if self.last_metrics.smoothed_rtt != self.rtt.smoothed_rtt() {
            self.last_metrics.smoothed_rtt = self.rtt.smoothed_rtt();
            smoothed_rtt = Some(self.last_metrics.smoothed_rtt.as_secs_f32() * 1000.0);
            updated = true;
        }

        let mut latest_rtt = None;
        if self.last_metrics.latest_rtt != self.rtt.latest_rtt() {
            self.last_metrics.latest_rtt = self.rtt.latest_rtt();
            latest_rtt = Some(self.last_metrics.latest_rtt.as_secs_f32() * 1000.0);
            updated = true;
        }

        let mut rtt_variance = None;
        if self.last_metrics.rttvar != self.rtt.rttvar() {
            self.last_metrics.rttvar = self.rtt.rttvar();
            rtt_variance = Some(self.last_metrics.rttvar.as_secs_f32() * 1000.0);
            updated = true;
        }

        let mut congestion_window = None;
        if self.last_metrics.cwnd != self.congestion.congestion_window() {
            self.last_metrics.cwnd = self.congestion.congestion_window();
            congestion_window = Some(self.last_metrics.cwnd);
            updated = true;
        }

        let mut bytes_in_flight = None;
        if self.last_metrics.bytes_in_flight != self.bytes_in_flight as u64 {
            self.last_metrics.bytes_in_flight = self.bytes_in_flight as u64;
            bytes_in_flight = Some(self.last_metrics.bytes_in_flight);
            updated = true;
        }

        let mut pacing_rate = None;
        if self.last_metrics.pacing_rate != self.congestion.pacing_rate() {
            self.last_metrics.pacing_rate = self.congestion.pacing_rate();
            pacing_rate = self.last_metrics.pacing_rate.map(|v| v * 8); // bps
            updated = true;
        }

        if !updated {
            return;
        }

        let ev_data = EventData::RecoveryMetricsUpdated {
            min_rtt,
            smoothed_rtt,
            latest_rtt,
            rtt_variance,
            pto_count: None,
            congestion_window,
            bytes_in_flight,
            ssthresh: None,
            packets_in_flight: None,
            pacing_rate,
        };
        qlog.add_event_data(Instant::now(), ev_data).ok();
    }

    /// Write a qlog RecoveryPacketLost event.
    #[cfg(feature = "qlog")]
    pub(crate) fn qlog_recovery_packet_lost(
        &mut self,
        qlog: &mut qlog::QlogWriter,
        pkt: &SentPacket,
    ) {
        let ev_data = EventData::RecoveryPacketLost {
            header: Some(qlog::events::PacketHeader {
                packet_type: pkt.pkt_type.to_qlog(),
                packet_number: pkt.pkt_num,
                ..qlog::events::PacketHeader::default()
            }),
            frames: None,
            is_mtu_probe_packet: None,
            trigger: None,
        };
        qlog.add_event_data(Instant::now(), ev_data).ok();
    }
}

/// Metrics used for emitting qlog RecoveryMetricsUpdated event.
#[cfg(feature = "qlog")]
#[derive(Default)]
struct RecoveryMetrics {
    /// The minimum RTT observed on the path, ignoring ack delay
    min_rtt: Duration,

    /// The smoothed RTT of the path is an exponentially weighted moving average
    /// of an endpoint's RTT samples
    smoothed_rtt: Duration,

    /// The most recent RTT sample.
    latest_rtt: Duration,

    /// The RTT variance estimates the variation in the RTT samples using a
    /// mean variation
    rttvar: Duration,

    /// Congestion window in bytes.
    cwnd: u64,

    /// Total number of bytes in fight.
    bytes_in_flight: u64,

    /// Pacing rate in Bps
    pacing_rate: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::congestion_control::CongestionControlAlgorithm;
    use crate::connection::space::RateSamplePacketState;
    use crate::ranges::RangeSet;
    use std::time::Duration;
    use std::time::Instant;

    fn new_test_sent_packet(pkt_num: u64, sent_size: usize, now: Instant) -> SentPacket {
        SentPacket {
            pkt_num,
            frames: vec![],
            time_sent: now,
            time_acked: None,
            time_lost: None,
            sent_size,
            ack_eliciting: true,
            in_flight: true,
            has_data: true,
            rate_sample_state: Default::default(),
            ..SentPacket::default()
        }
    }

    fn new_test_recovery_config() -> RecoveryConfig {
        RecoveryConfig {
            max_datagram_size: 1200,
            max_ack_delay: Duration::from_millis(100),
            congestion_control_algorithm: CongestionControlAlgorithm::Bbr,
            min_congestion_window: 2_u64,
            initial_congestion_window: 10_u64,
            initial_rtt: crate::INITIAL_RTT,
            pto_linear_factor: crate::DEFAULT_PTO_LINEAR_FACTOR,
            max_pto: crate::MAX_PTO,
            ..RecoveryConfig::default()
        }
    }

    #[test]
    fn loss_on_timeout() -> Result<()> {
        let conf = new_test_recovery_config();
        let mut recovery = Recovery::new(&conf);
        let mut spaces = PacketNumSpaceMap::new();
        let space_id = SpaceId::Handshake;
        let status = HandshakeStatus {
            derived_handshake_keys: true,
            peer_verified_address: true,
            completed: false,
        };
        let mut now = Instant::now();

        // Fake sending of packet 0
        let sent_pkt0 = new_test_sent_packet(0, 1000, now);
        recovery.on_packet_sent(sent_pkt0, space_id, &mut spaces, status, now);
        assert_eq!(spaces.get(space_id).unwrap().sent.len(), 1);
        assert_eq!(spaces.get(space_id).unwrap().bytes_in_flight, 1000);
        assert_eq!(recovery.bytes_in_flight, 1000);

        // Fake sending of packet 1
        let sent_pkt1 = new_test_sent_packet(1, 1001, now);
        recovery.on_packet_sent(sent_pkt1, space_id, &mut spaces, status, now);
        assert_eq!(spaces.get(space_id).unwrap().sent.len(), 2);
        assert_eq!(spaces.get(space_id).unwrap().bytes_in_flight, 2001);
        assert_eq!(recovery.bytes_in_flight, 2001);

        // Fake sending of packet 2
        let sent_pkt2 = new_test_sent_packet(2, 1002, now);
        recovery.on_packet_sent(sent_pkt2, space_id, &mut spaces, status, now);
        assert_eq!(spaces.get(space_id).unwrap().sent.len(), 3);
        assert_eq!(spaces.get(space_id).unwrap().bytes_in_flight, 3003);
        assert_eq!(spaces.get(space_id).unwrap().ack_eliciting_in_flight, 3);
        assert_eq!(recovery.bytes_in_flight, 3003);
        assert_eq!(recovery.ack_eliciting_in_flight, 3);

        // Advance ticks and fake receiving of ack
        now += Duration::from_millis(100);
        let mut acked = RangeSet::default();
        acked.insert(0..1);
        acked.insert(2..3);
        recovery.on_ack_received(
            &acked,
            0,
            SpaceId::Handshake,
            &mut spaces,
            status,
            #[cfg(feature = "qlog")]
            None,
            now,
        )?;
        assert_eq!(spaces.get(space_id).unwrap().sent.len(), 2);
        assert_eq!(spaces.get(space_id).unwrap().ack_eliciting_in_flight, 1);
        assert_eq!(recovery.ack_eliciting_in_flight, 1);

        // Advance ticks until loss timeout
        now = recovery.loss_detection_timer().unwrap();
        let (lost_pkts, lost_bytes) = recovery.on_loss_detection_timeout(
            SpaceId::Handshake,
            &mut spaces,
            status,
            #[cfg(feature = "qlog")]
            None,
            now,
        );
        assert_eq!(lost_pkts, 1);
        assert_eq!(lost_bytes, 1001);
        assert_eq!(spaces.get(space_id).unwrap().ack_eliciting_in_flight, 0);
        assert_eq!(recovery.ack_eliciting_in_flight, 0);

        Ok(())
    }

    // A congestion loss burst of six large packets, followed only by
    // acknowledged small packets, is one loss burst and not a PMTU black hole.
    #[test]
    fn pmtu_black_hole_single_large_loss_burst_is_not_a_black_hole() -> Result<()> {
        let status = HandshakeStatus {
            derived_handshake_keys: true,
            peer_verified_address: true,
            completed: true,
        };
        let conf = new_test_recovery_config();
        let mut recovery = Recovery::new(&conf);
        let mut spaces = PacketNumSpaceMap::new();
        let space_id = SpaceId::Data;
        let mut now = Instant::now();
        for pkt_num in 0..6 {
            let pkt = new_test_sent_packet(pkt_num, 1400, now);
            recovery.on_packet_sent(pkt, space_id, &mut spaces, status, now);
        }
        for pkt_num in 6..10 {
            let pkt = new_test_sent_packet(pkt_num, 1000, now);
            recovery.on_packet_sent(pkt, space_id, &mut spaces, status, now);
        }

        now += Duration::from_millis(100);
        let mut acked = RangeSet::default();
        acked.insert(6..10);
        let (lost_pkts, _) = recovery.on_ack_received(
            &acked,
            0,
            space_id,
            &mut spaces,
            status,
            #[cfg(feature = "qlog")]
            None,
            now,
        )?;
        assert_eq!(lost_pkts, 6);
        assert!(!recovery.take_pmtu_black_hole());
        Ok(())
    }

    // The tests below are ported from Quinn's `BlackHoleDetector` tests
    // (`quinn-proto/src/connection/mtud.rs`, MIT OR Apache-2.0), with the
    // detector driven directly.

    #[test]
    fn black_hole_detector_ignores_burst_containing_non_suspicious_packet() {
        let mut bhd = BlackHoleDetector::new(1200);
        bhd.on_non_probe_lost(2, 1300);
        bhd.on_non_probe_lost(3, 1300);
        assert_eq!(bhd.largest_non_probe_lost(), Some(3));
        assert_eq!(bhd.suspicious_loss_burst_count(), 0);

        bhd.on_non_probe_lost(4, 800);
        assert!(!bhd.black_hole_detected());
        assert_eq!(bhd.largest_non_probe_lost(), None);
        assert_eq!(bhd.suspicious_loss_burst_count(), 0);
    }

    #[test]
    fn black_hole_detector_counts_burst_containing_only_suspicious_packets() {
        let mut bhd = BlackHoleDetector::new(1200);
        bhd.on_non_probe_lost(2, 1300);
        bhd.on_non_probe_lost(3, 1300);
        assert_eq!(bhd.largest_non_probe_lost(), Some(3));
        assert_eq!(bhd.suspicious_loss_burst_count(), 0);

        assert!(!bhd.black_hole_detected());
        assert_eq!(bhd.largest_non_probe_lost(), None);
        assert_eq!(bhd.suspicious_loss_burst_count(), 1);
    }

    #[test]
    fn black_hole_detector_ignores_empty_burst() {
        let mut bhd = BlackHoleDetector::new(1200);
        assert!(!bhd.black_hole_detected());
        assert_eq!(bhd.suspicious_loss_burst_count(), 0);
    }

    // Loss of packets larger than have been acknowledged should indicate a
    // black hole.
    #[test]
    fn simple_black_hole_detection() {
        let mut bhd = BlackHoleDetector::new(1200);
        bhd.on_non_probe_acked((BLACK_HOLE_THRESHOLD + 1) as u64 * 2, 1300);
        for i in 0..BLACK_HOLE_THRESHOLD {
            bhd.on_non_probe_lost(i as u64 * 2, 1400);
        }
        // But not before `BLACK_HOLE_THRESHOLD + 1` bursts.
        assert!(!bhd.black_hole_detected());
        bhd.on_non_probe_lost(BLACK_HOLE_THRESHOLD as u64 * 2, 1400);
        assert!(bhd.black_hole_detected());
    }

    // Loss of packets followed in transmission order by confirmation of a
    // larger packet should not indicate a black hole.
    #[test]
    fn non_suspicious_bursts() {
        let mut bhd = BlackHoleDetector::new(1200);
        bhd.on_non_probe_acked((BLACK_HOLE_THRESHOLD + 1) as u64 * 2, 1500);
        for i in 0..(BLACK_HOLE_THRESHOLD + 1) {
            bhd.on_non_probe_lost(i as u64 * 2, 1400);
        }
        assert!(!bhd.black_hole_detected());
    }

    // Loss of packets smaller than have been acknowledged previously should
    // still indicate a black hole.
    #[test]
    fn dynamic_mtu_reduction() {
        let mut bhd = BlackHoleDetector::new(1200);
        bhd.on_non_probe_acked(0, 1500);
        for i in 0..(BLACK_HOLE_THRESHOLD + 1) {
            bhd.on_non_probe_lost(i as u64 * 2, 1400);
        }
        assert!(bhd.black_hole_detected());
    }

    // Bursts containing heterogeneous packets are judged based on the
    // smallest.
    #[test]
    fn mixed_non_suspicious_bursts() {
        let mut bhd = BlackHoleDetector::new(1200);
        bhd.on_non_probe_acked((BLACK_HOLE_THRESHOLD + 1) as u64 * 3, 1400);
        for i in 0..(BLACK_HOLE_THRESHOLD + 1) {
            bhd.on_non_probe_lost(i as u64 * 3, 1500);
            bhd.on_non_probe_lost(i as u64 * 3 + 1, 1300);
        }
        assert!(!bhd.black_hole_detected());
    }

    // Multi-packet bursts are only counted once.
    #[test]
    fn bursts_count_once() {
        let mut bhd = BlackHoleDetector::new(1200);
        bhd.on_non_probe_acked((BLACK_HOLE_THRESHOLD + 1) as u64 * 3, 1400);
        for i in 0..BLACK_HOLE_THRESHOLD {
            bhd.on_non_probe_lost(i as u64 * 3, 1500);
            bhd.on_non_probe_lost(i as u64 * 3 + 1, 1500);
        }
        assert!(!bhd.black_hole_detected());
        bhd.on_non_probe_lost(BLACK_HOLE_THRESHOLD as u64 * 3, 1500);
        assert!(bhd.black_hole_detected());
    }

    // Non-suspicious bursts do not interfere with detection of suspicious
    // bursts.
    #[test]
    fn interleaved_bursts() {
        let mut bhd = BlackHoleDetector::new(1200);
        bhd.on_non_probe_acked((BLACK_HOLE_THRESHOLD + 1) as u64 * 4, 1400);
        for i in 0..(BLACK_HOLE_THRESHOLD + 1) {
            bhd.on_non_probe_lost(i as u64 * 4, 1500);
            bhd.on_non_probe_lost(i as u64 * 4 + 2, 1300);
        }
        assert!(bhd.black_hole_detected());
    }

    // Bursts that are non-suspicious before a delivered packet become
    // suspicious past it.
    #[test]
    fn suspicious_after_acked() {
        let mut bhd = BlackHoleDetector::new(1200);
        bhd.on_non_probe_acked((BLACK_HOLE_THRESHOLD + 1) as u64 * 2, 1400);
        for i in 0..(BLACK_HOLE_THRESHOLD + 1) {
            bhd.on_non_probe_lost(i as u64 * 2, 1300);
        }
        assert!(
            !bhd.black_hole_detected(),
            "1300 byte losses preceding a 1400 byte delivery are not suspicious"
        );
        for i in 0..(BLACK_HOLE_THRESHOLD + 1) {
            bhd.on_non_probe_lost((BLACK_HOLE_THRESHOLD as u64 + 1 + i as u64) * 2, 1300);
        }
        assert!(
            bhd.black_hole_detected(),
            "1300 byte losses following a 1400 byte delivery are suspicious"
        );
    }

    // Loss bursts that precede the delivery of another packet of the largest
    // size seen so far are not suspicious: that delivery proves the path still
    // carries packets of that size, even though it does not raise `acked_mtu`.
    #[test]
    fn equal_size_delivery_clears_preceding_bursts() {
        let mut bhd = BlackHoleDetector::new(1200);
        bhd.on_non_probe_acked(0, 1400);
        bhd.on_non_probe_acked((BLACK_HOLE_THRESHOLD + 1) as u64 * 2, 1400);
        for i in 0..(BLACK_HOLE_THRESHOLD + 1) {
            bhd.on_non_probe_lost(i as u64 * 2 + 1, 1400);
        }
        assert!(
            !bhd.black_hole_detected(),
            "full-size losses preceding a full-size delivery are not suspicious"
        );
        for i in 0..(BLACK_HOLE_THRESHOLD + 1) {
            bhd.on_non_probe_lost((BLACK_HOLE_THRESHOLD as u64 + 1 + i as u64) * 2 + 1, 1400);
        }
        assert!(
            bhd.black_hole_detected(),
            "full-size losses following the last full-size delivery are suspicious"
        );
    }

    // Acknowledgment of a packet marks prior loss bursts with the same packet
    // size as non-suspicious.
    #[test]
    fn retroactively_non_suspicious() {
        let mut bhd = BlackHoleDetector::new(1200);
        for i in 0..BLACK_HOLE_THRESHOLD {
            bhd.on_non_probe_lost(i as u64 * 2, 1400);
        }
        bhd.on_non_probe_acked(BLACK_HOLE_THRESHOLD as u64 * 2, 1400);
        bhd.on_non_probe_lost(BLACK_HOLE_THRESHOLD as u64 * 2 + 1, 1400);
        assert!(!bhd.black_hole_detected());
    }

    // An acknowledged probe clears the suspicious bursts recorded before it.
    #[test]
    fn probe_acked_clears_suspicious_bursts() {
        let mut bhd = BlackHoleDetector::new(1200);
        for i in 0..BLACK_HOLE_THRESHOLD {
            bhd.on_non_probe_lost(i as u64 * 2, 1400);
        }
        assert!(!bhd.black_hole_detected());
        assert_eq!(bhd.suspicious_loss_burst_count(), BLACK_HOLE_THRESHOLD);
        bhd.on_probe_acked(BLACK_HOLE_THRESHOLD as u64 * 2, 1450);
        assert_eq!(bhd.suspicious_loss_burst_count(), 0);
        // A burst after the probe starts a new count.
        bhd.on_non_probe_lost(BLACK_HOLE_THRESHOLD as u64 * 2 + 1, 1450);
        assert!(!bhd.black_hole_detected());
        assert_eq!(bhd.suspicious_loss_burst_count(), 1);
    }

    // Four separate loss bursts of large packets, with only small packets
    // acknowledged in between, are a PMTU black hole; three are not.
    #[test]
    fn pmtu_black_hole_needs_four_independent_large_loss_bursts() -> Result<()> {
        let status = HandshakeStatus {
            derived_handshake_keys: true,
            peer_verified_address: true,
            completed: true,
        };
        for (bursts, black_hole) in [(3, false), (4, true)] {
            let conf = new_test_recovery_config();
            let mut recovery = Recovery::new(&conf);
            let mut spaces = PacketNumSpaceMap::new();
            let space_id = SpaceId::Data;
            let mut now = Instant::now();
            // Per burst: two large packets (lost), then three small ones
            // (acknowledged).
            for burst in 0..bursts {
                for i in 0..5 {
                    let size = if i < 2 { 1400 } else { 1000 };
                    let pkt = new_test_sent_packet(burst * 5 + i, size, now);
                    recovery.on_packet_sent(pkt, space_id, &mut spaces, status, now);
                }
            }

            now += Duration::from_millis(100);
            let mut acked = RangeSet::default();
            for burst in 0..bursts {
                acked.insert(burst * 5 + 2..burst * 5 + 5);
            }
            let (lost_pkts, _) = recovery.on_ack_received(
                &acked,
                0,
                space_id,
                &mut spaces,
                status,
                #[cfg(feature = "qlog")]
                None,
                now,
            )?;
            assert_eq!(lost_pkts, bursts * 2);
            assert_eq!(recovery.take_pmtu_black_hole(), black_hole);
            // The evidence is consumed.
            assert!(!recovery.take_pmtu_black_hole());
        }
        Ok(())
    }

    #[test]
    fn loss_on_reordering() -> Result<()> {
        let conf = new_test_recovery_config();
        let mut recovery = Recovery::new(&conf);
        let mut spaces = PacketNumSpaceMap::new();
        let space_id = SpaceId::Handshake;
        let status = HandshakeStatus {
            derived_handshake_keys: true,
            peer_verified_address: true,
            completed: false,
        };
        let mut now = Instant::now();

        // Fake sending of packet 0
        let sent_pkt0 = new_test_sent_packet(0, 1000, now);
        recovery.on_packet_sent(sent_pkt0, space_id, &mut spaces, status, now);
        assert_eq!(spaces.get(space_id).unwrap().sent.len(), 1);
        assert_eq!(spaces.get(space_id).unwrap().bytes_in_flight, 1000);
        assert_eq!(recovery.bytes_in_flight, 1000);

        // Fake sending of packet 1
        let sent_pkt1 = new_test_sent_packet(1, 1001, now);
        recovery.on_packet_sent(sent_pkt1, space_id, &mut spaces, status, now);
        assert_eq!(spaces.get(space_id).unwrap().sent.len(), 2);
        assert_eq!(spaces.get(space_id).unwrap().bytes_in_flight, 2001);
        assert_eq!(recovery.bytes_in_flight, 2001);

        // Fake sending of packet 2
        let sent_pkt2 = new_test_sent_packet(2, 1002, now);
        recovery.on_packet_sent(sent_pkt2, space_id, &mut spaces, status, now);
        assert_eq!(spaces.get(space_id).unwrap().sent.len(), 3);
        assert_eq!(spaces.get(space_id).unwrap().bytes_in_flight, 3003);
        assert_eq!(recovery.bytes_in_flight, 3003);

        // Fake sending of packet 3
        let sent_pkt2 = new_test_sent_packet(3, 1003, now);
        recovery.on_packet_sent(sent_pkt2, space_id, &mut spaces, status, now);
        assert_eq!(spaces.get(space_id).unwrap().sent.len(), 4);
        assert_eq!(spaces.get(space_id).unwrap().bytes_in_flight, 4006);
        assert_eq!(recovery.bytes_in_flight, 4006);

        // Advance ticks and fake receiving of ack
        now += Duration::from_millis(100);
        let mut acked = RangeSet::default();
        acked.insert(1..4);

        // Detect packet loss base on reordering threshold
        let (lost_pkts, lost_bytes) = recovery.on_ack_received(
            &acked,
            0,
            SpaceId::Handshake,
            &mut spaces,
            status,
            #[cfg(feature = "qlog")]
            None,
            now,
        )?;
        assert_eq!(spaces.get(space_id).unwrap().sent.len(), 4);
        assert_eq!(lost_pkts, 1);
        assert_eq!(lost_bytes, 1000);

        // Advance ticks and fake receiving of duplicated ack
        now += recovery.rtt.smoothed_rtt();
        let (lost_pkts, lost_bytes) = recovery.on_ack_received(
            &acked,
            0,
            SpaceId::Handshake,
            &mut spaces,
            status,
            #[cfg(feature = "qlog")]
            None,
            now,
        )?;
        assert_eq!(lost_pkts, 0);
        assert_eq!(lost_bytes, 0);
        assert_eq!(recovery.pto_count, 0);

        recovery.drain_sent_packets(
            spaces.get_mut(space_id).unwrap(),
            now,
            recovery.rtt.smoothed_rtt(),
        );
        assert_eq!(spaces.get(space_id).unwrap().sent.len(), 0);

        Ok(())
    }

    #[test]
    fn pto() -> Result<()> {
        let conf = new_test_recovery_config();
        let mut recovery = Recovery::new(&conf);
        let mut spaces = PacketNumSpaceMap::new();
        let space_id = SpaceId::Handshake;
        let status = HandshakeStatus {
            derived_handshake_keys: true,
            peer_verified_address: true,
            completed: false,
        };
        let mut now = Instant::now();

        // Fake sending of packet 0
        let sent_pkt0 = new_test_sent_packet(0, 1000, now);
        recovery.on_packet_sent(sent_pkt0, space_id, &mut spaces, status, now);
        assert_eq!(spaces.get(space_id).unwrap().sent.len(), 1);
        assert_eq!(spaces.get(space_id).unwrap().bytes_in_flight, 1000);
        assert_eq!(recovery.bytes_in_flight, 1000);

        // Fake sending of packet 1
        let sent_pkt1 = new_test_sent_packet(1, 1001, now);
        recovery.on_packet_sent(sent_pkt1, space_id, &mut spaces, status, now);
        assert_eq!(spaces.get(space_id).unwrap().sent.len(), 2);
        assert_eq!(spaces.get(space_id).unwrap().bytes_in_flight, 2001);
        assert_eq!(recovery.bytes_in_flight, 2001);

        // Advance ticks and fake receiving of ack
        now += Duration::from_millis(100);
        let mut acked = RangeSet::default();
        acked.insert(0..1);
        let (lost_pkts, lost_bytes) = recovery.on_ack_received(
            &acked,
            0,
            SpaceId::Handshake,
            &mut spaces,
            status,
            #[cfg(feature = "qlog")]
            None,
            now,
        )?;
        assert_eq!(spaces.get(space_id).unwrap().sent.len(), 1);
        assert_eq!(lost_pkts, 0);
        assert_eq!(lost_bytes, 0);
        assert!(recovery.loss_detection_timer().is_some());

        // Advance ticks until pto timeout
        now = recovery.loss_detection_timer().unwrap();
        let (lost_pkts, lost_bytes) = recovery.on_loss_detection_timeout(
            SpaceId::Handshake,
            &mut spaces,
            status,
            #[cfg(feature = "qlog")]
            None,
            now,
        );
        assert_eq!(recovery.pto_count, 1);
        assert_eq!(lost_pkts, 0);
        assert_eq!(lost_bytes, 0);

        Ok(())
    }

    #[test]
    fn discard_pkt_num_space() -> Result<()> {
        let conf = new_test_recovery_config();
        let mut recovery = Recovery::new(&conf);
        let mut spaces = PacketNumSpaceMap::new();
        let space_id = SpaceId::Handshake;
        let status = HandshakeStatus {
            derived_handshake_keys: true,
            peer_verified_address: true,
            completed: false,
        };
        let mut now = Instant::now();

        // Fake sending of packet 0 on Handshake space
        let sent_pkt0 = new_test_sent_packet(0, 1000, now);
        recovery.on_packet_sent(sent_pkt0, space_id, &mut spaces, status, now);
        assert_eq!(spaces.get(space_id).unwrap().sent.len(), 1);
        assert_eq!(spaces.get(space_id).unwrap().bytes_in_flight, 1000);
        assert_eq!(recovery.bytes_in_flight, 1000);

        // Fake sending of packet 1 on Handshake space
        let sent_pkt1 = new_test_sent_packet(1, 1001, now);
        recovery.on_packet_sent(sent_pkt1, space_id, &mut spaces, status, now);
        assert_eq!(spaces.get(space_id).unwrap().sent.len(), 2);
        assert_eq!(spaces.get(space_id).unwrap().bytes_in_flight, 2001);
        assert_eq!(recovery.bytes_in_flight, 2001);

        // Fake sending of packet 2 on Handshake space
        let sent_pkt2 = new_test_sent_packet(2, 1002, now);
        recovery.on_packet_sent(sent_pkt2, space_id, &mut spaces, status, now);
        assert_eq!(spaces.get(space_id).unwrap().sent.len(), 3);
        assert_eq!(spaces.get(space_id).unwrap().bytes_in_flight, 3003);
        assert_eq!(recovery.bytes_in_flight, 3003);

        // Fake sending of packet 0 on Data space
        let sent_pkt3 = new_test_sent_packet(0, 1003, now);
        recovery.on_packet_sent(sent_pkt3, SpaceId::Data, &mut spaces, status, now);
        assert_eq!(spaces.get(SpaceId::Data).unwrap().sent.len(), 1);
        assert_eq!(spaces.get(SpaceId::Data).unwrap().bytes_in_flight, 1003);
        assert_eq!(recovery.bytes_in_flight, 4006);

        // Advance ticks and fake receiving of ack on Handshake space
        now += Duration::from_millis(100);
        let mut acked = RangeSet::default();
        acked.insert(0..2);
        recovery.on_ack_received(
            &acked,
            0,
            SpaceId::Handshake,
            &mut spaces,
            status,
            #[cfg(feature = "qlog")]
            None,
            now,
        )?;
        assert_eq!(spaces.get(SpaceId::Handshake).unwrap().sent.len(), 1);
        assert_eq!(
            spaces.get(SpaceId::Handshake).unwrap().bytes_in_flight,
            1002
        );
        assert_eq!(recovery.bytes_in_flight, 2005);

        // Discard Handshake space
        recovery.on_pkt_num_space_discarded(space_id, &mut spaces, status, now);
        assert_eq!(spaces.get(space_id).unwrap().sent.len(), 0);
        assert_eq!(spaces.get(space_id).unwrap().bytes_in_flight, 0);
        assert_eq!(spaces.get(space_id).unwrap().ack_eliciting_in_flight, 0);
        assert_eq!(recovery.bytes_in_flight, 1003);
        assert_eq!(recovery.ack_eliciting_in_flight, 1);

        Ok(())
    }

    fn check_acked_packets(sent: &VecDeque<SentPacket>, acked_ranges: Vec<Range<u64>>) -> bool {
        let ranges_contain = |pkt_num: u64, ranges: Vec<Range<u64>>| {
            for range in &ranges {
                if range.contains(&pkt_num) {
                    return true;
                }
            }
            return false;
        };

        for sent_pkt in sent {
            match sent_pkt.pkt_num {
                pkt_num if ranges_contain(pkt_num, acked_ranges.clone()) => {
                    if sent_pkt.time_acked.is_none() {
                        return false;
                    }
                }
                _ => {
                    if sent_pkt.time_acked.is_some() {
                        return false;
                    }
                }
            }
        }

        true
    }

    fn generate_ack(ranges: Vec<Range<u64>>) -> RangeSet {
        let mut acked = RangeSet::default();
        for range in ranges {
            acked.insert(range);
        }
        acked
    }

    #[test]
    fn detect_acked_packets() -> Result<()> {
        let conf = new_test_recovery_config();
        let mut recovery = Recovery::new(&conf);
        let mut spaces = PacketNumSpaceMap::new();
        let status = HandshakeStatus {
            derived_handshake_keys: true,
            peer_verified_address: true,
            completed: false,
        };
        let mut now = Instant::now();

        // Fake sending of packets on Data space.
        for pkt_num in 100..1000 as u64 {
            let sent_pkt = new_test_sent_packet(pkt_num, 1000, now);
            recovery.on_packet_sent(sent_pkt, SpaceId::Data, &mut spaces, status, now);
        }
        now += Duration::from_millis(100);

        // Packets with a higher number got acked in interleaved mode.
        // Fake receiving ACK.
        let ack = generate_ack(vec![500..550, 600..650, 700..750, 800..850, 900..950]);
        let mut newly_acked_pkts = Vec::<AckedPacket>::new();
        let mut spuriously_lost = Vec::new();
        _ = recovery.detect_acked_packets(
            &ack,
            spaces.get_mut(SpaceId::Data).unwrap(),
            &mut newly_acked_pkts,
            &mut spuriously_lost,
            now,
        );
        assert!(check_acked_packets(
            &spaces.get(SpaceId::Data).unwrap().sent,
            vec![500..550, 600..650, 700..750, 800..850, 900..950],
        ));
        // Fake receiving next ACK.
        let ack = generate_ack(vec![550..600, 650..700, 750..800, 850..900]);
        _ = recovery.detect_acked_packets(
            &ack,
            spaces.get_mut(SpaceId::Data).unwrap(),
            &mut newly_acked_pkts,
            &mut spuriously_lost,
            now,
        );
        assert!(check_acked_packets(
            &spaces.get(SpaceId::Data).unwrap().sent,
            vec![500..950],
        ));
        // Fake receiving duplicated ACK.
        recovery.on_ack_received(
            &ack,
            0,
            SpaceId::Data,
            &mut spaces,
            status,
            #[cfg(feature = "qlog")]
            None,
            now,
        )?;
        assert!(check_acked_packets(
            &spaces.get(SpaceId::Data).unwrap().sent,
            vec![500..950],
        ));

        // Got ACKs with no intersection.
        let ack = generate_ack(vec![0..100, 1000..1100]);
        _ = recovery.detect_acked_packets(
            &ack,
            spaces.get_mut(SpaceId::Data).unwrap(),
            &mut newly_acked_pkts,
            &mut spuriously_lost,
            now,
        );
        assert!(check_acked_packets(
            &spaces.get(SpaceId::Data).unwrap().sent,
            vec![500..950],
        ));

        // Got ACKs with partial overlapping.
        let ack = generate_ack(vec![50..150, 950..1050]);
        _ = recovery.detect_acked_packets(
            &ack,
            spaces.get_mut(SpaceId::Data).unwrap(),
            &mut newly_acked_pkts,
            &mut spuriously_lost,
            now,
        );
        assert!(check_acked_packets(
            &spaces.get(SpaceId::Data).unwrap().sent,
            vec![100..150, 500..1000],
        ));

        // Packets with a lower number got acked.
        let ack = generate_ack(vec![100..200, 300..400]);
        _ = recovery.detect_acked_packets(
            &ack,
            spaces.get_mut(SpaceId::Data).unwrap(),
            &mut newly_acked_pkts,
            &mut spuriously_lost,
            now,
        );
        assert!(check_acked_packets(
            &spaces.get(SpaceId::Data).unwrap().sent,
            vec![100..200, 300..400, 500..1000],
        ));
        assert!(spuriously_lost.is_empty(), "nothing was declared lost");

        Ok(())
    }

    #[test]
    fn check_cwnd_for_non_app_data_ack() -> Result<()> {
        let conf = new_test_recovery_config();
        let mut recovery = Recovery::new(&conf);
        let mut spaces = PacketNumSpaceMap::new();
        let space_id = SpaceId::Handshake;
        let status = HandshakeStatus {
            derived_handshake_keys: true,
            peer_verified_address: true,
            completed: false,
        };
        let mut now = Instant::now();
        let cwnd_before_ack = recovery.congestion.congestion_window();

        // Fake sending of packet 0
        let sent_pkt0 = new_test_sent_packet(0, 1000, now);
        recovery.on_packet_sent(sent_pkt0, space_id, &mut spaces, status, now);

        // Fake sending of packet 1
        let sent_pkt1 = new_test_sent_packet(1, 2000, now);
        recovery.on_packet_sent(sent_pkt1, space_id, &mut spaces, status, now);

        // Advance ticks and fake receiving of ack
        now += Duration::from_millis(100);
        let mut acked = RangeSet::default();
        acked.insert(0..2);

        // Detect packet loss base on reordering threshold
        let (lost_pkts, lost_bytes) = recovery.on_ack_received(
            &acked,
            0,
            SpaceId::Handshake,
            &mut spaces,
            status,
            #[cfg(feature = "qlog")]
            None,
            now,
        )?;
        assert_eq!(cwnd_before_ack, recovery.congestion.congestion_window());

        Ok(())
    }

    const MAX_PTO_UT: Duration = Duration::from_secs(30);

    fn calculate_pto_with_count(count: usize) -> (Duration, Duration) {
        let mut conf = new_test_recovery_config();
        conf.pto_linear_factor = 2;
        conf.max_pto = MAX_PTO_UT;
        let mut recovery = Recovery::new(&conf);
        recovery.pto_count = count;

        let duration = recovery.calculate_pto();
        (duration, recovery.pto_with_ack_delay(duration))
    }

    fn rfc9002_with_pto_interval(max_pto_interval: Option<Duration>) -> Rfc9002 {
        let conf = RecoveryConfig {
            pto_linear_factor: 0,
            max_pto: MAX_PTO_UT,
            max_pto_interval,
            ..RecoveryConfig::default()
        };
        Rfc9002::new(&conf)
    }

    /// Without a limit the probe timeout is the plain exponential backoff.
    #[test]
    fn rfc9002_pto_is_exponential_without_a_pto_interval_limit() {
        let ld = rfc9002_with_pto_interval(None);
        let base = Duration::from_secs(1);
        let srtt = Duration::from_millis(500);
        for count in 0..5usize {
            assert_eq!(ld.pto(base, count, srtt), base * 2_u32.pow(count as u32));
        }
        let mad = Duration::from_millis(250);
        let duration = ld.pto(base, 3, srtt);
        assert_eq!(
            ld.pto_with_ack_delay(duration, base, mad, 3, srtt),
            duration + mad * 8
        );
    }

    /// noq's `MAX_PTO_INTERVAL`: each probe timeout is at most the previous
    /// one plus the limit, so a long outage is probed at a steady pace.
    #[test]
    fn rfc9002_pto_grows_linearly_beyond_the_pto_interval_limit() {
        let ld = rfc9002_with_pto_interval(Some(Duration::from_secs(2)));
        let base = Duration::from_secs(1);
        let srtt = Duration::from_millis(500);
        let got: Vec<_> = (0..7usize).map(|count| ld.pto(base, count, srtt).as_millis()).collect();
        assert_eq!(got, [1000, 2000, 4000, 6000, 8000, 10000, 12000]);

        // A slow link steps by 1.5 * smoothed_rtt instead.
        let srtt = Duration::from_secs(2);
        let got: Vec<_> = (0..5usize).map(|count| ld.pto(base, count, srtt).as_millis()).collect();
        assert_eq!(got, [1000, 2000, 4000, 7000, 10000]);

        // The Application Data space waits for max_ack_delay on top.
        let srtt = Duration::from_millis(500);
        let mad = Duration::from_millis(250);
        let got: Vec<_> = (0..4usize)
            .map(|count| {
                let duration = ld.pto(base, count, srtt);
                ld.pto_with_ack_delay(duration, base, mad, count, srtt).as_millis()
            })
            .collect();
        assert_eq!(got, [1250, 2500, 4500, 6500]);

        // max_pto still caps it.
        let ld = Rfc9002::new(&RecoveryConfig {
            pto_linear_factor: 0,
            max_pto: Duration::from_secs(5),
            max_pto_interval: Some(Duration::from_secs(2)),
            ..RecoveryConfig::default()
        });
        assert_eq!(ld.pto(base, 6, srtt), Duration::from_secs(5));
    }

    #[test]
    fn rfc9002_loss_thresholds() {
        let ld = Rfc9002::new(&RecoveryConfig::default());
        assert_eq!(ld.name(), "tquic-rfc9002");
        for app_data in [false, true] {
            // kPacketThreshold = 3
            assert!(!ld.lost_by_reordering(8, 10, app_data));
            assert!(ld.lost_by_reordering(7, 10, app_data));
            // kTimeThreshold = 9/8 of max(latest_rtt, smoothed_rtt)
            assert_eq!(
                ld.loss_delay(Duration::from_millis(80), Duration::from_millis(40), app_data),
                Duration::from_millis(90)
            );
            // kGranularity lower bound
            assert_eq!(
                ld.loss_delay(Duration::ZERO, Duration::ZERO, app_data),
                TIMER_GRANULARITY
            );
        }
    }

    /// RFC 9002 Section 6.1, as quic-go does it: a spurious loss ends the
    /// packet threshold for application data, and reordering that outlasted
    /// the time threshold doubles it, up to two RTTs. Packets sent before the
    /// last increase cannot raise it again.
    #[test]
    fn rfc9002_spurious_losses_relax_the_app_data_thresholds() {
        let rtt = Duration::from_millis(80);
        let mut ld = Rfc9002::new(&RecoveryConfig::default());
        ld.on_app_data_sent(0);

        // Reordering within the time threshold: only the packet threshold goes.
        ld.on_spurious_losses(&[(1, Duration::from_millis(85))], rtt, rtt);
        assert!(!ld.lost_by_reordering(0, 100, true));
        assert!(ld.lost_by_reordering(0, 100, false), "handshake spaces keep it");
        assert_eq!(ld.loss_delay(rtt, rtt, true), Duration::from_millis(90));

        // Beyond it: 10/8.
        ld.on_spurious_losses(&[(2, Duration::from_millis(95))], rtt, rtt);
        assert_eq!(ld.loss_delay(rtt, rtt, true), Duration::from_millis(100));
        assert_eq!(ld.loss_delay(rtt, rtt, false), Duration::from_millis(90));

        // A packet sent before that increase cannot raise it again.
        ld.on_app_data_sent(10);
        ld.on_spurious_losses(&[(3, Duration::from_millis(150))], rtt, rtt);
        assert_eq!(ld.loss_delay(rtt, rtt, true), Duration::from_millis(100));

        // Later ones can, up to 16/8.
        for pkt_num in 10..20 {
            ld.on_spurious_losses(&[(pkt_num, Duration::from_secs(1))], rtt, rtt);
            ld.on_app_data_sent(pkt_num + 1);
        }
        assert_eq!(ld.loss_delay(rtt, rtt, true), Duration::from_millis(160));
    }

    /// The trace of 2026-10-14: a small packet overtook queued ones, the
    /// peer acknowledged it first, and the packets it overtook were declared
    /// lost though they had arrived. Their late acknowledgment must neither
    /// take their bytes out of flight a second time nor leave the packet
    /// threshold to declare the next overtaken packets lost.
    #[test]
    fn a_spurious_loss_is_recognized_and_not_repeated() -> Result<()> {
        let conf = new_test_recovery_config();
        let mut recovery = Recovery::new(&conf);
        let mut spaces = PacketNumSpaceMap::new();
        let space_id = SpaceId::Data;
        let status = HandshakeStatus {
            derived_handshake_keys: true,
            peer_verified_address: true,
            completed: true,
        };
        let start = Instant::now();
        let ack = |recovery: &mut Recovery,
                   spaces: &mut PacketNumSpaceMap,
                   range: Range<u64>,
                   now: Instant|
         -> Result<(u64, u64)> {
            let mut acked = RangeSet::default();
            acked.insert(range);
            recovery.on_ack_received(
                &acked,
                0,
                space_id,
                spaces,
                status,
                #[cfg(feature = "qlog")]
                None,
                now,
            )
        };

        for pkt_num in 0..5 {
            let pkt = new_test_sent_packet(pkt_num, 1000, start);
            recovery.on_packet_sent(pkt, space_id, &mut spaces, status, start);
        }
        // 3 and 4 overtook 0..3: 0 and 1 are declared lost by the packet threshold.
        let now = start + Duration::from_millis(10);
        assert_eq!(ack(&mut recovery, &mut spaces, 3..5, now)?, (2, 2000));
        assert_eq!(recovery.bytes_in_flight, 1000, "packet 2 is still in flight");

        // They had arrived: their acknowledgment comes next.
        let now = start + Duration::from_millis(11);
        assert_eq!(ack(&mut recovery, &mut spaces, 0..2, now)?, (0, 0));
        assert_eq!(recovery.bytes_in_flight, 1000, "packet 2 is still in flight");
        assert_eq!(recovery.stats.lost_count, 2);
        let now = start + Duration::from_millis(12);
        assert_eq!(ack(&mut recovery, &mut spaces, 2..3, now)?, (0, 0));
        assert_eq!(recovery.bytes_in_flight, 0);

        // The same overtaking again is now waited out.
        let start = start + Duration::from_millis(20);
        for pkt_num in 5..10 {
            let pkt = new_test_sent_packet(pkt_num, 1000, start);
            recovery.on_packet_sent(pkt, space_id, &mut spaces, status, start);
        }
        let now = start + Duration::from_millis(10);
        assert_eq!(ack(&mut recovery, &mut spaces, 8..10, now)?, (0, 0));
        let now = start + Duration::from_millis(11);
        assert_eq!(ack(&mut recovery, &mut spaces, 5..8, now)?, (0, 0));
        assert_eq!(recovery.bytes_in_flight, 0);
        assert_eq!(recovery.stats.lost_count, 2);
        Ok(())
    }

    #[test]
    fn calculate_pto() -> Result<()> {
        assert_eq!(
            calculate_pto_with_count(0),
            (
                Duration::from_millis(999),  // 999 * 2 ^ ( 2 - 2)
                Duration::from_millis(1099)  // (999 + 100) * 2 ^ 0, max_ack_delay is 100ms.
            )
        );

        assert_eq!(
            calculate_pto_with_count(2),
            (
                Duration::from_millis(999),  // 999 * 2 ^ 0
                Duration::from_millis(1099)  // (999 + 100) * 2 ^ 0
            )
        );

        assert_eq!(
            calculate_pto_with_count(3),
            (
                Duration::from_millis(1998), // 999 * 2 ^ ( 2 - 2)
                Duration::from_millis(2198)  // (999 + 100) * 2 ^ ( 3 - 2)
            )
        );

        // PTO reach the upper limit.
        assert_eq!(calculate_pto_with_count(100), (MAX_PTO_UT, MAX_PTO_UT));

        Ok(())
    }
}
