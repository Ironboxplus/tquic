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

//! Unreliable datagrams (RFC 9221).
//!
//! The queue semantics are ported from quinn-proto 0.11.12
//! `connection/datagrams.rs`: a bounded send queue that either drops the
//! oldest entries or reports `Blocked`, a bounded receive window that drops
//! the oldest undelivered datagram, and dropping queued datagrams that no
//! longer fit after the usable size shrinks.

use std::collections::VecDeque;
use std::time::Duration;
use std::time::Instant;

use bytes::Bytes;
use log::*;
use rustc_hash::FxHashMap;

use crate::codec;
use crate::error::Error;
use crate::Result;

/// Loss ratio above which a round trip counts against the cwnd bypass.
const BYPASS_LOSS_THRESHOLD: f64 = 0.1;

/// Consecutive lossy round trips that trip the cwnd bypass (RFC 8084).
const BYPASS_BAD_ROUND_TRIPS: u32 = 3;

/// A flow silent for this long is forgotten (`FlowPaths`).
const FLOW_FORGET_AFTER: Duration = Duration::from_secs(30);

/// Errors that can arise when sending a datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendDatagramError {
    /// The peer does not support receiving datagram frames.
    UnsupportedByPeer,

    /// Datagram support is disabled locally.
    Disabled,

    /// The datagram is larger than the connection can currently accommodate.
    TooLarge,

    /// The send queue is full; the datagram is handed back.
    Blocked(Bytes),
}

impl std::fmt::Display for SendDatagramError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            SendDatagramError::UnsupportedByPeer => write!(f, "datagrams not supported by peer"),
            SendDatagramError::Disabled => write!(f, "datagram support disabled"),
            SendDatagramError::TooLarge => write!(f, "datagram too large"),
            SendDatagramError::Blocked(_) => write!(f, "datagram send blocked"),
        }
    }
}

impl std::error::Error for SendDatagramError {}

/// Datagram counters of a connection. All values are cumulative.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DatagramStats {
    /// DATAGRAM frames written into packets.
    pub sent: u64,

    /// DATAGRAM frames received.
    pub received: u64,

    /// Queued datagrams dropped before sending (drop-oldest or oversize).
    pub dropped_outgoing: u64,

    /// Received datagrams dropped because the receive window was full.
    pub dropped_incoming: u64,

    /// DATAGRAM frames declared lost.
    pub lost: u64,

    /// DATAGRAM frames acknowledged.
    pub acked: u64,

    /// Times the congestion window bypass was switched off by the breaker.
    pub bypass_trips: u32,

    /// Whether datagrams currently bypass the congestion window.
    pub bypass_active: bool,
}

pub(crate) struct OutgoingDatagram {
    pub data: Bytes,

    /// The application's flow of this datagram, told to the send backend
    /// through `PacketSendMeta::flow_hash`.
    pub flow: Option<u32>,

    /// A measurement of the path itself (EasyTier's one-way delay probes and
    /// their reports), not application data: it is sent even when the
    /// congestion window is closed or the bypass breaker has tripped. RFC 8084
    /// Section 3.1 asks a circuit breaker to limit the load a tunnel puts on
    /// the path; a probe every 100 ms is not that load, and held back with the
    /// bulk it stops reporting exactly when the path is congested.
    pub measurement: bool,
}

impl OutgoingDatagram {
    /// Encoded size of the DATAGRAM frame carrying this datagram.
    pub(crate) fn frame_len(&self) -> usize {
        1 + codec::encode_varint_len(self.data.len() as u64) + self.data.len()
    }
}

/// Circuit breaker of the optional congestion window bypass
/// (RFC 9484 Section 10.2, RFC 8084): once too many round trips in a row lose
/// more than `BYPASS_LOSS_THRESHOLD` of the datagrams, datagrams go back
/// under the congestion window.
#[derive(Default)]
pub(crate) struct BypassBreaker {
    enabled: bool,
    /// The breaker never trips: a shaper below QUIC (EasyTier's CAKE) limits
    /// the rate already, and its AQM drops are no network congestion.
    never_trips: bool,
    tripped: bool,
    trips: u32,
    window_start: Option<Instant>,
    acked: u64,
    lost: u64,
    bad_round_trips: u32,
}

impl BypassBreaker {
    pub(crate) fn set_enabled(&mut self, enabled: bool) {
        *self = BypassBreaker {
            enabled,
            never_trips: self.never_trips,
            trips: self.trips,
            ..BypassBreaker::default()
        };
    }

    /// Let the breaker trip (the default), or never. Turning tripping off
    /// also re-arms a tripped breaker.
    pub(crate) fn set_trips(&mut self, trips: bool) {
        self.never_trips = !trips;
        if !trips {
            self.tripped = false;
            self.bad_round_trips = 0;
        }
    }

    pub(crate) fn active(&self) -> bool {
        self.enabled && !self.tripped
    }

    pub(crate) fn trips(&self) -> u32 {
        self.trips
    }

    pub(crate) fn on_acked(&mut self, n: u64) {
        self.acked += n;
    }

    pub(crate) fn on_lost(&mut self, n: u64) {
        self.lost += n;
    }

    /// Close the current round trip window if it is over. Return true if
    /// the breaker tripped.
    pub(crate) fn on_tick(&mut self, now: Instant, srtt: Duration) -> bool {
        if !self.active() {
            return false;
        }
        let start = *self.window_start.get_or_insert(now);
        if now.saturating_duration_since(start) < srtt {
            return false;
        }

        let total = self.acked + self.lost;
        if total > 0 && self.lost as f64 / total as f64 > BYPASS_LOSS_THRESHOLD {
            self.bad_round_trips += 1;
        } else {
            self.bad_round_trips = 0;
        }
        self.window_start = Some(now);
        self.acked = 0;
        self.lost = 0;

        if self.bad_round_trips >= BYPASS_BAD_ROUND_TRIPS && !self.never_trips {
            self.tripped = true;
            self.trips += 1;
            return true;
        }
        false
    }
}

/// Which path the datagrams of each application flow go on
/// (MP_FIX_PHASES.md S-I5/I6).
///
/// A datagram carries an inner packet, and nothing below QUIC puts the
/// packets of a flow back in order: spreading one flow over paths of
/// different delay reorders the inner transport, which then sees loss (a
/// proxied QUIC connection dropped the late packets as duplicates once they
/// fell 129 packet numbers behind). So a flow keeps its path, and moves only
/// at a flowlet boundary (FLARE, Kandula et al., SIGCOMM CCR 2007; CONGA,
/// SIGCOMM 2014; LetFlow, NSDI 2017): after a pause longer than the delay
/// difference of the paths it may use, its next packet cannot overtake the
/// last one wherever it goes. Pure hashing (ECMP, RFC 2991/6438) is not
/// used: it ignores the paths' rates and delays.
#[derive(Default)]
pub(crate) struct FlowPaths {
    flows: FxHashMap<Option<u32>, FlowPath>,
    last_prune: Option<Instant>,
}

struct FlowPath {
    path_id: usize,
    last_sent: Instant,
}

impl FlowPaths {
    /// The path `flow` keeps, if it may still use it: `usable(path)` and the
    /// flow sent no longer than `flowlet_gap` ago.
    pub(crate) fn current(
        &self,
        flow: Option<u32>,
        now: Instant,
        flowlet_gap: Duration,
        usable: impl Fn(usize) -> bool,
    ) -> Option<usize> {
        let entry = self.flows.get(&flow)?;
        let in_flowlet = now.saturating_duration_since(entry.last_sent) <= flowlet_gap;
        (in_flowlet && usable(entry.path_id)).then_some(entry.path_id)
    }

    /// `flow` goes on `path_id` from now on; its flowlet starts now.
    pub(crate) fn place(&mut self, flow: Option<u32>, path_id: usize, now: Instant) {
        self.flows.insert(
            flow,
            FlowPath {
                path_id,
                last_sent: now,
            },
        );
        self.prune(now);
    }

    /// A datagram of `flow` was written into a packet.
    pub(crate) fn on_sent(&mut self, flow: Option<u32>, now: Instant) {
        if let Some(entry) = self.flows.get_mut(&flow) {
            entry.last_sent = now;
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.flows.len()
    }

    fn prune(&mut self, now: Instant) {
        if self
            .last_prune
            .is_some_and(|at| now.saturating_duration_since(at) < FLOW_FORGET_AFTER)
        {
            return;
        }
        self.last_prune = Some(now);
        self.flows
            .retain(|_, e| now.saturating_duration_since(e.last_sent) < FLOW_FORGET_AFTER);
    }
}

#[derive(Default)]
pub(crate) struct DatagramState {
    /// Bytes received but not yet delivered to the application.
    recv_buffered: usize,
    incoming: VecDeque<(Bytes, Option<u64>)>,
    outgoing: VecDeque<OutgoingDatagram>,
    outgoing_total: usize,

    /// Whether the application has not been told about newly received
    /// datagrams yet.
    pub(crate) readable_pending: bool,

    /// Smallest usable size seen when the queue was last trimmed.
    last_max_size: Option<usize>,

    pub(crate) stats: DatagramStats,
    pub(crate) breaker: BypassBreaker,
    pub(crate) flow_paths: FlowPaths,
}

impl DatagramState {
    /// Queue a datagram whose size has already been checked.
    ///
    /// If `drop_oldest` is true, older unsent datagrams are discarded to
    /// make room; otherwise `Blocked` is returned when the queue is full.
    pub(crate) fn queue(
        &mut self,
        data: Bytes,
        drop_oldest: bool,
        send_buffer_size: usize,
    ) -> std::result::Result<(), SendDatagramError> {
        self.queue_with_flow(data, None, drop_oldest, send_buffer_size)
    }

    /// Like `queue`, for a datagram that belongs to the application flow `flow`.
    pub(crate) fn queue_with_flow(
        &mut self,
        data: Bytes,
        flow: Option<u32>,
        drop_oldest: bool,
        send_buffer_size: usize,
    ) -> std::result::Result<(), SendDatagramError> {
        self.queue_inner(data, flow, false, drop_oldest, send_buffer_size)
    }

    /// Like `queue_with_flow`, for a measurement datagram
    /// (`OutgoingDatagram::measurement`).
    pub(crate) fn queue_measurement(
        &mut self,
        data: Bytes,
        flow: Option<u32>,
        drop_oldest: bool,
        send_buffer_size: usize,
    ) -> std::result::Result<(), SendDatagramError> {
        self.queue_inner(data, flow, true, drop_oldest, send_buffer_size)
    }

    fn queue_inner(
        &mut self,
        data: Bytes,
        flow: Option<u32>,
        measurement: bool,
        drop_oldest: bool,
        send_buffer_size: usize,
    ) -> std::result::Result<(), SendDatagramError> {
        if drop_oldest {
            while self.outgoing_total + data.len() > send_buffer_size {
                let prev = match self.outgoing.pop_front() {
                    Some(prev) => prev,
                    None => break,
                };
                trace!("dropping outgoing datagram len={}", prev.data.len());
                self.outgoing_total -= prev.data.len();
                self.stats.dropped_outgoing += 1;
            }
        } else if self.outgoing_total + data.len() > send_buffer_size {
            return Err(SendDatagramError::Blocked(data));
        }
        self.outgoing_total += data.len();
        self.outgoing.push_back(OutgoingDatagram { data, flow, measurement });
        Ok(())
    }

    /// Handle a received datagram. Return true if the receive queue was
    /// empty before.
    pub(crate) fn received(&mut self, data: Bytes, window: Option<usize>, timestamp: Option<u64>) -> Result<bool> {
        let window = match window {
            Some(window) => window,
            // Unexpected DATAGRAM frame.
            None => return Err(Error::ProtocolViolation),
        };
        if data.len() > window {
            return Err(Error::ProtocolViolation);
        }

        let was_empty = self.recv_buffered == 0;
        while data.len() + self.recv_buffered > window {
            debug!("dropping stale datagram");
            self.recv();
            self.stats.dropped_incoming += 1;
        }

        self.recv_buffered += data.len();
        self.incoming.push_back((data, timestamp));
        self.stats.received += 1;
        self.readable_pending = true;
        Ok(was_empty)
    }

    /// Discard queued datagrams longer than `max_payload` bytes, so that a
    /// smaller usable size never leaves an unsendable datagram at the head
    /// of the queue.
    pub(crate) fn drop_oversized(&mut self, max_payload: usize) {
        if self.last_max_size.is_some_and(|last| last <= max_payload) {
            self.last_max_size = Some(max_payload);
            return;
        }
        self.last_max_size = Some(max_payload);

        let mut dropped = 0;
        let mut dropped_bytes = 0;
        self.outgoing.retain(|d| {
            let keep = d.data.len() <= max_payload;
            if !keep {
                trace!(
                    "dropping {} byte datagram violating {} byte limit",
                    d.data.len(),
                    max_payload
                );
                dropped += 1;
                dropped_bytes += d.data.len();
            }
            keep
        });
        self.outgoing_total -= dropped_bytes;
        self.stats.dropped_outgoing += dropped;
    }

    /// Take the next queued datagram if its frame fits in `room` bytes.
    #[cfg(test)]
    pub(crate) fn pop_fitting(&mut self, room: usize) -> Option<OutgoingDatagram> {
        self.pop_fitting_in_packet(room, &mut None, false)
    }

    /// Take the next queued datagram if its frame fits in `room` bytes and it
    /// belongs to the same flow as the datagrams already in the packet
    /// (`packet_flow`, `None` while the packet has none): a packet carries
    /// one flow only, so that a send queue below QUIC can tell flows apart
    /// (and RFC 9484 Section 10.3 holds: datagrams of different flows, which
    /// may differ in DSCP, are not merged into one outer packet).
    pub(crate) fn pop_fitting_in_packet(
        &mut self,
        room: usize,
        packet_flow: &mut Option<Option<u32>>,
        only_measurement: bool,
    ) -> Option<OutgoingDatagram> {
        // Future work (as in quinn): a smaller later datagram could still fill
        // a mostly-full packet when a larger one is queued first.
        let index = if only_measurement {
            self.outgoing.iter().position(|d| d.measurement)?
        } else {
            0
        };
        let head = self.outgoing.get(index)?;
        if head.frame_len() > room || packet_flow.is_some_and(|flow| flow != head.flow) {
            return None;
        }
        let d = self.outgoing.remove(index)?;
        *packet_flow = Some(d.flow);
        self.outgoing_total -= d.data.len();
        self.stats.sent += 1;
        Some(d)
    }

    /// The flow of the `index`th queued datagram.
    pub(crate) fn flow_at(&self, index: usize) -> Option<Option<u32>> {
        self.outgoing.get(index).map(|d| d.flow)
    }

    /// Like `pop_fitting_in_packet`, for a packet on a path that carries only
    /// some flows: take the first queued datagram whose flow `on_this_path`
    /// accepts. The datagrams of one flow stay in order: once one of them
    /// does not fit, none of its flow is taken.
    pub(crate) fn pop_fitting_for_path(
        &mut self,
        room: usize,
        packet_flow: &mut Option<Option<u32>>,
        only_measurement: bool,
        mut on_this_path: impl FnMut(Option<u32>) -> bool,
    ) -> Option<OutgoingDatagram> {
        let mut index = None;
        for (i, d) in self.outgoing.iter().enumerate() {
            if (only_measurement && !d.measurement)
                || packet_flow.is_some_and(|flow| flow != d.flow)
                || !on_this_path(d.flow)
            {
                continue;
            }
            if d.frame_len() > room {
                return None;
            }
            index = Some(i);
            break;
        }
        let d = self.outgoing.remove(index?)?;
        *packet_flow = Some(d.flow);
        self.outgoing_total -= d.data.len();
        self.stats.sent += 1;
        Some(d)
    }

    pub(crate) fn recv(&mut self) -> Option<Bytes> {
        self.recv_with_timestamp().map(|(data, _)| data)
    }

    pub(crate) fn recv_with_timestamp(&mut self) -> Option<(Bytes, Option<u64>)> {
        let (data, timestamp) = self.incoming.pop_front()?;
        self.recv_buffered -= data.len();
        Some((data, timestamp))
    }

    pub(crate) fn has_outgoing(&self) -> bool {
        !self.outgoing.is_empty()
    }

    /// Whether a measurement datagram is queued.
    pub(crate) fn has_measurement(&self) -> bool {
        self.outgoing.iter().any(|d| d.measurement)
    }

    /// Whether the `index`th queued datagram is a measurement.
    pub(crate) fn is_measurement_at(&self, index: usize) -> bool {
        self.outgoing.get(index).is_some_and(|d| d.measurement)
    }

    pub(crate) fn outgoing_len(&self) -> usize {
        self.outgoing.len()
    }

    pub(crate) fn outgoing_bytes(&self) -> usize {
        self.outgoing_total
    }

    pub(crate) fn incoming_len(&self) -> usize {
        self.incoming.len()
    }

    pub(crate) fn snapshot_stats(&self) -> DatagramStats {
        DatagramStats {
            bypass_trips: self.breaker.trips(),
            bypass_active: self.breaker.active(),
            ..self.stats
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(len: usize) -> Bytes {
        Bytes::from(vec![7u8; len])
    }

    #[test]
    fn queue_drops_oldest_when_asked() {
        let mut st = DatagramState::default();
        st.queue(Bytes::from(vec![1u8; 40]), true, 100).unwrap();
        st.queue(Bytes::from(vec![2u8; 40]), true, 100).unwrap();
        st.queue(Bytes::from(vec![3u8; 40]), true, 100).unwrap();
        assert_eq!(st.outgoing_len(), 2);
        assert_eq!(st.outgoing_bytes(), 80);
        assert_eq!(st.stats.dropped_outgoing, 1);
        assert_eq!(st.pop_fitting(1000).unwrap().data[0], 2);
        assert_eq!(st.pop_fitting(1000).unwrap().data[0], 3);
        assert!(st.pop_fitting(1000).is_none());
    }

    #[test]
    fn queue_reports_blocked_without_dropping() {
        let mut st = DatagramState::default();
        st.queue(bytes(60), false, 100).unwrap();
        let blocked = st.queue(bytes(60), false, 100);
        assert_eq!(blocked, Err(SendDatagramError::Blocked(bytes(60))));
        assert_eq!(st.outgoing_len(), 1);
        assert_eq!(st.stats.dropped_outgoing, 0);
    }

    #[test]
    fn receive_window_drops_oldest_and_rejects_oversized() {
        let mut st = DatagramState::default();
        assert!(st.received(bytes(40), Some(100), Some(10)).unwrap());
        assert!(!st.received(Bytes::from(vec![2u8; 40]), Some(100), Some(20)).unwrap());
        // A third 40-byte datagram evicts the oldest one.
        st.received(Bytes::from(vec![3u8; 40]), Some(100), Some(30)).unwrap();
        assert_eq!(st.incoming_len(), 2);
        assert_eq!(st.stats.dropped_incoming, 1);
        let (data, timestamp) = st.recv_with_timestamp().unwrap();
        assert_eq!((data[0], timestamp), (2, Some(20)));
        let (data, timestamp) = st.recv_with_timestamp().unwrap();
        assert_eq!((data[0], timestamp), (3, Some(30)));
        assert!(st.recv().is_none());

        assert_eq!(
            st.received(bytes(101), Some(100), None),
            Err(Error::ProtocolViolation)
        );
        assert_eq!(st.received(bytes(1), None, None), Err(Error::ProtocolViolation));
    }

    #[test]
    fn shrinking_size_drops_oversized_queued_datagrams() {
        let mut st = DatagramState::default();
        st.drop_oversized(1400);
        st.queue(bytes(1300), false, 10_000).unwrap();
        st.queue(bytes(900), false, 10_000).unwrap();
        st.drop_oversized(1400);
        assert_eq!(st.outgoing_len(), 2);
        st.drop_oversized(1000);
        assert_eq!(st.outgoing_len(), 1);
        assert_eq!(st.outgoing_bytes(), 900);
        assert_eq!(st.stats.dropped_outgoing, 1);
        assert_eq!(st.pop_fitting(2000).unwrap().data.len(), 900);
    }

    #[test]
    fn pop_fitting_keeps_head_that_does_not_fit() {
        let mut st = DatagramState::default();
        st.queue(bytes(100), false, 10_000).unwrap();
        // type (1) + length varint (2) + 100 payload bytes
        assert_eq!(st.outgoing.front().unwrap().frame_len(), 103);
        assert!(st.pop_fitting(102).is_none());
        assert_eq!(st.outgoing_len(), 1);
        assert!(st.pop_fitting(103).is_some());
        assert_eq!(st.stats.sent, 1);
    }

    #[test]
    fn a_packet_takes_datagrams_of_one_flow_only() {
        let mut st = DatagramState::default();
        for flow in [Some(1), Some(1), Some(2), None] {
            st.queue_with_flow(bytes(100), flow, false, 10_000).unwrap();
        }
        let mut packet_flow = None;
        assert_eq!(st.pop_fitting_in_packet(2000, &mut packet_flow, false).unwrap().flow, Some(1));
        assert_eq!(st.pop_fitting_in_packet(2000, &mut packet_flow, false).unwrap().flow, Some(1));
        assert!(st.pop_fitting_in_packet(2000, &mut packet_flow, false).is_none());
        assert_eq!(packet_flow, Some(Some(1)));
        // The next packet starts with the flow that was left behind.
        let mut packet_flow = None;
        assert_eq!(st.pop_fitting_in_packet(2000, &mut packet_flow, false).unwrap().flow, Some(2));
        assert!(st.pop_fitting_in_packet(2000, &mut packet_flow, false).is_none());
        let mut packet_flow = None;
        assert_eq!(st.pop_fitting_in_packet(2000, &mut packet_flow, false).unwrap().flow, None);
        assert!(st.pop_fitting_in_packet(2000, &mut packet_flow, false).is_none());
    }

    #[test]
    fn a_path_takes_only_its_flows_and_keeps_each_flow_in_order() {
        let mut st = DatagramState::default();
        for (marker, flow) in [(1u8, Some(1)), (2, Some(2)), (3, Some(1)), (4, Some(2))] {
            st.queue_with_flow(Bytes::from(vec![marker; 100]), flow, false, 10_000)
                .unwrap();
        }
        // Flow 2 is on this path, flow 1 elsewhere.
        let mut packet_flow = None;
        let on_path = |flow: Option<u32>| flow == Some(2);
        assert_eq!(st.pop_fitting_for_path(2000, &mut packet_flow, false, on_path).unwrap().data[0], 2);
        assert_eq!(st.pop_fitting_for_path(2000, &mut packet_flow, false, on_path).unwrap().data[0], 4);
        assert!(st.pop_fitting_for_path(2000, &mut packet_flow, false, on_path).is_none());
        assert_eq!(st.outgoing_len(), 2);
        assert_eq!(st.outgoing_bytes(), 200);

        // A flow's datagram that does not fit holds back the rest of its flow.
        st.queue_with_flow(bytes(50), Some(1), false, 10_000).unwrap();
        let mut packet_flow = None;
        assert!(st
            .pop_fitting_for_path(90, &mut packet_flow, false, |flow| flow == Some(1))
            .is_none());
        assert_eq!(st.outgoing_len(), 3);
    }

    #[test]
    fn a_flow_keeps_its_path_within_a_flowlet() {
        let ms = Duration::from_millis;
        let t0 = Instant::now();
        let mut flows = FlowPaths::default();
        let gap = ms(50);
        assert_eq!(flows.current(Some(7), t0, gap, |_| true), None);
        flows.place(Some(7), 3, t0);
        flows.on_sent(Some(7), t0 + ms(40));
        assert_eq!(flows.current(Some(7), t0 + ms(80), gap, |_| true), Some(3));
        // The path can no longer be used.
        assert_eq!(flows.current(Some(7), t0 + ms(80), gap, |p| p != 3), None);
        // A pause longer than the gap ends the flowlet.
        assert_eq!(flows.current(Some(7), t0 + ms(91), gap, |_| true), None);
        // Flows without a hash are one flow of their own.
        flows.place(None, 1, t0);
        assert_eq!(flows.current(None, t0, gap, |_| true), Some(1));
        assert_eq!(flows.current(Some(7), t0 + ms(41), gap, |_| true), Some(3));
    }

    #[test]
    fn silent_flows_are_forgotten() {
        let t0 = Instant::now();
        let mut flows = FlowPaths::default();
        flows.place(Some(1), 0, t0);
        flows.place(Some(2), 0, t0 + FLOW_FORGET_AFTER + Duration::from_secs(1));
        assert_eq!(flows.len(), 1);
    }

    /// A measurement datagram is taken ahead of the bulk when only
    /// measurements may go (a closed window or a tripped breaker), whatever
    /// its place in the queue; the bulk stays.
    #[test]
    fn only_measurements_are_taken_when_the_bulk_is_held_back() {
        let mut st = DatagramState::default();
        st.queue_with_flow(bytes(100), Some(1), false, 10_000).unwrap();
        st.queue_measurement(bytes(20), Some(7), false, 10_000).unwrap();
        st.queue_with_flow(bytes(100), Some(1), false, 10_000).unwrap();
        assert!(st.has_measurement());
        assert!(!st.is_measurement_at(0) && st.is_measurement_at(1));

        let mut packet_flow = None;
        let d = st.pop_fitting_in_packet(2000, &mut packet_flow, true).unwrap();
        assert!(d.measurement);
        assert_eq!(d.flow, Some(7));
        // Nothing but the bulk is left, and it does not go.
        assert!(!st.has_measurement());
        let mut packet_flow = None;
        assert!(st.pop_fitting_in_packet(2000, &mut packet_flow, true).is_none());
        assert!(st
            .pop_fitting_for_path(2000, &mut packet_flow, true, |_| true)
            .is_none());
        assert_eq!(st.outgoing_len(), 2);
        assert_eq!(st.outgoing_bytes(), 200);
    }

    #[test]
    fn a_breaker_that_never_trips_stays_active_under_loss() {
        let srtt = Duration::from_millis(10);
        let t0 = Instant::now();
        let mut b = BypassBreaker::default();
        b.set_enabled(true);
        b.set_trips(false);
        b.on_tick(t0, srtt);
        for i in 1..=(BYPASS_BAD_ROUND_TRIPS * 3) {
            b.on_acked(1);
            b.on_lost(9);
            assert!(!b.on_tick(t0 + srtt * i, srtt));
        }
        assert!(b.active());
        // Re-enabling the bypass keeps the setting.
        b.set_enabled(true);
        for i in 1..=(BYPASS_BAD_ROUND_TRIPS * 3) {
            b.on_lost(9);
            b.on_tick(t0 + srtt * (100 + i), srtt);
        }
        assert!(b.active());
    }

    #[test]
    fn breaker_trips_after_consecutive_lossy_round_trips() {
        let srtt = Duration::from_millis(10);
        let t0 = Instant::now();
        let mut b = BypassBreaker::default();
        assert!(!b.active());
        b.set_enabled(true);
        assert!(b.active());

        // Start the window.
        assert!(!b.on_tick(t0, srtt));
        for i in 1..=BYPASS_BAD_ROUND_TRIPS {
            b.on_acked(8);
            b.on_lost(2);
            let tripped = b.on_tick(t0 + srtt * i, srtt);
            assert_eq!(tripped, i == BYPASS_BAD_ROUND_TRIPS);
        }
        assert!(!b.active());
        assert_eq!(b.trips(), 1);

        // Re-enabling resets the breaker and keeps the trip count.
        b.set_enabled(true);
        assert!(b.active());
        assert_eq!(b.trips(), 1);
    }

    #[test]
    fn breaker_resets_on_a_clean_round_trip() {
        let srtt = Duration::from_millis(10);
        let t0 = Instant::now();
        let mut b = BypassBreaker::default();
        b.set_enabled(true);
        b.on_tick(t0, srtt);
        let mut t = t0;
        for _ in 0..10 {
            b.on_acked(8);
            b.on_lost(2);
            t += srtt;
            b.on_tick(t, srtt);
            b.on_acked(10);
            t += srtt;
            assert!(!b.on_tick(t, srtt));
        }
        assert!(b.active());
    }
}
