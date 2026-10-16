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

use std::any::Any;
use std::cmp;
use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::time;
use std::time::Duration;
use std::time::Instant;

use slab::Slab;

use super::pmtu::Dplpmtud;
use super::recovery::Recovery;
use super::timer;
use crate::connection::SpaceId;
use crate::error::Error;
use crate::multipath_scheduler::MultipathScheduler;
use crate::FourTuple;
use crate::PathStats;
use crate::RecoveryConfig;
use crate::Result;
use crate::TIMER_GRANULARITY;

pub(crate) const INITIAL_CHAL_TIMEOUT: u64 = 25;

pub(crate) const MAX_PROBING_TIMEOUTS: usize = 8;

/// Consecutive PTOs after which a validated path is backed off: data
/// scheduling passes it over and its in-flight data moves to the other paths.
/// Probes, ACKs and keep-alives still use it, and any ACK ends the back-off.
/// PTOs only drive recovery; whether the path is dead is decided by time
/// (the host's idle timeout on `PathStats::idle_time`), as in noq.
pub(crate) const PATH_BACKOFF_PTO_COUNT: usize = 3;

/// The kinds of active paths the multipath schedulers pass over, see
/// `PathMap::held_back`.
#[derive(Clone, Copy)]
pub(crate) struct HeldBack {
    standby: bool,
    backed_off: bool,
}

impl HeldBack {
    /// Whether the schedulers must pass over `path` for data.
    pub(crate) fn applies(&self, path: &Path) -> bool {
        (self.standby && path.standby()) || (self.backed_off && path.backed_off())
    }

    /// Whether `path` is passed over because it is backed off, as opposed
    /// to standby: such a path then also carries no data in its probes.
    pub(crate) fn applies_backed_off(&self, path: &Path) -> bool {
        self.backed_off && path.backed_off()
    }
}

pub(crate) const MAX_PATH_CHALS_RECV: usize = 8;

pub(crate) const MIN_PATH_PROBE_SIZE: usize = 64;

/// A network path on which QUIC packets can be sent.
pub struct Path {
    /// The local address.
    local_addr: SocketAddr,

    /// The remote address.
    remote_addr: SocketAddr,

    /// Source CID sequence number used over that path.
    pub(crate) scid_seq: Option<u64>,

    /// Destination CID sequence number used over that path.
    pub(crate) dcid_seq: Option<u64>,

    /// Peer context for the path.
    pub(crate) peer_context: Option<Box<dyn Any + Send + Sync>>,

    /// Is this path used to send non-probing packets. By default, the initial
    /// path is active and the others are not active.
    active: bool,

    /// Optional send-rate target supplied by an external path optimizer.
    ///
    /// `None` keeps the scheduler's native BBR/RTT weighting. `Some(0)` keeps
    /// the path available for validation and recovery traffic but excludes it
    /// from non-probing data scheduling. A positive value is authoritative and
    /// must not be reweighted by the scheduler's latency/bandwidth knob.
    scheduler_target_rate: Option<u64>,

    /// A backup path chosen by an external path optimizer: it carries data
    /// only when no non-standby path is active (see `PathMap::held_back`).
    /// Validation, acknowledgements and keep-alives are unaffected.
    standby: bool,

    /// Loss recovery and congestion control.
    pub(crate) recovery: Recovery,

    /// The current validation state of the path.
    state: PathState,

    /// Received path challenge data.
    recv_chals: VecDeque<[u8; 8]>,

    /// Pending challenge data with the size of the packet containing them.
    sent_chals: VecDeque<([u8; 8], usize, time::Instant, time::Instant)>,

    /// Whether it requires sending PATH_CHALLENGE?
    need_send_challenge: bool,

    /// Number of consecutive path probing packets lost.
    lost_chal: usize,

    /// The maximum challenge size that got acknowledged.
    max_challenge_size: usize,

    /// Whether the peer's address has been verified.
    pub(super) verified_peer_address: bool,

    /// Whether the peer has verified our address.
    pub(super) peer_verified_local_address: bool,

    /// Total bytes the server can send before the client's address is verified.
    pub(super) anti_ampl_limit: usize,

    /// The current pmtu probing state of the path.
    pub(super) dplpmtud: Dplpmtud,

    /// Whether a Ping frame should be sent on the path.
    pub(super) need_send_ping: bool,

    /// Trace id.
    trace_id: String,

    /// Packet number space for current path in MPQUIC mode.
    pub(crate) space_id: SpaceId,

    /// Whether the path has been abandoned in MPQUIC mode.
    pub(super) is_abandon: bool,

    /// When an abandoned path is discarded: 3 PTO after PATH_ABANDON was sent
    /// or received, long enough for the peer's last packets and ACKs to land.
    drain_deadline: Option<time::Instant>,

    /// Identifies the path within the connection, never reused (a 4-tuple
    /// opened again is a new path). The initial path is 0.
    serial: u64,

    /// When a packet last arrived on the path (creation time before that).
    last_recv_time: time::Instant,

    /// Whether the in-flight data was already handed to the other paths for
    /// the current back-off; reset by the next ACK.
    backoff_flushed: bool,

    /// The peer address last reported to the peer in an OBSERVED_ADDRESS
    /// frame on this path (draft-ietf-quic-address-discovery).
    observed_addr_reported: Option<SocketAddr>,

    /// Our address as reported by the peer on this path, with the sequence
    /// number of the frame carrying it.
    peer_observed_addr: Option<(u64, SocketAddr)>,
}

impl Path {
    /// Create a new path
    pub(crate) fn new(
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        is_initial: bool,
        conf: &RecoveryConfig,
        trace_id: &str,
    ) -> Self {
        let (state, scid_seq, dcid_seq) = if is_initial {
            (PathState::Validated, Some(0), Some(0))
        } else {
            (PathState::Unknown, None, None)
        };

        let dplpmtud = Dplpmtud::new(
            conf.enable_dplpmtud,
            conf.max_datagram_size,
            Self::is_ipv6(&remote_addr),
        );

        Self {
            local_addr,
            remote_addr,
            scid_seq,
            dcid_seq,
            peer_context: None,
            active: false,
            scheduler_target_rate: None,
            standby: false,
            recovery: Recovery::new(conf),
            state,
            recv_chals: VecDeque::new(),
            sent_chals: VecDeque::new(),
            need_send_challenge: false,
            lost_chal: 0,
            max_challenge_size: 0,
            verified_peer_address: false,
            peer_verified_local_address: false,
            anti_ampl_limit: 0,
            dplpmtud,
            need_send_ping: false,
            trace_id: trace_id.to_string(),
            space_id: SpaceId::Data,
            is_abandon: false,
            drain_deadline: None,
            serial: 0,
            last_recv_time: time::Instant::now(),
            backoff_flushed: false,
            observed_addr_reported: None,
            peer_observed_addr: None,
        }
    }

    /// Update trace id, appending path id.
    #[doc(hidden)]
    pub fn update_trace_id(&mut self, path_id: usize) {
        self.trace_id.push_str(&(format!("-{}", path_id)));
        self.recovery.set_trace_id(&self.trace_id);
    }

    /// Return the local address of the path.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Return the remote address of the path.
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Handle incoming PATH_CHALLENGE data.
    pub(super) fn on_path_chal_received(&mut self, data: [u8; 8]) {
        if self.recv_chals.len() >= MAX_PATH_CHALS_RECV {
            let _ = self.recv_chals.pop_front();
        }

        self.recv_chals.push_back(data);
        self.peer_verified_local_address = true;
    }

    /// Handle incoming PATH_RESPONSE data.
    /// Return true if the path status changes to `Validated`.
    pub(super) fn on_path_resp_received(&mut self, data: [u8; 8], multipath: bool) -> bool {
        if self.state == PathState::Validated {
            return false;
        }

        self.verified_peer_address = true;
        self.lost_chal = 0;

        // The 4-tuple is reachable, but we didn't check Path MTU yet.
        let mut challenge_size = 0;
        self.sent_chals.retain(|(d, s, sent_time, _)| {
            if *d == data {
                challenge_size = *s;
                // Use the delay between sending a PATH_CHALLENGE and receiving a PATH_RESPONSE
                // to set the initial RTT for the new path. This delay should not be considered
                // an RTT sample.
                let initial_rtt = Instant::now().duration_since(*sent_time);
                self.recovery.rtt.try_set_init_rtt(initial_rtt);
                false
            } else {
                true
            }
        });
        self.max_challenge_size = std::cmp::max(self.max_challenge_size, challenge_size);
        self.promote_to(PathState::ValidatingMTU);

        // The MTU was validated
        if self.max_challenge_size >= crate::MIN_CLIENT_INITIAL_LEN {
            self.promote_to(PathState::Validated);
            self.set_active(multipath);
            self.sent_chals.clear();
            return true;
        }

        // If the MTU was not validated, probe again.
        self.need_send_challenge = true;
        false
    }

    /// Fetch a received challenge data item.
    pub(super) fn pop_recv_chal(&mut self) -> Option<[u8; 8]> {
        self.recv_chals.pop_front()
    }

    /// Return whether path validation has been initialed.
    pub(super) fn path_chal_initiated(&self) -> bool {
        self.need_send_challenge
    }

    /// Request path validation.
    pub(super) fn initiate_path_chal(&mut self) {
        self.need_send_challenge = true;
    }

    /// Handle sent event of PATH_CHALLENGE
    pub(super) fn on_path_chal_sent(
        &mut self,
        data: [u8; 8],
        pkt_size: usize,
        sent_time: time::Instant,
    ) {
        self.promote_to(PathState::Validating);
        self.need_send_challenge = false;

        // Use exponential back-off because the RTT of the new path is unknown.
        let loss_time =
            sent_time + time::Duration::from_millis(INITIAL_CHAL_TIMEOUT << self.lost_chal);

        self.sent_chals
            .push_back((data, pkt_size, sent_time, loss_time));
    }

    /// Handle timeout of PATH_CHALLENGE
    pub(super) fn on_path_chal_timeout(&mut self, now: time::Instant) {
        if self.state != PathState::Validating && self.state != PathState::ValidatingMTU {
            return;
        }

        // Remove the lost challenges.
        while let Some(first_chal) = self.sent_chals.front() {
            if first_chal.3 > now {
                return;
            }

            self.sent_chals.pop_front();
            self.lost_chal += 1;

            if self.lost_chal < MAX_PROBING_TIMEOUTS {
                // Try to initiate path validation again.
                self.initiate_path_chal();
            } else {
                // The Path validation eventually failed.
                self.state = PathState::Failed;
                self.active = false;
                self.sent_chals.clear();
                return;
            }
        }
    }

    /// Set peer context
    pub fn set_peer_context<T: Any + Send + Sync>(&mut self, ctx: T) {
        self.peer_context = Some(Box::new(ctx));
    }

    /// Get peer context
    pub fn peer_context(&mut self) -> Option<&mut dyn Any> {
        match self.peer_context {
            Some(ref mut data) => Some(data.as_mut()),
            None => None,
        }
    }

    /// Whether PATH_CHALLENGE or PATH_RESPONSE should be sent on the path.
    pub(super) fn need_send_validation_frames(&self, is_server: bool) -> bool {
        if is_server && self.anti_ampl_limit < MIN_PATH_PROBE_SIZE {
            return false;
        }

        self.need_send_challenge || !self.recv_chals.is_empty()
    }

    /// Whether the datagrams sent on the unvalidated path should be expanded
    /// to least the maximum datagram size
    pub(super) fn need_expand_padding_frames(&self, is_server: bool) -> bool {
        if self.validated() {
            return false;
        }
        if is_server && self.anti_ampl_limit <= self.recovery.max_datagram_size {
            return false;
        }
        true
    }

    /// Promote the path to the provided state.
    fn promote_to(&mut self, state: PathState) {
        if self.state < state {
            self.state = state;
        }
    }

    /// Return whether the path is validated.
    pub fn validated(&self) -> bool {
        self.state == PathState::Validated
    }

    /// Return whether the path is used to send non-probing packets.
    pub fn active(&self) -> bool {
        self.active && self.dcid_seq.is_some()
    }

    /// Set the active state of the path
    pub(crate) fn set_active(&mut self, v: bool) {
        self.active = v;
    }

    /// Set the externally optimized send-rate target for this path.
    ///
    /// MP_SQM_PLAN.md S2.4: also forwarded straight into the path's own
    /// congestion controller (`CongestionController::set_target_rate`).
    /// Every measurement-driven algorithm keeps this a no-op default; for
    /// `Brutal` specifically, this rate *is* its congestion window/pacing
    /// rate input, so an MP max-flow allocation becomes each path's actual
    /// Brutal send rate directly, with no separate negotiation channel
    /// between the optimizer and the congestion controller.
    pub(crate) fn set_scheduler_target_rate(&mut self, rate: Option<u64>) {
        self.scheduler_target_rate = rate;
        self.recovery.congestion.set_target_rate(rate);
        if rate == Some(0) {
            self.active = false;
        } else if self.validated() && !self.is_abandon {
            self.active = true;
        }
    }

    /// Return the externally optimized send-rate target for this path.
    pub(crate) fn scheduler_target_rate(&self) -> Option<u64> {
        self.scheduler_target_rate
    }

    /// Mark this path as a standby (backup) path, or a regular one again.
    pub(crate) fn set_standby(&mut self, standby: bool) {
        self.standby = standby;
    }

    /// Whether this path is a standby (backup) path.
    pub fn standby(&self) -> bool {
        self.standby
    }

    /// Whether ACKs for this path's packet number space may be sent on it.
    /// A path the scheduler holds idle (target rate 0) keeps acknowledging
    /// what the peer sends on it; otherwise the peer's packets there are never
    /// acked and its data stalls behind PTO probes.
    pub(crate) fn can_send_ack(&self) -> bool {
        self.active || (self.validated() && !self.is_abandon)
    }

    /// Mark this path as abandoned by the host.
    pub(crate) fn abandon(&mut self) {
        self.is_abandon = true;
        self.active = false;
        self.scheduler_target_rate = Some(0);
    }

    /// PMTU black hole detection (RFC 8899 Section 4.3): large packets keep
    /// getting lost while smaller ones sent after them are acknowledged and
    /// none of the large ones is. Consecutive PTOs are no evidence: a PMTU
    /// black hole still passes small packets (whose ACKs reset the PTO
    /// count), while an outage or an overloaded path drops everything.
    /// Falls back to the base PMTU and returns the new size.
    pub(super) fn check_pmtu_black_hole(&mut self) -> Option<usize> {
        if !self.recovery.take_pmtu_black_hole() || !self.dplpmtud.on_black_hole() {
            return None;
        }
        let current = self.dplpmtud.get_current_size();
        self.recovery.update_max_datagram_size(current, false);
        Some(current)
    }

    /// Whether this path was abandoned, by the host or by the peer.
    pub fn is_abandoned(&self) -> bool {
        self.is_abandon
    }

    /// Whether the validated path is backed off: its PTOs keep firing, so
    /// data scheduling passes it over (see `PATH_BACKOFF_PTO_COUNT`).
    pub(crate) fn backed_off(&self) -> bool {
        self.validated() && self.recovery.pto_count() >= PATH_BACKOFF_PTO_COUNT
    }

    /// Note that the in-flight data was handed over for this back-off.
    /// Returns whether it is the first time.
    pub(crate) fn mark_backoff_flushed(&mut self) -> bool {
        !std::mem::replace(&mut self.backoff_flushed, true)
    }

    /// An ACK arrived: the back-off, if any, is over.
    pub(crate) fn on_ack_progress(&mut self) {
        if self.recovery.pto_count() == 0 {
            self.backoff_flushed = false;
        }
    }

    /// A packet arrived on the path.
    pub(crate) fn on_packet_received(&mut self, now: time::Instant) {
        self.last_recv_time = now;
    }

    /// Time since a packet last arrived on the path.
    pub(crate) fn idle_time(&self, now: time::Instant) -> Duration {
        now.saturating_duration_since(self.last_recv_time)
    }

    /// Start draining an abandoned path: it is discarded 3 PTO from `now`
    /// (draft-ietf-quic-multipath, as in noq's `PathDrained`). No-op if the
    /// path is not abandoned or already draining.
    pub(crate) fn start_drain(&mut self, now: time::Instant, max_ack_delay: time::Duration) {
        if self.is_abandon && self.drain_deadline.is_none() {
            let pto = self.recovery.rtt.pto_base() + max_ack_delay;
            self.drain_deadline = Some(now + 3 * pto);
        }
    }

    /// When the abandoned path is to be discarded, once draining has started.
    pub(crate) fn drain_deadline(&self) -> Option<time::Instant> {
        self.drain_deadline
    }

    /// Identifies this path within the connection, see `PathLifecycleEvent`.
    pub fn serial(&self) -> u64 {
        self.serial
    }

    /// Set the serial of a path about to be inserted.
    pub(crate) fn set_serial(&mut self, serial: u64) {
        self.serial = serial;
    }

    /// Return whether the path is unused.
    fn unused(&self) -> bool {
        !self.active && self.dcid_seq.is_none()
    }

    /// Whether the peer's current address still has to be reported to it.
    pub(super) fn need_report_observed_addr(&self) -> bool {
        self.validated() && self.observed_addr_reported != Some(self.remote_addr)
    }

    /// Record that the peer's current address was reported to it.
    pub(super) fn on_observed_addr_reported(&mut self) {
        self.observed_addr_reported = Some(self.remote_addr);
    }

    /// Report `addr` again if the frame carrying it was lost while it is
    /// still the peer's address on this path.
    pub(super) fn on_observed_addr_lost(&mut self, addr: SocketAddr) {
        if self.observed_addr_reported == Some(addr) && self.remote_addr == addr {
            self.observed_addr_reported = None;
        }
    }

    /// Handle an OBSERVED_ADDRESS frame received on this path. Frames with
    /// a sequence number not above the last processed one are ignored.
    /// Return true if the observed address was updated.
    pub(super) fn on_observed_addr_received(&mut self, seq_num: u64, addr: SocketAddr) -> bool {
        if self
            .peer_observed_addr
            .is_some_and(|(last, _)| seq_num <= last)
        {
            return false;
        }
        self.peer_observed_addr = Some((seq_num, addr));
        true
    }

    /// Name of the loss detection used on this path.
    pub fn loss_detection_name(&self) -> &'static str {
        self.recovery.loss_detection_name()
    }

    /// Our address on this path as reported by the peer.
    pub fn observed_local_addr(&self) -> Option<SocketAddr> {
        self.peer_observed_addr.map(|(_, addr)| addr)
    }

    /// Update and return the latest statistics about the path
    pub fn stats(&mut self) -> &PathStats {
        self.recovery.stat_lazy_update();
        self.recovery.stats.observed_local_addr = self.observed_local_addr();
        self.recovery.stats.scheduler_target_rate_valid = self.scheduler_target_rate.is_some();
        self.recovery.stats.scheduler_target_rate = self.scheduler_target_rate.unwrap_or_default();
        self.recovery.stats.idle_time = self.idle_time(time::Instant::now()).as_micros() as u64;
        &self.recovery.stats
    }

    /// Return the validation state of the path
    pub fn state(&self) -> PathState {
        self.state
    }

    /// Return true if the given address is a pure IPv6 address, rather than an
    /// IPv4-mapped IPv6 address.
    fn is_ipv6(addr: &SocketAddr) -> bool {
        if let IpAddr::V6(ip) = addr.ip() {
            if !matches!(ip.segments(), [0, 0, 0, 0, 0, 0xffff, _, _]) {
                return true;
            }
        }
        false
    }
}

impl std::fmt::Debug for Path {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "local={:?} ", self.local_addr)?;
        write!(f, "remote={:?}", self.remote_addr)?;
        Ok(())
    }
}

/// The states about the path validation.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum PathState {
    /// The path validation failed
    Failed,

    /// No path validation has been performed.
    Unknown,

    /// The path is under validation.
    Validating,

    /// The remote address has been validated, but not the path MTU.
    ValidatingMTU,

    /// The path has been validated.
    Validated,
}

/// Path manager for a QUIC connection
pub(crate) struct PathMap {
    /// The paths of the connection. Each path has a path identifier
    /// used by `addrs`.
    paths: Slab<Path>,

    /// The maximum number of paths allowed.
    max_paths: usize,

    /// The mapping from the (local `SocketAddr`, peer `SocketAddr`) to the
    /// `Path` identifier.
    addrs: BTreeMap<(SocketAddr, SocketAddr), usize>,

    /// The anti-amplification factor.
    pub(crate) anti_ampl_factor: usize,

    /// Whether the multipath extension is successfully negotiated.
    is_multipath: bool,

    /// Whether it serves as a server.
    is_server: bool,
}

impl PathMap {
    pub fn new(
        mut initial_path: Path,
        max_paths: usize,
        anti_ampl_factor: usize,
        is_server: bool,
    ) -> Self {
        // As it is the first path, it is active by default.
        initial_path.active = true;
        let local_addr = initial_path.local_addr;
        let remote_addr = initial_path.remote_addr;

        let mut paths = Slab::with_capacity(2);
        let active_path_id = paths.insert(initial_path);

        if let Some(path) = paths.get_mut(active_path_id) {
            path.update_trace_id(active_path_id);
        }

        let mut addrs = BTreeMap::new();
        addrs.insert((local_addr, remote_addr), active_path_id);

        Self {
            paths,
            max_paths,
            addrs,
            anti_ampl_factor,
            is_multipath: false,
            is_server,
        }
    }

    /// Get an immutable reference to the path identified by `path_id`
    pub fn get(&self, path_id: usize) -> Result<&Path> {
        self.paths.get(path_id).ok_or(Error::InternalError)
    }

    /// Get an mutable reference to the path identified by `path_id`
    pub fn get_mut(&mut self, path_id: usize) -> Result<&mut Path> {
        self.paths.get_mut(path_id).ok_or(Error::InternalError)
    }

    /// Get the `Path` identifier related to the given `addrs`.
    ///
    /// The address tuple `addrs` is (local address, remote address)
    pub fn get_path_id(&self, addrs: &(SocketAddr, SocketAddr)) -> Option<usize> {
        self.addrs.get(addrs).copied()
    }

    /// Get an mutable reference to the active path.
    pub fn get_active(&self) -> Result<&Path> {
        Ok(self.get_active_with_path_id()?.1)
    }

    /// Get an mutable reference to the active path.
    pub fn get_active_mut(&mut self) -> Result<&mut Path> {
        let path = self.paths.iter_mut().find(|(_, p)| p.active);
        Ok(path.ok_or(Error::InternalError)?.1)
    }

    /// Get the `Path` identifier related to the active path.
    pub fn get_active_path_id(&self) -> Result<usize> {
        Ok(self.get_active_with_path_id()?.0)
    }

    /// Get an mutable reference to the active path with the value of the
    /// path identifier. If there is no active path, returns `None`.
    pub fn get_active_with_path_id(&self) -> Result<(usize, &Path)> {
        self.paths
            .iter()
            .find(|(_, p)| p.active)
            .ok_or(Error::InternalError)
    }

    /// Insert a new path
    pub fn insert_path(&mut self, path: Path) -> Result<usize> {
        // eliminate an unused path if the maximum paths limit is reached.
        // Abandoned paths are not handled here: dropping one needs the
        // connection (CIDs, packet number space), see
        // `Connection::discard_drained_paths`, which runs before this.
        if self.paths.len() >= self.max_paths {
            let (pid_to_remove, _) = self
                .paths
                .iter()
                .find(|(_, p)| p.unused())
                .ok_or(Error::Done)?;
            let path = self.paths.remove(pid_to_remove);
            self.addrs.remove(&(path.local_addr, path.remote_addr));
        }

        // insert new path
        let local_addr = path.local_addr;
        let remote_addr = path.remote_addr;

        let pid = self.paths.insert(path);
        self.addrs.insert((local_addr, remote_addr), pid);
        Ok(pid)
    }

    /// Remove the path identified by `path_id`, freeing its slot and 4-tuple.
    pub(crate) fn remove(&mut self, path_id: usize) -> Option<Path> {
        if !self.paths.contains(path_id) {
            return None;
        }
        let path = self.paths.remove(path_id);
        let key = (path.local_addr, path.remote_addr);
        if self.addrs.get(&key) == Some(&path_id) {
            self.addrs.remove(&key);
        }
        Some(path)
    }

    /// Whether every slot is taken.
    pub(crate) fn is_full(&self) -> bool {
        self.paths.len() >= self.max_paths
    }

    /// Return an immutable iterator over all existing paths.
    pub fn iter(&self) -> slab::Iter<Path> {
        self.paths.iter()
    }

    /// Return a mutable iterator over all existing paths.
    pub fn iter_mut(&mut self) -> slab::IterMut<Path> {
        self.paths.iter_mut()
    }

    /// Which active paths the schedulers pass over for data.
    ///
    /// Standby paths are held back while some active path is not a standby
    /// one (a full congestion window on it does not count as gone). Paths
    /// backed off after repeated PTOs are held back while some other active
    /// path is not backed off. Either takes over once nothing else is left.
    pub(crate) fn held_back(&self) -> HeldBack {
        let backed_off = self
            .paths
            .iter()
            .any(|(_, path)| path.active() && !path.backed_off());
        let standby = self.paths.iter().any(|(_, path)| {
            path.active() && !path.standby() && !(backed_off && path.backed_off())
        });
        HeldBack { standby, backed_off }
    }

    /// Return the number of all paths
    pub fn len(&self) -> usize {
        self.paths.len()
    }

    /// Process a PATH_CHALLENGE frame on the give path
    pub fn on_path_chal_received(&mut self, path_id: usize, data: [u8; 8]) {
        if let Some(path) = self.paths.get_mut(path_id) {
            path.on_path_chal_received(data);
        }
    }

    /// Process a PATH_RESPONSE frame on the give path
    pub fn on_path_resp_received(&mut self, path_id: usize, data: [u8; 8]) -> bool {
        if let Some(path) = self.paths.get_mut(path_id) {
            return path.on_path_resp_received(data, self.is_multipath);
        }
        false
    }

    /// Handle the sent event of PATH_CHALLENGE.
    pub fn on_path_chal_sent(
        &mut self,
        path_id: usize,
        data: [u8; 8],
        pkt_size: usize,
        sent_time: time::Instant,
    ) -> Result<()> {
        let path = self.get_mut(path_id)?;
        path.on_path_chal_sent(data, pkt_size, sent_time);

        Ok(())
    }

    /// Handle timeout of PATH_CHALLENGE.
    pub fn on_path_chal_timeout(&mut self, now: time::Instant) {
        for (_, path) in self.paths.iter_mut() {
            path.on_path_chal_timeout(now);
        }
    }

    /// Return the lowest loss timer value among all paths.
    pub fn min_loss_detection_timer(&self) -> Option<time::Instant> {
        self.paths
            .iter()
            .filter_map(|(_, p)| p.recovery.loss_detection_timer())
            .min()
    }

    /// Return the lowest pacer timer value among all paths.
    pub fn min_pacer_timer(&self) -> Option<time::Instant> {
        self.paths
            .iter()
            .filter_map(|(_, p)| p.recovery.pacer_timer)
            .min()
    }

    /// Return the minimum timeout among all paths.
    pub fn min_path_chal_timer(&self) -> Option<time::Instant> {
        self.paths
            .iter()
            .filter_map(|(_, p)| p.sent_chals.front())
            .min_by_key(|&(_, _, _, loss_time)| loss_time)
            .map(|&(_, _, _, loss_time)| loss_time)
    }

    /// Return the maximum PTO among all paths.
    pub fn max_pto(&self) -> Option<Duration> {
        self.iter()
            .map(|(_, path)| path.recovery.rtt.pto_base())
            .max()
    }

    /// Increase send limit before address validation for server
    pub fn inc_anti_ampl_limit(&mut self, pid: usize, pkt_len: usize) {
        if !self.is_server {
            return;
        }
        if let Some(path) = self.paths.get_mut(pid) {
            if !path.verified_peer_address {
                let inc = self.anti_ampl_factor.saturating_mul(pkt_len);
                path.anti_ampl_limit = path.anti_ampl_limit.saturating_add(inc);
            }
        }
    }

    /// Decrease send limit before address validation for server
    pub fn dec_anti_ampl_limit(&mut self, pid: usize, pkt_len: usize) {
        if !self.is_server {
            return;
        }
        if let Some(path) = self.paths.get_mut(pid) {
            if !path.verified_peer_address {
                path.anti_ampl_limit = path.anti_ampl_limit.saturating_sub(pkt_len);
            }
        }
    }

    /// Return the min value between the given `left` and `anti_ampl_limit`
    pub fn cmp_anti_ampl_limit(&self, pid: usize, left: usize) -> usize {
        if !self.is_server {
            return left;
        }
        if let Some(path) = self.paths.get(pid) {
            if !path.verified_peer_address {
                return cmp::min(left, path.anti_ampl_limit);
            }
        }
        left
    }

    /// Schedule a Ping frame on the specified path or all active paths.
    pub fn mark_ping(&mut self, path_addr: Option<FourTuple>) -> Result<()> {
        // If multipath is not enabled, schedule a Ping frame on the current
        // active path.
        if !self.is_multipath {
            self.get_active_mut()?.need_send_ping = true;
            return Ok(());
        }

        // If multipath is enabled, schedule a Ping frame on the specified path
        // or all the active paths.
        if let Some(a) = path_addr {
            let pid = match self.get_path_id(&(a.local, a.remote)) {
                Some(pid) => pid,
                None => return Ok(()),
            };
            self.get_mut(pid)?.need_send_ping = true;
            return Ok(());
        }
        for (_, path) in self.paths.iter_mut() {
            if path.active() {
                path.need_send_ping = true;
            }
        }
        Ok(())
    }

    /// Promote to multipath mode.
    pub fn enable_multipath(&mut self) {
        self.is_multipath = true;
    }
}

#[cfg(test)]
mod observed_address_tests {
    use super::*;

    fn path(validated: bool) -> Path {
        let local: SocketAddr = "10.0.0.2:5000".parse().unwrap();
        let remote: SocketAddr = "198.51.100.9:443".parse().unwrap();
        Path::new(local, remote, validated, &RecoveryConfig::default(), "test")
    }

    #[test]
    fn report_waits_for_validation_and_happens_once() {
        let mut p = path(false);
        assert!(!p.need_report_observed_addr());
        let mut p = path(true);
        assert!(p.need_report_observed_addr());
        p.on_observed_addr_reported();
        assert!(!p.need_report_observed_addr());
    }

    #[test]
    fn lost_report_is_resent_only_for_the_current_address() {
        let mut p = path(true);
        p.on_observed_addr_reported();
        p.on_observed_addr_lost("198.51.100.9:1".parse().unwrap());
        assert!(!p.need_report_observed_addr());
        p.on_observed_addr_lost(p.remote_addr());
        assert!(p.need_report_observed_addr());
    }

    #[test]
    fn stale_sequence_numbers_are_ignored() {
        let mut p = path(true);
        let a: SocketAddr = "203.0.113.1:1000".parse().unwrap();
        let b: SocketAddr = "203.0.113.2:2000".parse().unwrap();
        assert!(p.on_observed_addr_received(5, a));
        assert!(!p.on_observed_addr_received(4, b));
        assert!(!p.on_observed_addr_received(5, b));
        assert_eq!(p.observed_local_addr(), Some(a));
        assert!(p.on_observed_addr_received(6, b));
        assert_eq!(p.stats().observed_local_addr, Some(b));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::congestion_control::CongestionControlAlgorithm;
    use crate::congestion_control::CongestionController;
    use crate::connection::space::SentPacket;
    use std::net::IpAddr;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn new_test_recovery_config() -> RecoveryConfig {
        RecoveryConfig {
            max_datagram_size: 1200,
            max_ack_delay: time::Duration::from_millis(0),
            congestion_control_algorithm: CongestionControlAlgorithm::Bbr,
            min_congestion_window: 2_u64,
            initial_congestion_window: 10_u64,
            initial_rtt: crate::INITIAL_RTT,
            pto_linear_factor: crate::DEFAULT_PTO_LINEAR_FACTOR,
            max_pto: crate::MAX_PTO,
            ..RecoveryConfig::default()
        }
    }

    fn new_path_mgr(
        clients: &Vec<SocketAddr>,
        server: SocketAddr,
        path_num: usize,
        is_server: bool,
    ) -> Result<PathMap> {
        assert!(clients.len() > 0);

        let conf = new_test_recovery_config();
        let initial_path = Path::new(clients[0], server, true, &conf, "");
        let mut path_mgr = PathMap::new(
            initial_path,
            path_num,
            crate::ANTI_AMPLIFICATION_FACTOR,
            is_server,
        );
        for i in 1..clients.len() {
            let new_path = Path::new(clients[i], server, false, &conf, "");
            path_mgr.insert_path(new_path)?;
        }
        Ok(path_mgr)
    }

    #[test]
    fn path_initial() -> Result<()> {
        let client_addrs = vec![SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            9443,
        )];
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        let mut path_mgr = new_path_mgr(&client_addrs, server_addr, 8, false)?;
        assert_eq!(path_mgr.len(), 1);
        assert_eq!(path_mgr.iter().count(), 1);
        assert_eq!(path_mgr.iter_mut().count(), 1);

        let client_addr = client_addrs[0];
        let pid = path_mgr
            .get_path_id(&(client_addr, server_addr))
            .ok_or(Error::InternalError)?;
        assert_eq!(pid, 0);
        assert_eq!(path_mgr.get(pid)?.local_addr(), client_addr);
        assert_eq!(path_mgr.get(pid)?.remote_addr(), server_addr);
        assert_eq!(path_mgr.get(pid)?.active(), true);
        assert_eq!(path_mgr.get(pid)?.unused(), false);
        assert_eq!(path_mgr.get_mut(pid)?.stats().recv_count, 0);
        assert_eq!(path_mgr.get_mut(pid)?.stats().sent_count, 0);
        assert!(path_mgr.get_mut(pid)?.stats().bandwidth_model_valid);
        assert_eq!(
            path_mgr.get_mut(pid)?.stats().congestion_control_state,
            crate::CongestionControlState::Startup
        );
        assert!(!path_mgr.get_mut(pid)?.stats().scheduler_target_rate_valid);
        path_mgr
            .get_mut(pid)?
            .set_scheduler_target_rate(Some(3_000_000));
        assert!(path_mgr.get_mut(pid)?.stats().scheduler_target_rate_valid);
        assert_eq!(
            path_mgr.get_mut(pid)?.stats().scheduler_target_rate,
            3_000_000
        );
        path_mgr.get_mut(pid)?.set_scheduler_target_rate(None);
        assert!(!path_mgr.get_mut(pid)?.stats().scheduler_target_rate_valid);
        assert_eq!(path_mgr.get_mut(pid)?.stats().scheduler_target_rate, 0);
        assert_eq!(path_mgr.get_active()?.local_addr(), client_addr);
        assert_eq!(path_mgr.get_active_mut()?.remote_addr(), server_addr);
        assert_eq!(path_mgr.get_active_path_id()?, 0);

        Ok(())
    }

    /// Real review finding (MP_SQM_PLAN.md S2.4): the first `Brutal::
    /// set_target_rate` implementation zeroed its rate outright on `None`,
    /// so the exact call `set_scheduler_target_rate` makes to restore native
    /// policy (`Path::set_scheduler_target_rate(None)`, e.g. once an MP
    /// allocation stops covering this path) would leave a live Brutal path
    /// stuck reporting a near-zero congestion window forever. Assert the
    /// window stays well above the one-MTU floor after exactly that call.
    #[test]
    fn brutal_path_keeps_a_real_window_after_target_rate_is_cleared() -> Result<()> {
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9460);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 460);
        let conf = RecoveryConfig {
            congestion_control_algorithm: CongestionControlAlgorithm::Brutal,
            brutal_bps: 1_000_000,
            ..new_test_recovery_config()
        };
        let mut path = Path::new(client_addr, server_addr, true, &conf, "");
        // Brutal reports a floor window before any RTT sample; give it one
        // through the real `CongestionController::on_ack` path so the actual
        // `bps * srtt * 2 / ack_rate` formula is exercised, not the no-RTT
        // floor (which would trivially pass regardless of this bug).
        let rtt_estimator = crate::connection::rtt::RttEstimator::new(Duration::from_millis(100));
        let now = time::Instant::now();
        let mut pkt = SentPacket {
            ack_eliciting: true,
            in_flight: true,
            sent_size: 1200,
            ..SentPacket::default()
        };
        path.recovery.congestion.on_sent(now, &mut pkt, 1200);
        path.recovery.congestion.begin_ack(now, 1200);
        path.recovery
            .congestion
            .on_ack(&mut pkt, now, false, &rtt_estimator, 0);

        path.set_scheduler_target_rate(Some(3_000_000));
        path.set_scheduler_target_rate(None);

        let cwnd = path.recovery.congestion.congestion_window();
        assert!(
            cwnd > conf.max_datagram_size as u64,
            "cwnd {cwnd} did not recover past one MTU after clearing the external target"
        );
        Ok(())
    }

    #[test]
    fn client_path_validation() -> Result<()> {
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9443);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        let conf = new_test_recovery_config();
        let initial_path = Path::new(client_addr, server_addr, true, &conf, "");
        let mut path_mgr = PathMap::new(initial_path, 8, crate::ANTI_AMPLIFICATION_FACTOR, false);

        // Add a new path and initiate path validation
        let client_addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9444);
        let new_path = Path::new(client_addr1, server_addr, false, &conf, "");
        path_mgr.insert_path(new_path)?;
        assert_eq!(path_mgr.len(), 2);

        let pid = path_mgr
            .get_path_id(&(client_addr1, server_addr))
            .ok_or(Error::InternalError)?;
        path_mgr.get_mut(pid)?.initiate_path_chal();
        assert!(path_mgr.get_mut(pid)?.need_send_validation_frames(false));
        assert_eq!(path_mgr.get_mut(pid)?.path_chal_initiated(), true);

        // Fake sending of PATH_CHALLENGE
        let data = rand::random::<[u8; 8]>();
        let now = time::Instant::now();
        path_mgr.on_path_chal_sent(pid, data, 100, now)?;
        assert_eq!(path_mgr.get_mut(pid)?.path_chal_initiated(), false);
        assert_eq!(path_mgr.get_mut(pid)?.validated(), false);
        assert_eq!(path_mgr.get_mut(pid)?.state, PathState::Validating);

        // Fake receiving of unmatched PATH_RESPONSE
        assert_eq!(path_mgr.on_path_resp_received(pid, [0xab; 8]), false);
        assert_eq!(path_mgr.get_mut(pid)?.state, PathState::ValidatingMTU);

        // Fake receiving of PATH_RESPONSE
        assert_eq!(path_mgr.on_path_resp_received(pid, data), false);
        assert_eq!(path_mgr.get_mut(pid)?.path_chal_initiated(), true);
        assert_eq!(path_mgr.get_mut(pid)?.validated(), false);
        assert_eq!(path_mgr.get_mut(pid)?.state, PathState::ValidatingMTU);

        // Fake sending of PATH_CHALLENGE
        path_mgr.on_path_chal_sent(pid, data, 1300, now)?;

        // Fake receiving of PATH_RESPONSE
        assert_eq!(path_mgr.on_path_resp_received(pid, data), true);
        assert_eq!(path_mgr.get_mut(pid)?.path_chal_initiated(), false);
        assert_eq!(path_mgr.get_mut(pid)?.validated(), true);
        assert_eq!(path_mgr.get_mut(pid)?.state, PathState::Validated);
        assert_eq!(path_mgr.get_mut(pid)?.sent_chals.len(), 0);

        // Fake receiving of depulicated PATH_RESPONSE
        assert_eq!(path_mgr.on_path_resp_received(pid, data), false);
        assert_eq!(path_mgr.get_mut(pid)?.validated(), true);

        // Timeout event
        path_mgr.on_path_chal_timeout(now + time::Duration::from_millis(INITIAL_CHAL_TIMEOUT));
        assert_eq!(path_mgr.get_mut(pid)?.lost_chal, 0);
        assert_eq!(path_mgr.get_mut(pid)?.sent_chals.len(), 0);
        assert_eq!(path_mgr.get_mut(pid)?.state, PathState::Validated);

        Ok(())
    }

    #[test]
    fn abandoned_path_is_immediately_removed_from_data_scheduling() -> Result<()> {
        let client_addrs = vec![SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            9450,
        )];
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 450);
        let mut path_mgr = new_path_mgr(&client_addrs, server_addr, 8, false)?;
        let path = path_mgr.get_mut(0)?;
        path.set_scheduler_target_rate(Some(50_000_000));

        path.abandon();

        assert!(path.is_abandon);
        assert!(
            !path.active(),
            "abandoned path must stop carrying payload immediately"
        );
        assert_eq!(
            path.scheduler_target_rate(),
            Some(0),
            "abandoned path must not retain scheduler credit"
        );
        Ok(())
    }

    #[test]
    fn zero_target_deactivates_path_and_positive_target_reactivates_validated_path() -> Result<()> {
        let client_addrs = vec![SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            9451,
        )];
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 451);
        let mut path_mgr = new_path_mgr(&client_addrs, server_addr, 8, false)?;
        let path = path_mgr.get_mut(0)?;

        path.set_scheduler_target_rate(Some(0));
        assert!(!path.active());

        path.set_scheduler_target_rate(Some(10_000_000));
        assert!(path.active());
        Ok(())
    }

    #[test]
    fn server_path_validation() -> Result<()> {
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9443);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        let conf = new_test_recovery_config();
        let initial_path = Path::new(server_addr, client_addr, true, &conf, "");
        let mut path_mgr = PathMap::new(initial_path, 2, crate::ANTI_AMPLIFICATION_FACTOR, false);

        // Fake receiving of an packet on a new path 1
        let client_addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9444);
        let new_path = Path::new(server_addr, client_addr1, false, &conf, "");
        let pid = path_mgr.insert_path(new_path)?;
        assert_eq!(path_mgr.len(), 2);
        assert_eq!(pid, 1);

        // Fake receiving of PATH_CHALLENGE
        let data = rand::random::<[u8; 8]>();
        path_mgr.on_path_chal_received(pid, data);
        assert_eq!(path_mgr.get_mut(pid)?.recv_chals.len(), 1);

        // Fake sending of PATH_RESPONSE
        let chal = path_mgr.get_mut(pid)?.pop_recv_chal();
        assert_eq!(chal, Some(data));

        // Fake receiving of an packet on a new path 2
        let client_addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9445);
        let new_path = Path::new(server_addr, client_addr2, false, &conf, "");
        let pid = path_mgr.insert_path(new_path)?;
        assert_eq!(path_mgr.len(), 2);
        assert_eq!(path_mgr.get_mut(pid)?.remote_addr(), client_addr2);

        // Fake receiving of PATH_CHALLENGE
        let data = rand::random::<[u8; 8]>();
        path_mgr.on_path_chal_received(pid, data);
        assert_eq!(path_mgr.get_mut(pid)?.recv_chals.len(), 1);

        // Fake sending of PATH_RESPONSE
        let chal = path_mgr.get_mut(pid)?.pop_recv_chal();
        assert_eq!(chal, Some(data));

        Ok(())
    }

    #[test]
    fn path_chal_timeout() -> Result<()> {
        let clients = vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9443),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9444),
        ];
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        let mut path_mgr = new_path_mgr(&clients, server_addr, 8, false)?;
        assert_eq!(path_mgr.len(), 2);

        let pid = path_mgr
            .get_path_id(&(clients[1], server_addr))
            .ok_or(Error::InternalError)?;
        path_mgr.get_mut(pid)?.initiate_path_chal();
        assert!(path_mgr.get_mut(pid)?.need_send_validation_frames(false));
        assert_eq!(path_mgr.get_mut(pid)?.path_chal_initiated(), true);

        // Fake sending of PATH_CHALLENGE.
        let data = rand::random::<[u8; 8]>();
        let now = time::Instant::now();
        path_mgr.on_path_chal_sent(pid, data, 1300, now)?;
        assert_eq!(path_mgr.get_mut(pid)?.path_chal_initiated(), false);
        assert_eq!(path_mgr.get_mut(pid)?.validated(), false);
        assert_eq!(path_mgr.get_mut(pid)?.state, PathState::Validating);

        // Not expired.
        path_mgr.on_path_chal_timeout(now + time::Duration::from_millis(1));
        assert_eq!(path_mgr.get_mut(pid)?.sent_chals.len(), 1);
        assert_eq!(path_mgr.get_mut(pid)?.lost_chal, 0);
        assert_eq!(path_mgr.get_mut(pid)?.path_chal_initiated(), false);

        // Timeout.
        let mut next_timeout = now;
        for i in 0..MAX_PROBING_TIMEOUTS {
            next_timeout += time::Duration::from_millis(INITIAL_CHAL_TIMEOUT << i);

            path_mgr.on_path_chal_timeout(next_timeout);
            assert_eq!(path_mgr.get_mut(pid)?.lost_chal, i + 1);
            assert_eq!(path_mgr.get_mut(pid)?.sent_chals.len(), 0);

            if i != MAX_PROBING_TIMEOUTS - 1 {
                assert_eq!(path_mgr.get_mut(pid)?.path_chal_initiated(), true);
                assert_eq!(path_mgr.get_mut(pid)?.state, PathState::Validating);

                let data = rand::random::<[u8; 8]>();
                path_mgr.on_path_chal_sent(pid, data, 1300, next_timeout)?;
                assert_eq!(path_mgr.get_mut(pid)?.path_chal_initiated(), false);
            }
        }
        assert_eq!(path_mgr.get_mut(pid)?.state, PathState::Failed);
        assert_eq!(path_mgr.get_mut(pid)?.active(), false);
        assert_eq!(path_mgr.get_mut(pid)?.lost_chal, MAX_PROBING_TIMEOUTS);

        Ok(())
    }

    #[test]
    fn path_peer_context() -> Result<()> {
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9443);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        let conf = new_test_recovery_config();
        let mut path = Path::new(client_addr, server_addr, true, &conf, "");

        // Test setting peer context
        let text_context = String::from("test context");
        path.set_peer_context(text_context);

        // Test getting peer context
        let context = path.peer_context();
        assert!(context.is_some());

        // Test downcasting to String
        if let Some(ctx) = context {
            if let Some(s) = ctx.downcast_mut::<String>() {
                assert_eq!(s, "test context");
            } else {
                panic!("Failed to downcast to String");
            }
        }

        Ok(())
    }

    #[test]
    fn min_path_chal_timeout() -> Result<()> {
        let clients = vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9443),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9444),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9445),
        ];
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        let mut path_mgr = new_path_mgr(&clients, server_addr, 8, false)?;
        assert_eq!(path_mgr.len(), 3);
        assert!(path_mgr.min_path_chal_timer().is_none());

        let pid1 = path_mgr
            .get_path_id(&(clients[1], server_addr))
            .ok_or(Error::InternalError)?;
        let pid2 = path_mgr
            .get_path_id(&(clients[2], server_addr))
            .ok_or(Error::InternalError)?;

        // Fake sending of PATH_CHALLENGE on the first path.
        let now = time::Instant::now();
        let sent_time1 = now;
        let data = rand::random::<[u8; 8]>();
        path_mgr.on_path_chal_sent(pid1, data, 1300, sent_time1)?;
        assert_eq!(path_mgr.get_mut(pid1)?.state, PathState::Validating);
        let timeout1 = sent_time1 + time::Duration::from_millis(INITIAL_CHAL_TIMEOUT);
        assert_eq!(path_mgr.min_path_chal_timer(), Some(timeout1));

        // Fake sending of PATH_CHALLENGE on the second path.
        let sent_time2 = now + time::Duration::from_millis(1);
        path_mgr.on_path_chal_sent(pid2, data, 1300, sent_time2)?;
        assert_eq!(path_mgr.get_mut(pid2)?.state, PathState::Validating);
        let timeout2 = sent_time2 + time::Duration::from_millis(INITIAL_CHAL_TIMEOUT);
        assert_eq!(path_mgr.min_path_chal_timer(), Some(timeout1));

        // Fake receiving of PATH_RESPONSE on the first path.
        path_mgr.on_path_resp_received(pid1, data);
        assert_eq!(path_mgr.min_path_chal_timer(), Some(timeout2));

        Ok(())
    }

    #[test]
    fn path_chals_flood() -> Result<()> {
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9443);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        let conf = new_test_recovery_config();
        let initial_path = Path::new(server_addr, client_addr, true, &conf, "");
        let mut path_mgr = PathMap::new(initial_path, 2, crate::ANTI_AMPLIFICATION_FACTOR, false);

        // Fake receiving of a packet on a new path
        let client_addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9444);
        let new_path = Path::new(server_addr, client_addr1, false, &conf, "");
        let pid = path_mgr.insert_path(new_path)?;
        assert_eq!(path_mgr.len(), 2);
        assert_eq!(pid, 1);

        // Fake receiving of PATH_CHALLENGE
        for i in 0..1000 {
            let data = rand::random::<[u8; 8]>();
            path_mgr.on_path_chal_received(pid, data);
            assert!(path_mgr.get_mut(pid)?.recv_chals.len() <= MAX_PATH_CHALS_RECV);
        }

        Ok(())
    }
}
