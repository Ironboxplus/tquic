// Copyright (c) 2024 The TQUIC Authors.
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

use crate::connection::path::HeldBack;
use crate::connection::path::Path;
use crate::connection::path::PathMap;
use crate::connection::space::PacketNumSpaceMap;
use crate::connection::stream::StreamMap;
use crate::multipath_scheduler::MultipathScheduler;
use crate::Error;
use crate::MultipathConfig;
use crate::Result;

/// SqmWeightedScheduler is the ECF (Earliest Completion First) scheduler of
/// the multipath-tcp.org kernel (`net/mptcp/mptcp_ecf.c`, v0.96; Lim, Nahum,
/// Towsley, Gibbens, "ECF: An MPTCP Path Scheduler to Manage Heterogeneous
/// Paths", CoNEXT 2017), ported line by line in [`ecf`]
/// (MP_FIX_PHASES.md S-I5/I6).
///
/// The fastest path takes the data while its congestion window has room.
/// When it is full, a slower path is used only if the data still to send
/// would complete sooner that way than by waiting for the fastest path;
/// otherwise nothing is sent and the data waits for the fastest path. Data of
/// one stream spread over paths of different delays waits for the slowest of
/// them (draft-ietf-quic-multipath, "Packet Scheduling"); ECF uses a slower
/// path only when that wait is shorter than the queue on the fast one.
///
/// Three inputs are EasyTier's, not MPTCP's: a path the external optimizer
/// targets at zero carries no data; backup (standby) or backed-off paths
/// are passed over as the other schedulers do (`PathMap::held_back`); and a
/// path with a target rate drains at most `rate * srtt` per round trip (the
/// shaper below it enforces the rate), so that is its window when smaller
/// than the congestion window ([`window`]). Bypassed datagrams are not held
/// by the congestion window at all, and the rate is the only limit they meet.
///
/// Datagrams of an application flow are not spread per packet: each flow
/// keeps a path (`connection::datagrams::FlowPaths`) and [`ecf_place`]
/// places a new flowlet.
pub struct SqmWeightedScheduler {
    /// ECF's `switching_margin` ("waiting" in the paper): set once ECF chose
    /// to wait for the fastest path, it makes switching to the slower one
    /// harder by `beta` next time.
    waiting: bool,
}

impl SqmWeightedScheduler {
    pub fn new(_conf: &MultipathConfig) -> SqmWeightedScheduler {
        SqmWeightedScheduler { waiting: false }
    }
}

/// `mptcp_ecf_r_beta`: beta = 1 / 4.
const ECF_R_BETA: f64 = 4.0;

/// What ECF decided for the next packet.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum EcfChoice {
    /// Send on this path.
    Send(usize),
    /// Send nothing: waiting for the fastest path (`pid`) completes sooner.
    Wait(usize),
}

/// Whether `path` may carry data at all (`mptcp_sk_can_send` in ECF): active,
/// not held back, not targeted at zero.
fn may_carry_data(path: &Path, held: HeldBack) -> bool {
    path.active() && !held.applies(path) && path.scheduler_target_rate() != Some(0)
}

/// The bytes `path` can have in flight per round trip: the congestion window,
/// or `rate * srtt` when the path has a smaller target rate.
fn window(path: &Path) -> u64 {
    let cwnd = path.recovery.congestion.congestion_window();
    match path.scheduler_target_rate() {
        Some(rate) if rate > 0 => {
            let per_rtt = (rate as f64 * path.recovery.rtt.smoothed_rtt().as_secs_f64()) as u64;
            cwnd.min(per_rtt.max(path.recovery.max_datagram_size as u64))
        }
        _ => cwnd,
    }
}

/// Whether `path` has room for another packet (`mptcp_is_available`).
fn has_room(path: &mut Path) -> bool {
    path.recovery.can_send() && (path.recovery.bytes_in_flight as u64) < window(path)
}

/// `ecf_get_available_subflow`. `unsent` is the data not yet given to any
/// path (MPTCP's `sndbuf`); `waiting` is the scheduler's `switching_margin`.
/// `None` when no path may carry data or none has room.
pub(crate) fn ecf(paths: &mut PathMap, unsent: u64, waiting: &mut bool) -> Option<EcfChoice> {
    let held = paths.held_back();
    // First, find the overall best (fastest) path.
    let mut fastest: Option<(usize, std::time::Duration)> = None;
    // The current best path according to the default scheduler: the lowest
    // srtt among those whose window has room.
    let mut best: Option<(usize, std::time::Duration)> = None;
    for (pid, path) in paths.iter_mut() {
        if !may_carry_data(path, held) {
            continue;
        }
        let srtt = path.recovery.rtt.smoothed_rtt();
        if fastest.map_or(true, |(_, rtt)| srtt < rtt) {
            fastest = Some((pid, srtt));
        }
        if best.map_or(true, |(_, rtt)| srtt < rtt) && has_room(path) {
            best = Some((pid, srtt));
        }
    }
    let (best, _) = best?;
    let (fastest, _) = fastest?;
    if best == fastest {
        return Some(EcfChoice::Send(best));
    }

    // We decided to use a slower path: we have the option of not using it.
    let f = paths.get(fastest).ok()?;
    let s = paths.get(best).ok()?;
    let cwnd_f = window(f) as f64;
    let srtt_f = f.recovery.rtt.smoothed_rtt().as_secs_f64();
    let rttvar_f = f.recovery.rtt.rttvar().as_secs_f64();
    let cwnd_s = window(s) as f64;
    let srtt_s = s.recovery.rtt.smoothed_rtt().as_secs_f64();
    let rttvar_s = s.recovery.rtt.rttvar().as_secs_f64();
    // `rttvar_us >> 1` in Linux, which keeps the mean deviation times 4.
    let delta = 2.0 * rttvar_f.max(rttvar_s);
    let sndbuf = unsent as f64;

    // At least one transmission over the fastest path is required.
    let x_f = sndbuf.max(cwnd_f);
    let lhs = srtt_f * (x_f + cwnd_f);
    let rhs = cwnd_f * (srtt_s + delta);
    let margin = if *waiting { 1.0 } else { 0.0 };
    if ECF_R_BETA * lhs < ECF_R_BETA * rhs + margin * rhs {
        let x_s = sndbuf.max(cwnd_s);
        let lhs_s = srtt_s * x_s;
        let rhs_s = cwnd_s * (2.0 * srtt_f + delta);
        if lhs_s >= rhs_s {
            // Too much slower than the fastest.
            *waiting = true;
            return Some(EcfChoice::Wait(fastest));
        }
    } else {
        // Use the slower one.
        *waiting = false;
    }
    Some(EcfChoice::Send(best))
}

/// The path a new flowlet of datagrams goes on: ECF's choice for `unsent`
/// queued datagram bytes, the fastest path when ECF would wait for it.
pub(crate) fn ecf_place(paths: &mut PathMap, unsent: u64) -> Option<usize> {
    let held = paths.held_back();
    if let Some(choice) = ecf(paths, unsent, &mut false) {
        return Some(match choice {
            EcfChoice::Send(pid) | EcfChoice::Wait(pid) => pid,
        });
    }
    // No window has room anywhere: the fastest path.
    paths
        .iter()
        .filter(|(_, p)| may_carry_data(p, held))
        .min_by_key(|(_, p)| p.recovery.rtt.smoothed_rtt())
        .map(|(pid, _)| pid)
}

impl MultipathScheduler for SqmWeightedScheduler {
    /// Select the path the next packet of stream data goes on.
    fn on_select(
        &mut self,
        paths: &mut PathMap,
        _spaces: &mut PacketNumSpaceMap,
        streams: &mut StreamMap,
    ) -> Result<usize> {
        match ecf(paths, streams.unsent_bytes(), &mut self.waiting) {
            Some(EcfChoice::Send(pid)) => Ok(pid),
            Some(EcfChoice::Wait(_)) | None => Err(Error::Done),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multipath_scheduler::tests::*;

    fn select_counts(t: &mut MultipathTester, rounds: usize) -> Result<Vec<usize>> {
        let mut s = SqmWeightedScheduler { waiting: false };
        let mut counts = vec![0usize; t.paths.len()];
        for _ in 0..rounds {
            counts[s.on_select(&mut t.paths, &mut t.spaces, &mut t.streams)?] += 1;
        }
        Ok(counts)
    }

    /// Feed every path steady samples of its initial RTT, as a path that has
    /// carried traffic has: rttvar decays from half the RTT towards zero.
    fn settle_rtts(t: &mut MultipathTester) {
        for (_, path) in t.paths.iter_mut() {
            let rtt = path.recovery.rtt.smoothed_rtt();
            for _ in 0..30 {
                path.recovery.rtt.update(std::time::Duration::ZERO, rtt);
            }
        }
    }

    fn fill_window(t: &mut MultipathTester, pid: usize) -> Result<()> {
        let r = &mut t.paths.get_mut(pid)?.recovery;
        r.bytes_in_flight = r.congestion.congestion_window() as usize;
        Ok(())
    }

    #[test]
    fn sqm_single_available_path() -> Result<()> {
        let mut t = MultipathTester::new()?;
        assert_eq!(select_counts(&mut t, 2)?, vec![2]);
        Ok(())
    }

    #[test]
    fn sqm_no_available_path() -> Result<()> {
        let mut t = MultipathTester::new()?;
        t.set_path_active(0, false)?;

        let mut s = SqmWeightedScheduler { waiting: false };
        assert_eq!(
            s.on_select(&mut t.paths, &mut t.spaces, &mut t.streams),
            Err(Error::Done)
        );
        Ok(())
    }

    /// I5: a 200 ms and a 20 ms path with room. Weighting by rate alone sent
    /// half the packets of every stream over the 200 ms path; ECF sends all
    /// of them on the fastest path while its window has room.
    #[test]
    fn sqm_light_traffic_stays_on_the_fastest_path() -> Result<()> {
        let mut t = MultipathTester::new()?; // pid0: 200 ms
        t.add_path("127.0.0.1:443", "127.0.0.2:8443", 20)?;
        settle_rtts(&mut t);
        assert_eq!(select_counts(&mut t, 50)?, vec![0, 50]);
        Ok(())
    }

    /// ECF: the fastest path's window is full and little data is left. Waiting
    /// for the 20 ms path completes sooner than the 200 ms path: send nothing.
    #[test]
    fn sqm_waits_for_the_fastest_path_when_little_data_is_left() -> Result<()> {
        let mut t = MultipathTester::new()?; // pid0: 200 ms
        t.add_path("127.0.0.1:443", "127.0.0.2:8443", 20)?;
        settle_rtts(&mut t);
        fill_window(&mut t, 1)?;
        let mut waiting = false;
        assert_eq!(ecf(&mut t.paths, 1_200, &mut waiting), Some(EcfChoice::Wait(1)));
        assert!(waiting);
        Ok(())
    }

    /// ECF: the fastest path's window is full and a bulk transfer is queued.
    /// The slower path finishes part of it sooner than waiting: use it.
    #[test]
    fn sqm_uses_the_slower_path_for_a_backlog() -> Result<()> {
        let mut t = MultipathTester::new()?; // pid0: 200 ms
        t.add_path("127.0.0.1:443", "127.0.0.2:8443", 20)?;
        settle_rtts(&mut t);
        fill_window(&mut t, 1)?;
        let mut waiting = false;
        assert_eq!(
            ecf(&mut t.paths, 100_000_000, &mut waiting),
            Some(EcfChoice::Send(0))
        );
        assert!(!waiting);
        Ok(())
    }

    #[test]
    fn sqm_zero_external_target_excludes_data_path() -> Result<()> {
        let mut t = MultipathTester::new()?;
        t.add_path("127.0.0.1:443", "127.0.0.2:8443", 50)?;
        t.paths.get_mut(0)?.set_scheduler_target_rate(Some(0));
        t.paths
            .get_mut(1)?
            .set_scheduler_target_rate(Some(1_000_000));
        assert_eq!(select_counts(&mut t, 20)?, vec![0, 20]);
        Ok(())
    }

    /// A standby path carries no data while a regular path is active, even
    /// if it is faster.
    #[test]
    fn sqm_skips_a_standby_path_while_a_regular_one_is_active() -> Result<()> {
        let mut t = MultipathTester::new()?; // pid0: 200 ms
        t.add_path("127.0.0.1:443", "127.0.0.2:8443", 20)?;
        settle_rtts(&mut t);
        t.set_path_standby(1, true)?;
        assert_eq!(select_counts(&mut t, 10)?, vec![10, 0]);
        t.set_path_active(0, false)?;
        assert_eq!(select_counts(&mut t, 10)?, vec![0, 10]);
        Ok(())
    }

    /// A path with a target rate drains `rate * srtt` per round trip: with
    /// that much in flight it has no room even though its congestion window
    /// has, and a backlog goes to the slower path.
    #[test]
    fn a_path_with_its_target_rate_in_flight_has_no_room() -> Result<()> {
        let mut t = MultipathTester::new()?; // pid0: 200 ms
        t.add_path("127.0.0.1:443", "127.0.0.2:8443", 20)?;
        settle_rtts(&mut t);
        t.paths.get_mut(1)?.recovery.bytes_in_flight = 2_000;
        let mut waiting = false;
        assert_eq!(ecf(&mut t.paths, 100_000_000, &mut waiting), Some(EcfChoice::Send(1)));
        // 100 kB/s over 20 ms: 2 000 bytes per round trip.
        t.paths.get_mut(1)?.set_scheduler_target_rate(Some(100_000));
        assert_eq!(ecf(&mut t.paths, 100_000_000, &mut waiting), Some(EcfChoice::Send(0)));
        Ok(())
    }

    /// A new flowlet goes where ECF would send, or to the fastest path when
    /// ECF would wait for it.
    #[test]
    fn ecf_places_a_flowlet_on_the_fastest_path_it_would_wait_for() -> Result<()> {
        let mut t = MultipathTester::new()?; // pid0: 200 ms
        t.add_path("127.0.0.1:443", "127.0.0.2:8443", 20)?;
        settle_rtts(&mut t);
        assert_eq!(ecf_place(&mut t.paths, 1_200), Some(1));
        fill_window(&mut t, 1)?;
        assert_eq!(ecf_place(&mut t.paths, 1_200), Some(1));
        assert_eq!(ecf_place(&mut t.paths, 100_000_000), Some(0));
        Ok(())
    }
}
