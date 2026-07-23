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

use std::collections::HashMap;

use crate::connection::path::PathMap;
use crate::connection::space::PacketNumSpaceMap;
use crate::connection::stream::StreamMap;
use crate::multipath_scheduler::MultipathScheduler;
use crate::Error;
use crate::MultipathConfig;
use crate::Result;

/// Default slider position (see [`SqmWeightedScheduler::lambda`]).
///
/// `1.0` means "maximum bandwidth": spread packets across all usable paths
/// weighted by their estimated capacity.
pub(crate) const DEFAULT_LAMBDA: f64 = 1.0;

/// Latency-concentration exponent applied when `lambda == 0`.
///
/// The per-path latency factor is `(min_srtt / srtt)^k` with
/// `k = (1 - lambda) * K_MAX`. A larger `K_MAX` makes `lambda = 0` collapse
/// harder onto the single lowest-RTT path.
const K_MAX: f64 = 8.0;

/// SqmWeightedScheduler spreads packets across all usable paths weighted by
/// each path's estimated capacity, exposing a single "latency <-> bandwidth"
/// knob (`lambda`).
///
/// The per-path send weight is
///
/// ```text
///   weight_i = rate_i * (min_srtt / srtt_i)^k,   k = (1 - lambda) * K_MAX
/// ```
///
/// where `rate_i` is the congestion controller's raw bottleneck-bandwidth
/// estimate when available, falling back to `cwnd / srtt` while that model is
/// cold. Controllers without a model-specific estimate keep their pacing-rate
/// signal with the same fallback.
///
/// * `lambda = 1` => `k = 0` => `weight_i = rate_i`: pure bandwidth-proportional
///   striping (MPTCP-like aggregation).
/// * `lambda = 0` => `k = K_MAX` => every non-minimal-RTT path is driven towards
///   zero weight, so traffic collapses onto the single lowest-latency path
///   (equivalent to `MinRtt`).
/// * Intermediate values trade latency for aggregate throughput smoothly.
///
/// Paths are then selected with Smooth Weighted Round Robin (the algorithm used
/// by nginx upstreams): it is deterministic, self-scaling in the weight
/// magnitude, and yields a selection frequency proportional to the weights
/// without bursty runs on a single path.
pub struct SqmWeightedScheduler {
    /// Slider in `[0, 1]`: `0` favours latency, `1` favours bandwidth.
    lambda: f64,

    /// Smooth Weighted Round Robin credit per path id. Persisted across calls
    /// so the long-run selection frequency tracks the weights; stale entries
    /// are pruned whenever a path stops being a candidate.
    credit: HashMap<usize, f64>,
}

impl SqmWeightedScheduler {
    pub fn new(conf: &MultipathConfig) -> SqmWeightedScheduler {
        SqmWeightedScheduler {
            lambda: conf.sqm_lambda,
            credit: HashMap::new(),
        }
    }

    /// Build a scheduler with an explicit slider position (clamped to `[0, 1]`).
    pub fn with_lambda(lambda: f64) -> SqmWeightedScheduler {
        SqmWeightedScheduler {
            lambda: lambda.clamp(0.0, 1.0),
            credit: HashMap::new(),
        }
    }

    /// Blend a path's bandwidth estimate and latency into a single send weight.
    fn path_weight(&self, rate: f64, srtt_s: f64, min_srtt_s: f64) -> f64 {
        let k = (1.0 - self.lambda) * K_MAX;
        let latency_factor = if srtt_s > 0.0 && min_srtt_s > 0.0 {
            (min_srtt_s / srtt_s).powf(k)
        } else {
            1.0
        };
        // Keep the weight strictly positive so every usable path is eventually
        // scheduled even when its estimate rounds to zero.
        (rate.max(1.0)) * latency_factor.max(f64::MIN_POSITIVE)
    }
}

impl MultipathScheduler for SqmWeightedScheduler {
    /// Select a usable path, spreading load by capacity-blended weights.
    fn on_select(
        &mut self,
        paths: &mut PathMap,
        _spaces: &mut PacketNumSpaceMap,
        _streams: &mut StreamMap,
    ) -> Result<usize> {
        // Collect the paths that can send a non-probing packet right now, along
        // with the capacity/latency inputs used to weight them.
        let mut candidates: Vec<(usize, f64, f64, bool)> = Vec::new(); // (pid, rate, srtt_s, externally_targeted)
        let mut min_srtt = f64::MAX;

        for (pid, path) in paths.iter_mut() {
            if !path.active() || !path.recovery.can_send() {
                continue;
            }

            let external_target = path.scheduler_target_rate();
            if external_target == Some(0) {
                continue;
            }

            let srtt = path.recovery.rtt.smoothed_rtt().as_secs_f64().max(1e-6);
            let fallback_rate = path.recovery.congestion.congestion_window() as f64 / srtt;
            let rate = match external_target {
                Some(rate) => rate as f64,
                None => match path.recovery.congestion.bandwidth_metrics() {
                    Some(metrics) if metrics.btlbw > 0 => metrics.btlbw as f64,
                    Some(_) => fallback_rate,
                    None => match path.recovery.congestion.pacing_rate() {
                        Some(r) if r > 0 => r as f64,
                        _ => fallback_rate,
                    },
                },
            };

            min_srtt = min_srtt.min(srtt);
            candidates.push((pid, rate, srtt, external_target.is_some()));
        }

        match candidates.len() {
            0 => return Err(Error::Done),
            1 => {
                self.credit.clear();
                return Ok(candidates[0].0);
            }
            _ => {}
        }

        // Drop credit for paths that are no longer candidates so a path cannot
        // hoard an unbounded advantage while it is unusable.
        self.credit
            .retain(|pid, _| candidates.iter().any(|(cid, _, _, _)| cid == pid));

        // Smooth Weighted Round Robin: advance every candidate by its weight,
        // pick the highest running credit, then charge it the total weight.
        let mut total_weight = 0.0;
        let mut best: Option<(usize, f64)> = None;
        for (pid, rate, srtt, externally_targeted) in &candidates {
            let weight = if *externally_targeted {
                rate.max(1.0)
            } else {
                self.path_weight(*rate, *srtt, min_srtt)
            };
            total_weight += weight;
            let credit = self.credit.entry(*pid).or_insert(0.0);
            *credit += weight;
            match best {
                None => best = Some((*pid, *credit)),
                Some((_, best_credit)) if *credit > best_credit => best = Some((*pid, *credit)),
                _ => {}
            }
        }

        let chosen = best.expect("at least two candidates present").0;
        if let Some(credit) = self.credit.get_mut(&chosen) {
            *credit -= total_weight;
        }
        Ok(chosen)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::congestion_control::{
        BandwidthMetrics, CongestionControlState, CongestionController, CongestionStats,
    };
    use crate::connection::rtt::RttEstimator;
    use crate::connection::space::SentPacket;
    use crate::multipath_scheduler::tests::*;
    use std::time::Instant;

    struct FixedBandwidthController {
        btlbw: u64,
        pacing_rate: u64,
        stats: CongestionStats,
    }

    impl FixedBandwidthController {
        fn new(btlbw: u64, pacing_rate: u64) -> Self {
            Self {
                btlbw,
                pacing_rate,
                stats: CongestionStats::default(),
            }
        }
    }

    impl CongestionController for FixedBandwidthController {
        fn name(&self) -> &str {
            "fixed-bandwidth-test"
        }

        fn on_sent(&mut self, _now: Instant, _packet: &mut SentPacket, _bytes_in_flight: u64) {}

        fn begin_ack(&mut self, _now: Instant, _bytes_in_flight: u64) {}

        fn on_ack(
            &mut self,
            _packet: &mut SentPacket,
            _now: Instant,
            _app_limited: bool,
            _rtt: &RttEstimator,
            _bytes_in_flight: u64,
        ) {
        }

        fn end_ack(&mut self) {}

        fn on_congestion_event(
            &mut self,
            _now: Instant,
            _packet: &SentPacket,
            _is_persistent_congestion: bool,
            _lost_bytes: u64,
            _bytes_in_flight: u64,
        ) {
        }

        fn congestion_window(&self) -> u64 {
            u64::MAX
        }

        fn pacing_rate(&self) -> Option<u64> {
            Some(self.pacing_rate)
        }

        fn initial_window(&self) -> u64 {
            u64::MAX
        }

        fn minimal_window(&self) -> u64 {
            1
        }

        fn stats(&self) -> &CongestionStats {
            &self.stats
        }

        fn bandwidth_metrics(&self) -> Option<BandwidthMetrics> {
            Some(BandwidthMetrics {
                btlbw: self.btlbw,
                latest_delivery_rate: self.btlbw,
                sample_app_limited: false,
                sample_time: Some(Instant::now()),
                state: CongestionControlState::ProbeBandwidth,
            })
        }
    }

    #[test]
    fn sqm_single_available_path() -> Result<()> {
        let mut t = MultipathTester::new()?;

        let mut s = SqmWeightedScheduler::with_lambda(1.0);
        assert_eq!(s.on_select(&mut t.paths, &mut t.spaces, &mut t.streams)?, 0);
        assert_eq!(s.on_select(&mut t.paths, &mut t.spaces, &mut t.streams)?, 0);
        Ok(())
    }

    #[test]
    fn sqm_new_uses_lambda_from_multipath_config() {
        let mut config = MultipathConfig::default();
        config.sqm_lambda = 0.25;

        let scheduler = SqmWeightedScheduler::new(&config);

        assert_eq!(scheduler.lambda, 0.25);
    }

    #[test]
    fn sqm_no_available_path() -> Result<()> {
        let mut t = MultipathTester::new()?;
        t.set_path_active(0, false)?;

        let mut s = SqmWeightedScheduler::with_lambda(1.0);
        assert_eq!(
            s.on_select(&mut t.paths, &mut t.spaces, &mut t.streams),
            Err(Error::Done)
        );
        Ok(())
    }

    #[test]
    fn sqm_lambda_zero_collapses_to_min_rtt() -> Result<()> {
        // paths: pid0=200ms (initial), pid1=50ms, pid2=150ms, pid3=100ms.
        let mut t = MultipathTester::new()?;
        t.add_path("127.0.0.1:443", "127.0.0.2:8443", 50)?;
        t.add_path("127.0.0.1:443", "127.0.0.3:8443", 150)?;
        t.add_path("127.0.0.1:443", "127.0.0.4:8443", 100)?;

        // lambda = 0 => latency mode => the 50ms path (pid1) dominates.
        let mut s = SqmWeightedScheduler::with_lambda(0.0);
        let mut counts = [0usize; 4];
        for _ in 0..100 {
            let pid = s.on_select(&mut t.paths, &mut t.spaces, &mut t.streams)?;
            counts[pid] += 1;
        }
        assert!(
            counts[1] >= 95,
            "expected min-rtt path to dominate, got {counts:?}"
        );
        Ok(())
    }

    #[test]
    fn sqm_lambda_one_stripes_across_paths() -> Result<()> {
        let mut t = MultipathTester::new()?;
        t.add_path("127.0.0.1:443", "127.0.0.2:8443", 50)?;
        t.add_path("127.0.0.1:443", "127.0.0.3:8443", 150)?;
        t.add_path("127.0.0.1:443", "127.0.0.4:8443", 100)?;

        // lambda = 1 => bandwidth mode => every usable path is scheduled, and
        // the higher-capacity (lower-srtt) paths get proportionally more.
        let mut s = SqmWeightedScheduler::with_lambda(1.0);
        let mut counts = [0usize; 4];
        for _ in 0..400 {
            let pid = s.on_select(&mut t.paths, &mut t.spaces, &mut t.streams)?;
            counts[pid] += 1;
        }
        assert!(
            counts.iter().all(|&c| c > 0),
            "expected striping across all paths, got {counts:?}"
        );
        assert!(
            counts[1] > counts[0],
            "expected the 50ms path to beat the 200ms path, got {counts:?}"
        );
        Ok(())
    }

    #[test]
    fn sqm_uses_raw_btlbw_instead_of_gain_adjusted_pacing_rate() -> Result<()> {
        let mut t = MultipathTester::new()?;
        t.add_path("127.0.0.1:443", "127.0.0.2:8443", 200)?;

        t.paths.get_mut(0)?.recovery.congestion =
            Box::new(FixedBandwidthController::new(1_000_000, 100_000_000));
        t.paths.get_mut(1)?.recovery.congestion =
            Box::new(FixedBandwidthController::new(10_000_000, 1_000_000));

        let mut scheduler = SqmWeightedScheduler::with_lambda(1.0);
        let mut counts = [0usize; 2];
        for _ in 0..110 {
            let pid = scheduler.on_select(&mut t.paths, &mut t.spaces, &mut t.streams)?;
            counts[pid] += 1;
        }

        assert!(
            counts[1] > counts[0],
            "raw BtlBw should favor path 1 despite path 0's higher pacing gain: {counts:?}"
        );
        Ok(())
    }

    #[test]
    fn sqm_external_targets_override_raw_bandwidth() -> Result<()> {
        let mut t = MultipathTester::new()?;
        t.add_path("127.0.0.1:443", "127.0.0.2:8443", 200)?;

        for pid in 0..2 {
            t.paths.get_mut(pid)?.recovery.congestion =
                Box::new(FixedBandwidthController::new(5_000_000, 5_000_000));
        }
        t.paths
            .get_mut(0)?
            .set_scheduler_target_rate(Some(1_000_000));
        t.paths
            .get_mut(1)?
            .set_scheduler_target_rate(Some(9_000_000));

        let mut scheduler = SqmWeightedScheduler::with_lambda(1.0);
        let mut counts = [0usize; 2];
        for _ in 0..100 {
            let pid = scheduler.on_select(&mut t.paths, &mut t.spaces, &mut t.streams)?;
            counts[pid] += 1;
        }

        assert_eq!(
            counts,
            [10, 90],
            "external target ratio must be authoritative"
        );
        Ok(())
    }

    #[test]
    fn sqm_external_targets_are_not_latency_reweighted() -> Result<()> {
        let mut t = MultipathTester::new()?;
        t.add_path("127.0.0.1:443", "127.0.0.2:8443", 20)?;
        t.paths
            .get_mut(0)?
            .set_scheduler_target_rate(Some(1_000_000));
        t.paths
            .get_mut(1)?
            .set_scheduler_target_rate(Some(1_000_000));

        let mut scheduler = SqmWeightedScheduler::with_lambda(0.0);
        let mut counts = [0usize; 2];
        for _ in 0..100 {
            let pid = scheduler.on_select(&mut t.paths, &mut t.spaces, &mut t.streams)?;
            counts[pid] += 1;
        }

        assert_eq!(
            counts,
            [50, 50],
            "optimizer targets already include latency policy"
        );
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

        let mut scheduler = SqmWeightedScheduler::with_lambda(1.0);
        for _ in 0..20 {
            assert_eq!(
                scheduler.on_select(&mut t.paths, &mut t.spaces, &mut t.streams)?,
                1
            );
        }
        Ok(())
    }
}
