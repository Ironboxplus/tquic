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

#![allow(unused_variables)]

use core::str::FromStr;
use std::time::Instant;

use self::scheduler_minrtt::*;
use self::scheduler_redundant::*;
use self::scheduler_rr::*;
use self::scheduler_sqm::*;
use crate::connection::path::PathMap;
use crate::connection::space::PacketNumSpaceMap;
use crate::connection::space::SentPacket;
use crate::connection::stream::StreamMap;
use crate::Error;
use crate::MultipathConfig;
use crate::PathEvent;
use crate::Result;

/// MultipathScheduler is a packet scheduler that decides the path over which
/// the next QUIC packet will be sent.
/// Note: The API of MultipathScheduler is not stable and may change in future
/// versions.
pub(crate) trait MultipathScheduler {
    /// Select a validated path with sufficient congestion window for sending
    /// non-probing packets.
    fn on_select(
        &mut self,
        paths: &mut PathMap,
        spaces: &mut PacketNumSpaceMap,
        streams: &mut StreamMap,
    ) -> Result<usize>;

    /// Process a packet sent event.
    fn on_sent(
        &mut self,
        packet: &SentPacket,
        now: Instant,
        path_id: usize,
        paths: &mut PathMap,
        spaces: &mut PacketNumSpaceMap,
        streams: &mut StreamMap,
    ) {
    }

    /// Process a path event.
    fn on_path_updated(&mut self, paths: &mut PathMap, event: PathEvent) {}
}

/// Available multipath scheduling algorithms.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MultipathAlgorithm {
    /// The scheduler sends packets over the path with the lowest smoothed RTT
    /// among all available paths. It aims to optimize throughput and achieve
    /// load balancing, making it particularly advantageous for bulk transfer
    /// applications in heterogeneous networks.
    MinRtt,

    /// The scheduler sends all packets redundantly on all available paths. It
    /// utilizes additional bandwidth to minimize latency, thereby reducing the
    /// overall flow completion time for applications with bounded bandwidth
    /// requirements that can be met by a single path.
    /// In scenarios where two paths with varying available bandwidths are
    /// present, it ensures a goodput at least equivalent to the best single
    /// path.
    Redundant,

    /// The scheduler sends packets over available paths in a round robin
    /// manner. It aims to fully utilize the capacity of each path as the
    /// distribution across all path is equal. It is only used for testing
    /// purposes.
    RoundRobin,

    /// The scheduler spreads packets across all usable paths weighted by their
    /// estimated capacity, exposing a single "latency <-> bandwidth" knob. At
    /// one extreme it behaves like `MinRtt` (lowest latency, single best path);
    /// at the other it stripes proportionally to per-path bandwidth (MPTCP-like
    /// aggregation). See [`scheduler_sqm::SqmWeightedScheduler`].
    SqmWeighted,
}

impl FromStr for MultipathAlgorithm {
    type Err = Error;

    fn from_str(algor: &str) -> Result<MultipathAlgorithm> {
        if algor.eq_ignore_ascii_case("minrtt") {
            Ok(MultipathAlgorithm::MinRtt)
        } else if algor.eq_ignore_ascii_case("redundant") {
            Ok(MultipathAlgorithm::Redundant)
        } else if algor.eq_ignore_ascii_case("roundrobin") {
            Ok(MultipathAlgorithm::RoundRobin)
        } else if algor.eq_ignore_ascii_case("sqmweighted") || algor.eq_ignore_ascii_case("sqm") {
            Ok(MultipathAlgorithm::SqmWeighted)
        } else {
            Err(Error::InvalidConfig("unknown".into()))
        }
    }
}

/// Build a multipath scheduler
pub(crate) fn build_multipath_scheduler(conf: &MultipathConfig) -> Box<dyn MultipathScheduler> {
    match conf.multipath_algorithm {
        MultipathAlgorithm::MinRtt => Box::new(MinRttScheduler::new(conf)),
        MultipathAlgorithm::Redundant => Box::new(RedundantScheduler::new(conf)),
        MultipathAlgorithm::RoundRobin => Box::new(RoundRobinScheduler::new(conf)),
        MultipathAlgorithm::SqmWeighted => Box::new(SqmWeightedScheduler::new(conf)),
    }
}

pub(crate) fn buffer_required(algor: MultipathAlgorithm) -> bool {
    match algor {
        MultipathAlgorithm::MinRtt => false,
        MultipathAlgorithm::Redundant => true,
        MultipathAlgorithm::RoundRobin => false,
        MultipathAlgorithm::SqmWeighted => false,
    }
}

// ---------------------------------------------------------------------------
// Pluggable scheduler plugin metadata.
//
// The `MultipathScheduler` trait references engine-private types (`PathMap`,
// `StreamMap`, ...), so schedulers must live inside this crate; a foreign crate
// cannot implement one. The "plugin" surface is therefore selection-by-name
// plus a tunables schema: a host (EasyTier, its GUI, or the FFI layer) can
// enumerate the built-in schedulers, render each tunable automatically, and
// pass the chosen algorithm name plus parameter values back through the config.
// Adding a new algorithm means dropping a `scheduler_*.rs` module in this fork
// and registering it in `SCHEDULER_REGISTRY` below.
// ---------------------------------------------------------------------------

/// Kind of a scheduler tunable, so a GUI/FFI can auto-render the right control.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TunableKind {
    /// Continuous slider over `[min, max]` with the given `step`.
    Slider { min: f64, max: f64, step: f64 },
    /// Boolean toggle.
    Bool,
    /// Unsigned integer over `[min, max]`.
    Uint { min: u64, max: u64 },
}

/// One tunable parameter of a scheduler plugin. Pure data (no engine types) so
/// it can be re-exported to the GUI and the C FFI.
#[derive(Debug, Clone, Copy)]
pub struct SchedulerTunable {
    /// Stable machine key, used in config/params.
    pub key: &'static str,
    /// Human-facing label for the control.
    pub label: &'static str,
    /// Control kind + range.
    pub kind: TunableKind,
    /// Default value (for `Bool`, `0.0` = false, `1.0` = true).
    pub default: f64,
    /// One-line help/tooltip.
    pub help: &'static str,
}

/// Metadata describing an available multipath scheduler plugin.
#[derive(Debug, Clone, Copy)]
pub struct SchedulerInfo {
    /// Stable machine name accepted by [`MultipathAlgorithm::from_str`].
    pub name: &'static str,
    /// Human-facing description.
    pub description: &'static str,
    /// Whether the scheduler needs the reorder/redundancy send buffer.
    pub buffer_required: bool,
    /// Tunable parameters exposed to the host UI.
    pub tunables: &'static [SchedulerTunable],
}

/// Tunables for [`MultipathAlgorithm::SqmWeighted`].
static SQM_TUNABLES: &[SchedulerTunable] = &[SchedulerTunable {
    key: "lambda",
    label: "Latency \u{2194} Bandwidth",
    kind: TunableKind::Slider {
        min: 0.0,
        max: 1.0,
        step: 0.01,
    },
    default: scheduler_sqm::DEFAULT_LAMBDA,
    help: "0 = lowest latency (single best path); 1 = maximum bandwidth (weighted striping across all paths).",
}];

/// All built-in scheduler plugins, in display order.
static SCHEDULER_REGISTRY: &[SchedulerInfo] = &[
    SchedulerInfo {
        name: "minrtt",
        description: "Lowest smoothed-RTT path first; spills to the next path when its cwnd fills.",
        buffer_required: false,
        tunables: &[],
    },
    SchedulerInfo {
        name: "sqmweighted",
        description: "Capacity-weighted striping with a latency<->bandwidth slider (bandwidth aggregation).",
        buffer_required: false,
        tunables: SQM_TUNABLES,
    },
    SchedulerInfo {
        name: "redundant",
        description: "Send every packet on all paths; trades bandwidth for the lowest possible latency.",
        buffer_required: true,
        tunables: &[],
    },
    SchedulerInfo {
        name: "roundrobin",
        description: "Equal round-robin across paths (testing only).",
        buffer_required: false,
        tunables: &[],
    },
];

/// Enumerate all built-in scheduler plugins and their tunables.
///
/// Hosts (EasyTier / its GUI / the FFI) use this to render per-scheduler
/// configuration UI automatically instead of hard-coding option lists.
pub fn available_schedulers() -> &'static [SchedulerInfo] {
    SCHEDULER_REGISTRY
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::connection::stream;
    use crate::Config;
    use crate::Path;
    use crate::TransportParams;
    use std::time::Duration;

    pub(crate) struct MultipathTester {
        pub(crate) paths: PathMap,
        pub(crate) spaces: PacketNumSpaceMap,
        pub(crate) streams: StreamMap,
    }

    impl MultipathTester {
        /// Create context for multipath scheduler.
        pub(crate) fn new() -> Result<MultipathTester> {
            let path = new_test_path("127.0.0.1:443", "127.0.0.1:8443", true, 200);
            let mut paths = PathMap::new(path, 8, crate::ANTI_AMPLIFICATION_FACTOR, true);
            paths.enable_multipath();

            let spaces = PacketNumSpaceMap::new();

            let params = stream::StreamTransportParams::from(&TransportParams::default());
            let streams = StreamMap::new(true, 1024 * 1024, 1024 * 1024, params);

            Ok(MultipathTester {
                paths,
                spaces,
                streams,
            })
        }

        /// Add a test path.
        pub(crate) fn add_path(
            &mut self,
            local: &str,
            remote: &str,
            initial_rtt: u64,
        ) -> Result<usize> {
            let mut path = new_test_path(local, remote, false, initial_rtt);
            path.set_active(true);
            path.dcid_seq = Some(self.paths.len() as u64);
            self.paths.insert_path(path)
        }

        /// Mark the given path as active or inactive.
        pub(crate) fn set_path_active(&mut self, path_id: usize, active: bool) -> Result<()> {
            let path = self.paths.get_mut(path_id)?;
            path.set_active(active);
            Ok(())
        }
    }

    fn new_test_path(local: &str, remote: &str, is_initial: bool, initial_rtt: u64) -> Path {
        let local = local.parse().unwrap();
        let remote = remote.parse().unwrap();
        let mut conf = Config::new().unwrap();
        conf.recovery.initial_rtt = Duration::from_millis(initial_rtt);

        Path::new(local, remote, is_initial, &conf.recovery, "")
    }

    #[test]
    fn scheduler_name() {
        let cases = [
            ("minrtt", Ok(MultipathAlgorithm::MinRtt)),
            ("Minrtt", Ok(MultipathAlgorithm::MinRtt)),
            ("MinRtt", Ok(MultipathAlgorithm::MinRtt)),
            ("MINRTT", Ok(MultipathAlgorithm::MinRtt)),
            ("redundant", Ok(MultipathAlgorithm::Redundant)),
            ("Redundant", Ok(MultipathAlgorithm::Redundant)),
            ("REDUNDANT", Ok(MultipathAlgorithm::Redundant)),
            ("roundrobin", Ok(MultipathAlgorithm::RoundRobin)),
            ("Roundrobin", Ok(MultipathAlgorithm::RoundRobin)),
            ("RoundRobin", Ok(MultipathAlgorithm::RoundRobin)),
            ("ROUNDROBIN", Ok(MultipathAlgorithm::RoundRobin)),
            ("sqmweighted", Ok(MultipathAlgorithm::SqmWeighted)),
            ("SqmWeighted", Ok(MultipathAlgorithm::SqmWeighted)),
            ("SQM", Ok(MultipathAlgorithm::SqmWeighted)),
            ("redun", Err(Error::InvalidConfig("unknown".into()))),
        ];

        for (name, algor) in cases {
            assert_eq!(MultipathAlgorithm::from_str(name), algor);
        }
    }
}

mod scheduler_minrtt;
mod scheduler_redundant;
mod scheduler_rr;
mod scheduler_sqm;
