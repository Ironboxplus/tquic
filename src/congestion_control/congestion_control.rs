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
use std::any::Any;
use std::fmt;
use std::time::Instant;

use crate::connection::rtt::RttEstimator;
use crate::connection::space::SentPacket;
pub(crate) use crate::CongestionControlState;
use crate::Error;
use crate::RecoveryConfig;
use crate::Result;
pub use bbr::Bbr;
pub use bbr::BbrConfig;
pub use bbr3::Bbr3;
pub use bbr3::Bbr3Config;
pub use brutal::Brutal;
pub use brutal::BrutalConfig;
pub use copa::Copa;
pub use copa::CopaConfig;
pub use copa::COPA_DELTA;
pub use cubic::Cubic;
pub use cubic::CubicConfig;
pub use dummy::Dummy;
pub use dummy::DummyConfig;
pub use hystart_plus_plus::HystartPlusPlus;
pub use pacing::Pacer;

/// Available congestion control algorithms.
#[repr(C)]
#[derive(Eq, PartialEq, Debug, Clone, Copy, Default)]
pub enum CongestionControlAlgorithm {
    /// CUBIC uses a cubic function instead of a linear window increase function
    /// of the current TCP standards to improve scalability and stability under
    /// fast and long-distance networks.
    Cubic,

    /// BBR uses recent measurements of a transport connection's delivery rate,
    /// round-trip time, and packet loss rate to build an explicit model of the
    /// network path. The model is then used to control data transmission speed
    /// and the maximum volume of data allowed in flight in the network at any
    /// time.
    #[default]
    Bbr,

    /// BBRv3 is the latest version of BBR, including various fixes and
    /// algorithm updates that reduce packet re-transmit rate and slightly
    /// improve latency. (Experimental)
    Bbr3,

    /// COPA is a tunable delay-based congestion control algorithm. COPA is
    /// based on an objective function where the trade-off between throughput
    /// and delay can be configured via a user-specified parameter.
    /// (Experimental)
    Copa,

    /// Dummy is a simple congestion controller with a static congestion window.
    /// It is intended to be used for testing and experiments.
    Dummy,

    /// Brutal (MP_SQM_PLAN.md S2.4, ported from Hysteria's
    /// `internal/congestion/brutal`) sends at a fixed, externally supplied
    /// rate rather than inferring one from measurements -- intended for
    /// links whose true capacity is already known out of band (e.g. an MP
    /// max-flow allocation). It self-compensates for measured loss by
    /// inflating its window/pacing rate, unless that compensation is
    /// disabled.
    Brutal,
}

impl FromStr for CongestionControlAlgorithm {
    type Err = Error;

    fn from_str(algor: &str) -> Result<CongestionControlAlgorithm> {
        if algor.eq_ignore_ascii_case("cubic") {
            Ok(CongestionControlAlgorithm::Cubic)
        } else if algor.eq_ignore_ascii_case("bbr") {
            Ok(CongestionControlAlgorithm::Bbr)
        } else if algor.eq_ignore_ascii_case("bbr3") {
            Ok(CongestionControlAlgorithm::Bbr3)
        } else if algor.eq_ignore_ascii_case("copa") {
            Ok(CongestionControlAlgorithm::Copa)
        } else if algor.eq_ignore_ascii_case("dummy") {
            Ok(CongestionControlAlgorithm::Dummy)
        } else if algor.eq_ignore_ascii_case("brutal") {
            Ok(CongestionControlAlgorithm::Brutal)
        } else {
            Err(Error::InvalidConfig("unknown".into()))
        }
    }
}

/// Congestion control statistics.
#[derive(Debug, Default, Clone)]
pub struct CongestionStats {
    /// Bytes in flight.
    pub bytes_in_flight: u64,

    /// Total bytes sent in slow start.
    pub bytes_sent_in_slow_start: u64,

    /// Total bytes acked in slow start.
    pub bytes_acked_in_slow_start: u64,

    /// Total bytes lost in slow start.
    pub bytes_lost_in_slow_start: u64,

    /// Total bytes sent.
    pub bytes_sent_in_total: u64,

    /// Total bytes acked.
    pub bytes_acked_in_total: u64,

    /// Total bytes lost.
    pub bytes_lost_in_total: u64,
}

/// Algorithm-neutral bandwidth signals exposed by model-based congestion
/// controllers. The scheduler must use the raw bottleneck estimate rather than
/// a gain-adjusted pacing rate when these signals are available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BandwidthMetrics {
    /// Windowed bottleneck-bandwidth estimate in bytes per second.
    pub btlbw: u64,

    /// Most recent delivery-rate sample in bytes per second.
    pub latest_delivery_rate: u64,

    /// Whether the most recent delivery-rate sample was application limited.
    pub sample_app_limited: bool,

    /// Wall-clock time associated with the most recent valid rate sample.
    pub sample_time: Option<Instant>,

    /// Current high-level congestion-control state.
    pub state: CongestionControlState,
}

/// Congestion control interfaces shared by different algorithms.
pub trait CongestionController {
    /// Name of congestion control algorithm.
    fn name(&self) -> &str;

    /// Callback after packet was sent out.
    fn on_sent(&mut self, now: Instant, packet: &mut SentPacket, bytes_in_flight: u64);

    /// Callback for ack packets preprocessing.
    fn begin_ack(&mut self, now: Instant, bytes_in_flight: u64);

    /// Callback for processing each ack packet.
    fn on_ack(
        &mut self,
        packet: &mut SentPacket,
        now: Instant,
        app_limited: bool,
        rtt: &RttEstimator,
        bytes_in_flight: u64,
    );

    /// Callback for Updating states after all ack packets are processed.
    fn end_ack(&mut self);

    /// Congestion event.
    fn on_congestion_event(
        &mut self,
        now: Instant,
        packet: &SentPacket,
        is_persistent_congestion: bool,
        lost_bytes: u64,
        bytes_in_flight: u64,
    );

    /// Check if in slow start.
    fn in_slow_start(&self) -> bool {
        true
    }

    /// Check if in recovery mode.
    fn in_recovery(&self, sent_time: Instant) -> bool {
        false
    }

    /// Current congestion window.
    fn congestion_window(&self) -> u64;

    /// Current pacing rate estimated by Congestion Control Algorithm (CCA).
    /// If CCA does not estimate pacing rate, return None.
    fn pacing_rate(&self) -> Option<u64> {
        None
    }

    /// Initial congestion window.
    fn initial_window(&self) -> u64;

    /// Minimal congestion window.
    fn minimal_window(&self) -> u64;

    /// Congestion stats.
    fn stats(&self) -> &CongestionStats;

    fn min_pacing_rate(&self) -> Option<u64> {
        None
    }

    /// Return raw model-based bandwidth signals when the congestion controller
    /// maintains them. Window-based controllers keep the default `None`.
    fn bandwidth_metrics(&self) -> Option<BandwidthMetrics> {
        None
    }

    /// Set (or clear) an externally supplied target send rate, in bytes/sec
    /// (MP_SQM_PLAN.md S2.4). Every measurement-driven algorithm (CUBIC,
    /// BBR/BBRv3, COPA) keeps the default no-op: they derive their own rate
    /// and have nothing to overwrite it with. Only rate-driven algorithms
    /// (`Brutal`) act on this -- for `Brutal` specifically, this is its only
    /// source of rate, fed by `Path::set_scheduler_target_rate` so an MP
    /// max-flow allocation becomes each path's actual send rate with no
    /// separate channel.
    fn set_target_rate(&mut self, bps: Option<u64>) {}

    /// The path's maximum datagram size changed (DPLPMTUD or a peer limit).
    /// Default no-op keeps every existing algorithm's behaviour; `Brutal`
    /// uses it as its window floor, like Hysteria's `SetMaxDatagramSize`.
    fn set_max_datagram_size(&mut self, max_datagram_size: u64) {}

    /// The sender has nothing more to send although neither the congestion
    /// window nor the pacer holds it back: the packets in flight do not fill
    /// the path, and rate samples taken until they are acknowledged say
    /// nothing about its bandwidth (draft-cheng-iccrg-delivery-rate-estimation
    /// Section 3.4, MarkConnectionAppLimited). Controllers without a
    /// delivery-rate model keep the default no-op.
    fn on_app_limited(&mut self) {}
}

impl fmt::Debug for dyn CongestionController {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "congestion controller.")
    }
}

/// Build a congestion controller.
pub fn build_congestion_controller(conf: &RecoveryConfig) -> Box<dyn CongestionController> {
    match conf.congestion_control_algorithm {
        CongestionControlAlgorithm::Cubic => Box::new(Cubic::new(CubicConfig::from(conf))),
        CongestionControlAlgorithm::Bbr => Box::new(Bbr::new(BbrConfig::from(conf))),
        CongestionControlAlgorithm::Bbr3 => Box::new(Bbr3::new(Bbr3Config::from(conf))),
        CongestionControlAlgorithm::Copa => Box::new(Copa::new(CopaConfig::from(conf))),
        CongestionControlAlgorithm::Dummy => Box::new(Dummy::new(DummyConfig::from(conf))),
        CongestionControlAlgorithm::Brutal => Box::new(Brutal::new(BrutalConfig::from(conf))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Config;
    use crate::Result;
    use std::time;

    #[test]
    fn congestion_control_name() {
        use super::*;

        let cases = [
            ("cubic", Ok(CongestionControlAlgorithm::Cubic)),
            ("Cubic", Ok(CongestionControlAlgorithm::Cubic)),
            ("CUBIC", Ok(CongestionControlAlgorithm::Cubic)),
            ("bbr", Ok(CongestionControlAlgorithm::Bbr)),
            ("Bbr", Ok(CongestionControlAlgorithm::Bbr)),
            ("BBR", Ok(CongestionControlAlgorithm::Bbr)),
            ("bbr3", Ok(CongestionControlAlgorithm::Bbr3)),
            ("Bbr3", Ok(CongestionControlAlgorithm::Bbr3)),
            ("BBR3", Ok(CongestionControlAlgorithm::Bbr3)),
            ("copa", Ok(CongestionControlAlgorithm::Copa)),
            ("Copa", Ok(CongestionControlAlgorithm::Copa)),
            ("COPA", Ok(CongestionControlAlgorithm::Copa)),
            ("dummy", Ok(CongestionControlAlgorithm::Dummy)),
            ("Dummy", Ok(CongestionControlAlgorithm::Dummy)),
            ("DUMMY", Ok(CongestionControlAlgorithm::Dummy)),
            ("cubci", Err(Error::InvalidConfig("unknown".into()))),
        ];

        for (name, algor) in cases {
            assert_eq!(CongestionControlAlgorithm::from_str(name), algor);
        }
    }

    #[test]
    fn congestion_control_build_congestion_controller() -> Result<()> {
        let mut config = Config::new()?;

        let cc = build_congestion_controller(&config.recovery);
        assert_eq!(cc.name(), "BBR");
        assert_eq!(cc.in_slow_start(), true);
        assert_eq!(cc.in_recovery(Instant::now()), false);
        assert_eq!(
            cc.initial_window(),
            config.recovery.initial_congestion_window * config.recovery.max_datagram_size as u64
        );
        assert_eq!(
            cc.minimal_window(),
            config.recovery.min_congestion_window * config.recovery.max_datagram_size as u64
        );
        assert_eq!(
            cc.congestion_window(),
            cc.minimal_window().max(cc.initial_window())
        );
        assert!(cc.pacing_rate().is_some());
        assert!(cc.min_pacing_rate().is_some());
        assert_eq!(format!("{:?}", cc), "congestion controller.");

        config.set_congestion_control_algorithm(CongestionControlAlgorithm::Bbr);
        let cc = build_congestion_controller(&config.recovery);
        assert_eq!(cc.name(), "BBR");

        config.set_congestion_control_algorithm(CongestionControlAlgorithm::Bbr3);
        let cc = build_congestion_controller(&config.recovery);
        assert_eq!(cc.name(), "BBRv3");

        config.set_congestion_control_algorithm(CongestionControlAlgorithm::Copa);
        let cc = build_congestion_controller(&config.recovery);
        assert_eq!(cc.name(), "COPA");

        Ok(())
    }
}

mod bbr;
mod bbr3;
mod brutal;
mod copa;
mod cubic;
mod delivery_rate;
mod dummy;
mod hystart_plus_plus;
mod minmax;
mod pacing;
