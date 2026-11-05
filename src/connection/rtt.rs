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
use std::time::Duration;
use std::time::Instant;

use crate::congestion_control::minmax::MinMax;
use crate::TIMER_GRANULARITY;

/// How long a sample stays the path's propagation delay estimate
/// (`windowed_min_rtt`). ET: Linux's `tcp_min_rtt_wlen` default (300 s,
/// `net/ipv4/tcp_ipv4.c`), kept by the Nichols filter of `lib/win_minmax.c`
/// (`tcp_update_rtt_min`). BBR's 10 s `MinRTTFilterLen` is not usable here: BBR
/// drains the queue in ProbeRTT so that every window holds a low sample, a
/// path selector has no such probe, and on a bufferbloated uplink the first
/// sample after 10 s is a queued one. The lifetime minimum of RFC 9002
/// Section 5.2 never forgets a route that is gone.
pub const MIN_RTT_WINDOW: Duration = Duration::from_secs(300);

/// RTT estimation for a network path
/// See RFC 9001 Section 5
pub struct RttEstimator {
    /// The most recent RTT sample.
    latest_rtt: Duration,

    /// The smoothed RTT of the path is an exponentially weighted moving average
    /// of an endpoint's RTT samples
    smoothed_rtt: Option<Duration>,

    /// The RTT variance estimates the variation in the RTT samples using a
    /// mean variation
    rttvar: Duration,

    /// The minimum RTT observed on the path, ignoring ack delay.
    /// It is used by loss detection to reject implausibly small RTT samples.
    min_rtt: Duration,

    /// The maximum RTT observed on the path, ignoring ack delay.
    max_rtt: Duration,

    /// The smallest sample of the last `MIN_RTT_WINDOW`, in microseconds
    /// since `origin`; 0 until the first sample.
    windowed_min_rtt: MinMax,

    /// The filter's time zero.
    origin: Instant,
}

/// An statistical description of the network path's RTT
impl RttEstimator {
    pub fn new(initial_rtt: Duration) -> Self {
        Self {
            latest_rtt: initial_rtt,
            smoothed_rtt: None,
            rttvar: initial_rtt / 2,
            min_rtt: initial_rtt,
            max_rtt: initial_rtt,
            windowed_min_rtt: MinMax::new(MIN_RTT_WINDOW.as_micros() as u64),
            origin: Instant::now(),
        }
    }

    /// Return the current best RTT estimation.
    pub fn smoothed_rtt(&self) -> Duration {
        self.smoothed_rtt.unwrap_or(self.latest_rtt)
    }

    /// Return the latest rtt sample
    pub fn latest_rtt(&self) -> Duration {
        self.latest_rtt
    }

    /// Return the Minimum RTT observed so far for this estimator.
    pub fn min_rtt(&self) -> Duration {
        self.min_rtt
    }

    /// The path's propagation delay: the smallest RTT sample of the last
    /// `MIN_RTT_WINDOW`, without the queueing that `smoothed_rtt` includes.
    /// The initial RTT until the first sample.
    pub fn windowed_min_rtt(&self) -> Duration {
        match self.windowed_min_rtt.get() {
            0 => self.latest_rtt,
            micros => Duration::from_micros(micros),
        }
    }

    /// Return the variation in the RTT samples using a mean variation.
    pub fn rttvar(&self) -> Duration {
        self.rttvar
    }

    /// Return the Maximum RTT observed so far for this estimator.
    pub fn max_rtt(&self) -> Duration {
        self.max_rtt
    }

    /// Return the PTO computed as described in RFC 9002 Section 6.2.1
    pub fn pto_base(&self) -> Duration {
        self.smoothed_rtt() + cmp::max(4 * self.rttvar, TIMER_GRANULARITY)
    }

    /// Try to set the initial RTT if no RTT samples have been updated.
    ///
    /// The API is generally used in the following scenarios:
    /// - A connection MAY use the delay between sending a PATH_CHALLENGE and
    ///   receiving a PATH_RESPONSE to set the initial RTT for a new path, but the
    ///   delay SHOULD NOT be considered an RTT sample.
    /// - Resumed connections over the same network MAY use the previous connection's
    ///   final smoothed RTT value as the resumed connection's initial RTT.
    pub fn try_set_init_rtt(&mut self, init_rtt: Duration) {
        // Only set init_rtt when no rtt sample.
        if self.smoothed_rtt.is_some() {
            return;
        }

        self.latest_rtt = init_rtt;
        self.smoothed_rtt = None;
        self.rttvar = init_rtt / 2;
        self.min_rtt = init_rtt;
        self.max_rtt = init_rtt;
    }

    /// Update estimator with the given RTT sample
    pub fn update(&mut self, ack_delay: Duration, rtt: Duration) {
        self.update_at(ack_delay, rtt, Instant::now())
    }

    fn update_at(&mut self, ack_delay: Duration, rtt: Duration, now: Instant) {
        // `MinMax` reads 0 as "no sample"; Linux's `tcp_update_rtt_min` also
        // lifts a zero sample to one tick.
        self.windowed_min_rtt.update_min(
            now.saturating_duration_since(self.origin).as_micros() as u64,
            (rtt.as_micros() as u64).max(1),
        );

        self.latest_rtt = rtt;
        self.min_rtt = cmp::min(self.min_rtt, self.latest_rtt);
        self.max_rtt = cmp::max(self.max_rtt, self.latest_rtt);

        if let Some(smoothed_rtt) = self.smoothed_rtt {
            // The endpoint MUST NOT subtract the acknowledgment delay from the
            // RTT sample if the resulting value is smaller than the min_rtt.
            let adjusted_rtt = if self.min_rtt + ack_delay <= self.latest_rtt {
                self.latest_rtt - ack_delay
            } else {
                self.latest_rtt
            };

            let var_sample = if smoothed_rtt > adjusted_rtt {
                smoothed_rtt - adjusted_rtt
            } else {
                adjusted_rtt - smoothed_rtt
            };

            self.rttvar = (3 * self.rttvar + var_sample) / 4;
            self.smoothed_rtt = Some((7 * smoothed_rtt + adjusted_rtt) / 8);
        } else {
            self.smoothed_rtt = Some(self.latest_rtt);
            self.rttvar = self.latest_rtt / 2;
            self.min_rtt = self.latest_rtt;
            self.max_rtt = self.latest_rtt;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time;

    #[test]
    fn initial() {
        let initial_rtt = time::Duration::from_millis(200);
        let r = RttEstimator::new(initial_rtt);
        assert_eq!(r.latest_rtt(), initial_rtt);
        assert_eq!(r.min_rtt(), initial_rtt);
        assert_eq!(r.max_rtt(), initial_rtt);
        assert_eq!(r.rttvar(), initial_rtt / 2);
        assert_eq!(r.smoothed_rtt(), initial_rtt);
        assert_eq!(r.pto_base(), initial_rtt * 3);
    }

    #[test]
    fn update() {
        let initial_rtt = time::Duration::from_millis(200);
        let mut r = RttEstimator::new(initial_rtt);

        // Try set init_rtt before get RTT sample
        let initial_rtt_before_sample = time::Duration::from_millis(100);
        r.try_set_init_rtt(initial_rtt_before_sample);
        assert_eq!(r.latest_rtt(), initial_rtt_before_sample);
        assert_eq!(r.min_rtt(), initial_rtt_before_sample);
        assert_eq!(r.max_rtt(), initial_rtt_before_sample);
        assert_eq!(r.rttvar(), initial_rtt_before_sample / 2);
        assert_eq!(r.smoothed_rtt(), initial_rtt_before_sample);

        // First rtt sample
        let rtt_sample = time::Duration::from_millis(400);
        let ack_delay = time::Duration::from_millis(100);
        r.update(ack_delay, rtt_sample);
        assert_eq!(r.latest_rtt(), rtt_sample);
        assert_eq!(r.min_rtt(), rtt_sample);
        assert_eq!(r.max_rtt(), rtt_sample);
        assert_eq!(r.rttvar(), rtt_sample / 2);
        assert_eq!(r.smoothed_rtt(), rtt_sample);
        assert_eq!(r.pto_base(), rtt_sample * 3);

        // Try set init_rtt after get RTT sample
        let initial_rtt_after_sample = time::Duration::from_millis(300);
        r.try_set_init_rtt(initial_rtt_after_sample);
        assert_eq!(r.latest_rtt(), rtt_sample);
        assert_eq!(r.min_rtt(), rtt_sample);
        assert_eq!(r.max_rtt(), rtt_sample);
        assert_eq!(r.rttvar(), rtt_sample / 2);
        assert_eq!(r.smoothed_rtt(), rtt_sample);

        // Second rtt sample
        let rtt_sample = time::Duration::from_millis(700);
        let ack_delay = time::Duration::from_millis(100);
        r.update(ack_delay, rtt_sample);
        assert_eq!(r.latest_rtt(), rtt_sample);
        assert_eq!(r.min_rtt(), time::Duration::from_millis(400));
        assert_eq!(r.max_rtt(), time::Duration::from_millis(700));
        assert_eq!(r.rttvar(), time::Duration::from_millis(200));
        assert_eq!(r.smoothed_rtt(), time::Duration::from_millis(425));
        assert_eq!(r.pto_base(), time::Duration::from_millis(1225));

        // Third rtt sample
        let rtt_sample = time::Duration::from_millis(225);
        let ack_delay = time::Duration::from_millis(100);
        r.update(ack_delay, rtt_sample);
        assert_eq!(r.latest_rtt(), rtt_sample);
        assert_eq!(r.min_rtt(), time::Duration::from_millis(225));
        assert_eq!(r.max_rtt(), time::Duration::from_millis(700));
        assert_eq!(r.rttvar(), time::Duration::from_millis(200));
        assert_eq!(r.smoothed_rtt(), time::Duration::from_millis(400));
        assert_eq!(r.pto_base(), time::Duration::from_millis(1200));
    }

    #[test]
    fn windowed_min_rtt_forgets_a_minimum_older_than_the_window() {
        let ms = time::Duration::from_millis;
        let t0 = Instant::now();
        let mut r = RttEstimator::new(ms(333));
        assert_eq!(r.windowed_min_rtt(), ms(333));

        r.update_at(ms(0), ms(20), t0);
        r.update_at(ms(0), ms(150), t0 + ms(1_000));
        assert_eq!(r.windowed_min_rtt(), ms(20));
        assert_eq!(r.min_rtt(), ms(20));

        // The route changed: every sample is now 80 ms. The lifetime minimum
        // stays at 20 ms, the windowed one moves once 20 ms is too old.
        r.update_at(ms(0), ms(80), t0 + ms(5_000));
        assert_eq!(r.windowed_min_rtt(), ms(20));
        r.update_at(ms(0), ms(80), t0 + MIN_RTT_WINDOW + ms(1));
        assert_eq!(r.windowed_min_rtt(), ms(80));
        assert_eq!(r.min_rtt(), ms(20));
    }

    #[test]
    fn windowed_min_rtt_keeps_the_propagation_delay_while_the_queue_builds() {
        let ms = time::Duration::from_millis;
        let mut r = RttEstimator::new(ms(333));
        let t0 = Instant::now();

        // An idle path measures its propagation delay.
        for s in 0..=5 {
            r.update_at(ms(0), ms(47), t0 + ms(s * 1_000));
        }
        // Then it carries load and the bufferbloated uplink queues every sample.
        // Past 10 s a "replace once old" filter adopts the queued sample.
        for s in 6..=20 {
            r.update_at(ms(0), ms(150 + (s % 7) * 10), t0 + ms(s * 1_000));
            assert_eq!(r.windowed_min_rtt(), ms(47), "at {s} s");
        }
    }

    #[test]
    fn windowed_min_rtt_follows_a_longer_route_after_the_window() {
        let ms = time::Duration::from_millis;
        let mut r = RttEstimator::new(ms(333));
        let t0 = Instant::now();

        r.update_at(ms(0), ms(47), t0);
        // The route got longer: every sample is 117 ms. The 47 ms sample is
        // forgotten only once it is older than the 300 s window.
        let mut s = 1;
        while ms(s * 1_000) <= MIN_RTT_WINDOW {
            r.update_at(ms(0), ms(117), t0 + ms(s * 1_000));
            assert_eq!(r.windowed_min_rtt(), ms(47), "at {s} s");
            s += 15;
        }
        r.update_at(ms(0), ms(117), t0 + MIN_RTT_WINDOW + ms(1_000));
        r.update_at(ms(0), ms(117), t0 + MIN_RTT_WINDOW + ms(2_000));
        assert_eq!(r.windowed_min_rtt(), ms(117));
        assert_eq!(r.min_rtt(), ms(47));
    }

    #[test]
    fn windowed_min_rtt_survives_a_zero_sample() {
        let ms = time::Duration::from_millis;
        let mut r = RttEstimator::new(ms(333));
        let t0 = Instant::now();
        // `MinMax` treats 0 as "uninitialised" (Linux's `tcp_update_rtt_min`
        // substitutes one tick for a zero sample).
        r.update_at(ms(0), time::Duration::ZERO, t0);
        r.update_at(ms(0), ms(30), t0 + ms(1));
        assert!(r.windowed_min_rtt() < ms(1));
    }
}
