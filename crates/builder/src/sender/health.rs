// This file is part of Rundler.
//
// Rundler is free software: you can redistribute it and/or modify it under the
// terms of the GNU Lesser General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later version.
//
// Rundler is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with Rundler.
// If not, see https://www.gnu.org/licenses/.

use std::{
    collections::VecDeque,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use metrics::{Counter, Gauge};
use metrics_derive::Metrics;

/// Number of most recent non-neutral final submission outcomes considered.
const WINDOW_SIZE: usize = 20;
/// Minimum observations in the window before an event can be entered.
const MIN_OBSERVATIONS: usize = 10;
/// Failure ratio at or above which an event is entered.
const ENTER_FAILURE_RATIO: f64 = 0.30;
/// Failure ratio below which an active event is exited.
const EXIT_FAILURE_RATIO: f64 = 0.10;

/// Rolling-window detector for provider-health events, per the provider-event
/// signal in `docs/designs/poison-user-operations.md`.
///
/// One signal exists per submission route and is shared by its builders. Only
/// final submission outcomes — after provider retries and fallbacks are
/// exhausted — are recorded: successes and non-terminal provider failures.
/// Neutral operational errors and terminal RPC errors are excluded from the
/// window by the caller.
///
/// Entering requires at least `MIN_OBSERVATIONS` with at least
/// `ENTER_FAILURE_RATIO` failures; exiting requires the failure ratio to drop
/// below `EXIT_FAILURE_RATIO`. The different thresholds prevent flapping.
pub(crate) struct ProviderEventSignal {
    /// Recent outcomes, `true` for a failure.
    window: Mutex<VecDeque<bool>>,
    active: AtomicBool,
    metrics: ProviderEventMetrics,
}

impl Default for ProviderEventSignal {
    fn default() -> Self {
        Self {
            window: Mutex::new(VecDeque::with_capacity(WINDOW_SIZE)),
            active: AtomicBool::new(false),
            metrics: ProviderEventMetrics::default(),
        }
    }
}

impl ProviderEventSignal {
    /// Records a final successful submission.
    pub(crate) fn record_success(&self) {
        self.record(false);
    }

    /// Records a final non-terminal provider failure.
    pub(crate) fn record_failure(&self) {
        self.record(true);
    }

    /// Returns true while a provider event is active.
    pub(crate) fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    /// Number of outcomes currently in the window, for tests.
    #[cfg(test)]
    pub(crate) fn observations(&self) -> usize {
        self.window.lock().unwrap().len()
    }

    fn record(&self, failure: bool) {
        let mut window = self.window.lock().unwrap();
        if window.len() == WINDOW_SIZE {
            window.pop_front();
        }
        window.push_back(failure);

        let failures = window.iter().filter(|f| **f).count();
        let ratio = failures as f64 / window.len() as f64;

        if self.active.load(Ordering::Relaxed) {
            if ratio < EXIT_FAILURE_RATIO {
                self.active.store(false, Ordering::Relaxed);
                self.metrics.provider_event_active.set(0.0);
                tracing::info!(
                    "Provider event ended: {failures} failures in last {} submissions",
                    window.len()
                );
            }
        } else if window.len() >= MIN_OBSERVATIONS && ratio >= ENTER_FAILURE_RATIO {
            self.active.store(true, Ordering::Relaxed);
            self.metrics.provider_event_active.set(1.0);
            self.metrics.provider_events_total.increment(1);
            tracing::warn!(
                "Provider event detected: {failures} failures in last {} submissions, pausing poison user operation evidence",
                window.len()
            );
        }
    }
}

#[derive(Metrics)]
#[metrics(scope = "builder_sender")]
struct ProviderEventMetrics {
    #[metric(describe = "whether a provider-health event is currently active.")]
    provider_event_active: Gauge,
    #[metric(describe = "the total number of times a provider-health event was entered.")]
    provider_events_total: Counter,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stays_inactive_below_min_observations() {
        let signal = ProviderEventSignal::default();
        // 100% failures, but fewer than MIN_OBSERVATIONS
        for _ in 0..MIN_OBSERVATIONS - 1 {
            signal.record_failure();
        }
        assert!(!signal.is_active());
    }

    #[test]
    fn enters_event_at_failure_ratio() {
        let signal = ProviderEventSignal::default();
        for _ in 0..7 {
            signal.record_success();
        }
        for _ in 0..2 {
            signal.record_failure();
        }
        // 9 observations: below the minimum even at the enter ratio
        assert!(!signal.is_active());
        signal.record_failure();
        // 3 failures in 10 observations reaches the 30% enter threshold
        assert!(signal.is_active());
    }

    #[test]
    fn stays_below_enter_ratio() {
        let signal = ProviderEventSignal::default();
        for _ in 0..8 {
            signal.record_success();
        }
        for _ in 0..2 {
            signal.record_failure();
        }
        // 2 failures in 10 observations is below the 30% enter threshold
        assert!(!signal.is_active());
    }

    #[test]
    fn exits_event_below_exit_ratio() {
        let signal = ProviderEventSignal::default();
        for _ in 0..7 {
            signal.record_success();
        }
        for _ in 0..3 {
            signal.record_failure();
        }
        assert!(signal.is_active());

        // successes push the failures out of the window; the event ends only
        // once fewer than 10% of the window are failures
        for _ in 0..18 {
            signal.record_success();
        }
        // two of the failures are still within the last 20 outcomes:
        // 2/20 = 10%, not yet below the exit ratio (hysteresis)
        assert!(signal.is_active());
        signal.record_success();
        // 1 failure in 20 = 5%, below the 10% exit ratio
        assert!(!signal.is_active());
    }

    #[test]
    fn old_outcomes_roll_off_the_window() {
        let signal = ProviderEventSignal::default();
        for _ in 0..6 {
            signal.record_failure();
        }
        for _ in 0..WINDOW_SIZE {
            signal.record_success();
        }
        // the failures have been fully evicted
        assert!(!signal.is_active());
        for _ in 0..5 {
            signal.record_failure();
        }
        // 5 failures in the last 20 = 25%, below the enter threshold
        assert!(!signal.is_active());
        signal.record_failure();
        // 6 in 20 = 30%
        assert!(signal.is_active());
    }
}
