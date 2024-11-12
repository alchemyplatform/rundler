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

//! Utilities for track scoped method timer.

use std::time::Instant;

use metrics::Histogram;

/// A customized guard to measure duration and record to metric.
///
/// exmaple usage:
/// ```
/// fn bala() {
///   let _timer = CustomTimerGuard::new(metric);
///   ...
/// } // _timer will automatically dropped and record the duration.
/// ```
pub struct CustomTimerGuard {
    timer: Instant,
    metric: Histogram,
}

impl CustomTimerGuard {
    /// initialzie instance.
    pub fn new(metric: Histogram) -> Self {
        Self {
            timer: Instant::now(),
            metric,
        }
    }
}

impl Drop for CustomTimerGuard {
    fn drop(&mut self) {
        self.metric.record(self.timer.elapsed().as_millis() as f64);
    }
}
