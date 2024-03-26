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

//! Timestamps and time ranges for ERC-4337 validity checks.

use std::{
    error::Error,
    fmt,
    fmt::{Debug, Display, Formatter},
    ops::{Add, AddAssign, Sub, SubAssign},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use chrono::{DateTime, LocalResult, TimeZone, Utc};
use ethers::types::U64;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// An on-chain timestamp expressed as seconds since the epoch, as might be
/// returned in a block header or in the `valid_before`/`valid_after` bounds in
/// ERC-4337.
///
/// Can be shifted by adding or subtracting a `Duration`. Can be converted to a
/// `DateTime<Utc>`, although this may fail if the timestamp is too large.
/// Serializes and deserializes as a hex string.

// Doesn't derive Debug because it has a custom implementation.
#[derive(Clone, Copy, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Timestamp(u64);

impl Timestamp {
    /// Minimum timestamp value
    pub const MIN: Timestamp = Timestamp(u64::MIN);
    /// Maximum timestamp value
    pub const MAX: Timestamp = Timestamp(u64::MAX);

    /// Create a new timestamp from seconds since the epoch.
    pub fn new(seconds_since_epoch: u64) -> Self {
        Self(seconds_since_epoch)
    }

    /// Create a new timestamp representing the current time.
    pub fn now() -> Self {
        Self(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time should be after epoch")
                .as_secs(),
        )
    }

    /// Returns the number of seconds since the epoch of this timestamp.
    pub fn seconds_since_epoch(self) -> u64 {
        self.0
    }
}

impl From<u64> for Timestamp {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl Add<Duration> for Timestamp {
    type Output = Self;

    fn add(self, duration: Duration) -> Self::Output {
        Self(self.0 + duration.as_secs())
    }
}

impl AddAssign<Duration> for Timestamp {
    fn add_assign(&mut self, duration: Duration) {
        *self = *self + duration;
    }
}

impl Sub<Duration> for Timestamp {
    type Output = Self;

    fn sub(self, duration: Duration) -> Self::Output {
        Self(self.0 - duration.as_secs())
    }
}

impl SubAssign<Duration> for Timestamp {
    fn sub_assign(&mut self, duration: Duration) {
        *self = *self - duration
    }
}

impl Display for Timestamp {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if let Ok(datetime) = DateTime::<Utc>::try_from(*self) {
            Display::fmt(&datetime, f)
        } else {
            write!(f, "later than {}", DateTime::<Utc>::MAX_UTC)
        }
    }
}

impl Debug for Timestamp {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Timestamp({} = {})", self.0, self)
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let n = <U64>::deserialize(deserializer)?;
        Ok(Self(n.as_u64()))
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        <U64>::from(self.0).serialize(serializer)
    }
}

impl TryFrom<Timestamp> for DateTime<Utc> {
    type Error = TimestampTooLarge;

    fn try_from(timestamp: Timestamp) -> Result<Self, Self::Error> {
        let secs = i64::try_from(timestamp.seconds_since_epoch()).map_err(|_| TimestampTooLarge)?;
        if let LocalResult::Single(datetime) = Utc.timestamp_opt(secs, 0) {
            Ok(datetime)
        } else {
            Err(TimestampTooLarge)
        }
    }
}

#[derive(Debug)]
pub struct TimestampTooLarge;

impl Display for TimestampTooLarge {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("timestamp is too large to convert to a datetime")
    }
}

impl Error for TimestampTooLarge {}

/// Represents a `[valid_after, valid_until)` pair as seen in ERC-4337 validity checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidTimeRange {
    /// The earliest time at which the operation is valid, inclusive.
    pub valid_after: Timestamp,
    /// The latest time at which the operation is valid, inclusive.
    pub valid_until: Timestamp,
}

impl Default for ValidTimeRange {
    fn default() -> Self {
        Self {
            valid_after: Timestamp::MIN,
            valid_until: Timestamp::MAX,
        }
    }
}

impl ValidTimeRange {
    /// Create a new valid new time range.
    pub fn new(valid_after: Timestamp, valid_until: Timestamp) -> Self {
        Self {
            valid_after,
            valid_until,
        }
    }

    /// A time range representing that the operation is valid for all time.
    pub fn all_time() -> Self {
        Self::default()
    }

    /// Returns true if the given timestamp falls within this time range,
    /// including a minimum buffer time that must be remaining before the time
    /// range expires.
    pub fn contains(self, timestamp: Timestamp, buffer: Duration) -> bool {
        self.valid_after <= timestamp && (timestamp + buffer) <= self.valid_until
    }

    /// Intersect two time ranges into a single time range that is valid whenever both are valid
    pub fn intersect(self, other: Self) -> Self {
        Self {
            valid_after: self.valid_after.max(other.valid_after),
            valid_until: self.valid_until.min(other.valid_until),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_wrapping_and_unwrapping_seconds() {
        assert_eq!(Timestamp::new(123).seconds_since_epoch(), 123);
    }

    #[test]
    fn test_now() {
        let actual_now_seconds = Timestamp::now().seconds_since_epoch();
        let expected_now_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("current time should be after epoch")
            .as_secs();
        assert!(actual_now_seconds - expected_now_seconds < 2);
    }

    #[test]
    fn test_adding_duration() {
        let mut timestamp = Timestamp::new(100);
        let duration = Duration::from_millis(12345);
        let expected_sum = Timestamp::new(112);
        assert_eq!(timestamp + duration, expected_sum);
        timestamp += duration;
        assert_eq!(timestamp, expected_sum);
    }

    #[test]
    fn test_subtracting_duration() {
        let mut timestamp = Timestamp::new(112);
        let duration = Duration::from_millis(12345);
        let expected_difference = Timestamp::new(100);
        assert_eq!(timestamp - duration, expected_difference);
        timestamp -= duration;
        assert_eq!(timestamp, expected_difference);
    }

    #[test]
    fn test_in_bounds_conversion_to_datetime() {
        let actual_datetime: DateTime<Utc> = Timestamp::new(100_000_000)
            .try_into()
            .expect("should convert low-ish timestamp to DateTime");
        let expected_datetime = DateTime::<Utc>::default() + chrono::Duration::seconds(100_000_000);
        assert_eq!(actual_datetime, expected_datetime);
    }

    #[test]
    fn test_out_of_bounds_conversion_to_datetime() {
        let timestamp = get_timestamp_out_of_bounds_for_datetime();
        DateTime::<Utc>::try_from(timestamp)
            .expect_err("out of bounds timestamp shouldn't convert to DateTime");
    }

    #[test]
    fn test_in_bounds_display() {
        let actual = Timestamp::new(100).to_string();
        assert_eq!(actual, "1970-01-01 00:01:40 UTC");
    }

    #[test]
    fn test_out_of_bounds_display() {
        let actual = get_timestamp_out_of_bounds_for_datetime().to_string();
        assert_eq!(actual, "later than +262143-12-31 23:59:59.999999999 UTC");
    }

    #[test]
    fn test_debug() {
        let actual = format!("{:?}", Timestamp::new(100));
        assert_eq!(actual, "Timestamp(100 = 1970-01-01 00:01:40 UTC)");
    }

    #[test]
    fn test_deserialization() {
        let json = "\"0x64\"";
        let timestamp: Timestamp =
            serde_json::from_str(json).expect("should deserialize valid hex");
        assert_eq!(timestamp, Timestamp::new(100));
        let json = "\"0xg1\"";
        serde_json::from_str::<'_, Timestamp>(json).expect_err("should fail on invalid hex");
        let json = "\"0x111111111111111111\"";
        serde_json::from_str::<'_, Timestamp>(json).expect_err("should fail on too large hex");
    }

    #[test]
    fn test_serialization() {
        let json = serde_json::to_string(&Timestamp::new(100))
            .expect("serialization should always succeed");
        assert_eq!(json, "\"0x64\"");
    }

    #[test]
    fn test_merge_time_ranges() {
        let range1 = ValidTimeRange::new(Timestamp::new(100), Timestamp::new(200));
        let range2 = ValidTimeRange::new(Timestamp::new(150), Timestamp::new(250));
        let intersect = range1.intersect(range2);
        assert_eq!(intersect.valid_after, Timestamp::new(150));
        assert_eq!(intersect.valid_until, Timestamp::new(200));
    }

    fn get_timestamp_out_of_bounds_for_datetime() -> Timestamp {
        // This is just a bit further in the future than the maximum allowed
        // DateTime, which is just before the start of year 2^18 = 262144.
        Timestamp(1 << 44)
    }
}
