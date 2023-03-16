use chrono::{DateTime, LocalResult, TimeZone, Utc};
use ethers::types::U64;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::error::Error;
use std::fmt;
use std::fmt::{Debug, Display, Formatter};
use std::ops::{Add, AddAssign, Sub, SubAssign};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
    pub fn new(seconds_since_epoch: u64) -> Self {
        Self(seconds_since_epoch)
    }

    pub fn now() -> Self {
        Self(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time should be after epoch")
                .as_secs(),
        )
    }

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

    fn get_timestamp_out_of_bounds_for_datetime() -> Timestamp {
        // This is just a bit further in the future than the maximum allowed
        // DateTime, which is just before the start of year 2^18 = 262144.
        Timestamp(1 << 44)
    }
}
