//! Math utilities

use std::ops::{Div, Mul};

/// Increases a number by a percentage
pub fn increase_by_percent<T>(n: T, percent: u64) -> T
where
    T: Mul<u64, Output = T> + Div<u64, Output = T>,
{
    n * (100 + percent) / 100
}

/// Take a percentage of a number
pub fn percent<T>(n: T, percent: u64) -> T
where
    T: Mul<u64, Output = T> + Div<u64, Output = T>,
{
    n * percent / 100
}
