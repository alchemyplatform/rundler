use std::ops::{Div, Mul};

pub fn increase_by_percent<T>(n: T, percent: u64) -> T
where
    T: Mul<u64, Output = T> + Div<u64, Output = T>,
{
    n * (100 + percent) / 100
}
