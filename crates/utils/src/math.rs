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

//! Math utilities

use std::ops::{Add, Div, Mul};

use alloy_primitives::Uint;

/// Increases a uint by a percentage
pub fn uint_increase_by_percent<const BITS: usize, const LIMBS: usize>(
    n: Uint<BITS, LIMBS>,
    percent: u32,
) -> Uint<BITS, LIMBS> {
    (n * Uint::from(Uint::<BITS, LIMBS>::from(100) + Uint::<BITS, LIMBS>::from(percent)))
        / Uint::<BITS, LIMBS>::from(100)
}

/// Increases a uint by a percentage, rounding up
pub fn uint_increase_by_percent_ceil<const BITS: usize, const LIMBS: usize>(
    n: Uint<BITS, LIMBS>,
    percent: u32,
) -> Uint<BITS, LIMBS> {
    ((n * (Uint::<BITS, LIMBS>::from(100) + Uint::<BITS, LIMBS>::from(percent)))
        + Uint::<BITS, LIMBS>::from(99))
        / Uint::<BITS, LIMBS>::from(100)
}

/// Take a percentage of a number
pub fn uint_percent<const BITS: usize, const LIMBS: usize>(
    n: Uint<BITS, LIMBS>,
    percent: u32,
) -> Uint<BITS, LIMBS> {
    (n * Uint::<BITS, LIMBS>::from(percent)) / Uint::<BITS, LIMBS>::from(100)
}

/// Increases a number by a percentage
pub fn increase_by_percent<T>(n: T, percent: u32) -> T
where
    T: Mul<Output = T> + Div<Output = T> + From<u32>,
{
    (n * T::from(100 + percent)) / T::from(100)
}

/// Increases a number by a percentage, rounding up
pub fn increase_by_percent_ceil<T>(n: T, percent: u32) -> T
where
    T: Add<Output = T> + Mul<Output = T> + Div<Output = T> + From<u32>,
{
    (n * (T::from(100 + percent)) + T::from(99)) / T::from(100)
}

/// Take a percentage of a number
pub fn percent<T>(n: T, percent: u32) -> T
where
    T: Mul<Output = T> + Div<Output = T> + From<u32>,
{
    (n * T::from(percent)) / T::from(100)
}

#[cfg(test)]
mod tests {
    use alloy_primitives::U256;

    use super::*;

    #[test]
    fn test_uint_increase_by_percent_ceil() {
        assert_eq!(
            uint_increase_by_percent_ceil(U256::from(3), 10),
            U256::from(4)
        );
    }

    #[test]
    fn test_uint_increase_by_percent() {
        assert_eq!(uint_increase_by_percent(U256::from(3), 10), U256::from(3));
    }

    #[test]
    fn test_uint_percent() {
        assert_eq!(uint_percent(U256::from(400), 10), U256::from(40));
    }

    #[test]
    fn test_increase_by_percent_ceil() {
        assert_eq!(increase_by_percent_ceil(3123_u32, 10), 3436);
    }

    #[test]
    fn test_increase_by_percent() {
        assert_eq!(increase_by_percent(3123_u32, 10), 3435);
    }

    #[test]
    fn test_percent() {
        assert_eq!(percent(3123_u32, 10), 312);
    }
}
