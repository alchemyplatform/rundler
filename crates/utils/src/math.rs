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
    (n * (Uint::<BITS, LIMBS>::from(100) + Uint::<BITS, LIMBS>::from(percent)))
        + Uint::<BITS, LIMBS>::from(99) / Uint::<BITS, LIMBS>::from(100)
}

/// Take a percentage of a number
pub fn uint_percent<const BITS: usize, const LIMBS: usize>(
    n: Uint<BITS, LIMBS>,
    percent: u32,
) -> Uint<BITS, LIMBS> {
    n * Uint::<BITS, LIMBS>::from(percent) / Uint::<BITS, LIMBS>::from(100)
}

#[cfg(test)]
mod tests {
    use alloy_primitives::U256;

    use super::*;

    #[test]
    fn test_increase_by_percent_ceil() {
        assert_eq!(
            uint_increase_by_percent_ceil(U256::from(3), 10),
            U256::from(4)
        );
    }
}
