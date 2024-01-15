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

/// Increases a number by a percentage
pub fn increase_by_percent<T>(n: T, percent: u64) -> T
where
    T: Mul<u64, Output = T> + Div<u64, Output = T>,
{
    n * (100 + percent) / 100
}

/// Increases a number by a percentage, rounding up
pub fn increase_by_percent_ceil<T>(n: T, percent: u64) -> T
where
    T: Add<u64, Output = T> + Mul<u64, Output = T> + Div<u64, Output = T>,
{
    (n * (100 + percent) + 99) / 100
}

/// Take a percentage of a number
pub fn percent<T>(n: T, percent: u64) -> T
where
    T: Mul<u64, Output = T> + Div<u64, Output = T>,
{
    n * percent / 100
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_increase_by_percent_ceil() {
        assert_eq!(increase_by_percent_ceil(3, 10), 4);
    }
}
