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

// from reth github: https://github.com/paradigmxyz/reth/blob/main/crates/transaction-pool/src/pool/size.rs
//! Tracks a size value.
use std::ops::{AddAssign, SubAssign};

/// Keeps track of accumulated size in bytes.
///
/// Note: We do not assume that size tracking is always exact. Depending on the bookkeeping of the
/// additions and subtractions the total size might be slightly off. Therefore, the underlying value
/// is an `isize`, so that the value does not wrap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SizeTracker(pub isize);

impl AddAssign<usize> for SizeTracker {
    fn add_assign(&mut self, rhs: usize) {
        self.0 += rhs as isize
    }
}

impl SubAssign<usize> for SizeTracker {
    fn sub_assign(&mut self, rhs: usize) {
        self.0 -= rhs as isize
    }
}

impl From<SizeTracker> for usize {
    fn from(value: SizeTracker) -> Self {
        value.0 as usize
    }
}

impl PartialEq<usize> for SizeTracker {
    fn eq(&self, other: &usize) -> bool {
        self.0 == (*other as isize)
    }
}

impl PartialOrd<usize> for SizeTracker {
    fn partial_cmp(&self, other: &usize) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(&(*other as isize))
    }
}
