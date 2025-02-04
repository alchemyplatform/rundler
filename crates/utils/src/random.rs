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
//! Random fill utility functions
use alloy_primitives::Bytes;
use rand::RngCore;

/// Fills a bytes array of size ARR_SIZE with FILL_SIZE random bytes starting
/// at the beginning
pub fn random_bytes_array<const ARR_SIZE: usize, const FILL_SIZE: usize>() -> [u8; ARR_SIZE] {
    let mut bytes = [0_u8; ARR_SIZE];
    rand::thread_rng().fill_bytes(&mut bytes[..FILL_SIZE]);
    bytes
}

/// Fills a bytes object with fill_size random bytes
pub fn random_bytes(fill_size: usize) -> Bytes {
    let mut bytes = vec![0_u8; fill_size];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.into()
}
