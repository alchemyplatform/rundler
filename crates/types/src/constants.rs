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

//! Various constants that have no other home

use alloy_primitives::{address, Address};

/// Address used for simulation calls to the entry point.
/// Calculated as `address(uint160(uint256(keccak256("rundler simulation sender"))))`.
pub const SIMULATION_SENDER: Address = address!("0x0643866dA50efE0b055Cd15aF95191968c8411b5");
