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

//! Utilities for 7702 authorization tuples

use alloy_primitives::{fixed_bytes, Address, FixedBytes};
use alloy_rpc_types_eth::state::{AccountOverride, StateOverride};

/// Apply a [7702](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-7702.md)
/// overrides to `StateOverride`.
pub fn apply_7702_overrides(
    state_override: &mut StateOverride,
    sender: Address,
    authorization_contract: Address,
) {
    state_override.entry(sender).or_insert({
        let prefix: FixedBytes<3> = fixed_bytes!("ef0100");
        let code: FixedBytes<23> = prefix.concat_const(authorization_contract.into());

        AccountOverride {
            code: Some((code).into()),
            ..Default::default()
        }
    });
}
