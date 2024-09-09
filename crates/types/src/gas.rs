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

use rundler_utils::math;

/// Gas fees for a user operation or transaction
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GasFees {
    /// EIP-1559 max fee per gas
    pub max_fee_per_gas: u128,
    /// EIP-1559 max priority fee per gas
    pub max_priority_fee_per_gas: u128,
}

impl GasFees {
    /// Increase the gas fees by a percentage
    pub fn increase_by_percent(self, percent: u32) -> Self {
        Self {
            max_fee_per_gas: math::increase_by_percent_ceil(self.max_fee_per_gas, percent),
            max_priority_fee_per_gas: math::increase_by_percent_ceil(
                self.max_priority_fee_per_gas,
                percent,
            ),
        }
    }
}
