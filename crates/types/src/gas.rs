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

use ethers::types::{transaction::eip2718::TypedTransaction, U256};
use rundler_utils::math;

/// Gas fees for a user operation or transaction
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GasFees {
    /// EIP-1559 max fee per gas
    pub max_fee_per_gas: U256,
    /// EIP-1559 max priority fee per gas
    pub max_priority_fee_per_gas: U256,
}

impl From<&TypedTransaction> for GasFees {
    fn from(tx: &TypedTransaction) -> Self {
        match tx {
            TypedTransaction::Eip1559(tx) => Self {
                max_fee_per_gas: tx.max_fee_per_gas.unwrap_or_default(),
                max_priority_fee_per_gas: tx.max_priority_fee_per_gas.unwrap_or_default(),
            },
            _ => Self::default(),
        }
    }
}

impl GasFees {
    /// Increase the gas fees by a percentage
    pub fn increase_by_percent(self, percent: u64) -> Self {
        Self {
            max_fee_per_gas: math::increase_by_percent_ceil(self.max_fee_per_gas, percent),
            max_priority_fee_per_gas: math::increase_by_percent_ceil(
                self.max_priority_fee_per_gas,
                percent,
            ),
        }
    }
}
