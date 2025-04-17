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

use std::cmp;

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

    /// Get the gas price from these fees given a base fee
    pub fn gas_price(self, base_fee: u128) -> u128 {
        cmp::min(
            self.max_fee_per_gas,
            base_fee.saturating_add(self.max_priority_fee_per_gas),
        )
    }
}

/// Different modes for calculating the required priority fee
/// for the bundler to include a user operation in a bundle.
#[derive(Debug, Clone, Copy)]
pub enum PriorityFeeMode {
    /// The priority fee is required to be a percentage of the bundle base fee.
    BaseFeePercent(u32),
    /// The priority fee is required to be a percentage above the bundle priority fee.
    PriorityFeeIncreasePercent(u32),
}

impl PriorityFeeMode {
    /// Try to create a priority fee mode from a string and value.
    pub fn try_from(kind: &str, value: u32) -> anyhow::Result<Self> {
        match kind {
            "base_fee_percent" => Ok(Self::BaseFeePercent(value)),
            "priority_fee_increase_percent" => Ok(Self::PriorityFeeIncreasePercent(value)),
            _ => anyhow::bail!("Invalid priority fee mode: {}", kind),
        }
    }

    /// Returns the required fees for the given bundle fees based on this priority
    /// fee mode.
    pub fn required_fees(&self, bundle_fees: GasFees) -> GasFees {
        let base_fee = bundle_fees.max_fee_per_gas - bundle_fees.max_priority_fee_per_gas;

        let max_priority_fee_per_gas = match *self {
            PriorityFeeMode::BaseFeePercent(percent) => math::percent(base_fee, percent),
            PriorityFeeMode::PriorityFeeIncreasePercent(percent) => {
                math::increase_by_percent(bundle_fees.max_priority_fee_per_gas, percent)
            }
        };

        let max_fee_per_gas = base_fee + max_priority_fee_per_gas;
        GasFees {
            max_fee_per_gas,
            max_priority_fee_per_gas,
        }
    }

    /// Calculate the minimum priority fee given the current bundle fees and network configured
    /// settings
    pub fn minimum_priority_fee(
        &self,
        base_fee: u128,
        base_fee_accept_percent: u32,
        min_max_priority_fee_per_gas: u128,
        bundle_priority_fee_overhead_percent: u32,
    ) -> u128 {
        match *self {
            PriorityFeeMode::BaseFeePercent(percent) => {
                math::percent(math::percent(base_fee, base_fee_accept_percent), percent)
            }
            PriorityFeeMode::PriorityFeeIncreasePercent(percent) => math::increase_by_percent(
                min_max_priority_fee_per_gas,
                percent + bundle_priority_fee_overhead_percent,
            ),
        }
    }
}
