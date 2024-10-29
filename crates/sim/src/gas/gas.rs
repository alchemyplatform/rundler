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

use std::fmt::Debug;

use anyhow::Context;
#[cfg(feature = "test-utils")]
use mockall::automock;
use rundler_provider::{BlockHashOrNumber, DAGasProvider, EvmProvider};
use rundler_types::{chain::ChainSpec, da::DAGasUOData, GasFees, UserOperation};
use rundler_utils::math;
use tokio::try_join;

use super::oracle::FeeOracle;

/// Returns the required pre_verification_gas for the given user operation
///
/// `full_op` is either the user operation submitted via `sendUserOperation`
/// or the user operation that was submitted via `estimateUserOperationGas` and filled
/// in via its `max_fill()` call. It is used to calculate the static portion of the pre_verification_gas
///
/// `random_op` is either the user operation submitted via `sendUserOperation`
/// or the user operation that was submitted via `estimateUserOperationGas` and filled
/// in via its `random_fill()` call. It is used to calculate the DA portion of the pre_verification_gas
/// on networks that require it.
///
/// Networks that require Data Availability (DA) pre_verification_gas are those that charge extra calldata fees
/// that can scale based on DA gas prices.
pub async fn estimate_pre_verification_gas<UO: UserOperation, E: DAGasProvider<UO = UO>>(
    chain_spec: &ChainSpec,
    entry_point: &E,
    full_op: &UO,
    random_op: &UO,
    block: BlockHashOrNumber,
    gas_price: u128,
) -> anyhow::Result<u128> {
    let da_gas = if chain_spec.da_pre_verification_gas {
        entry_point
            .calc_da_gas(random_op.clone(), block, gas_price)
            .await?
            .0
    } else {
        0
    };

    // Currently assume 1 op bundle
    Ok(full_op.required_pre_verification_gas(chain_spec, 1, da_gas))
}

/// Calculate the required pre_verification_gas for the given user operation and the provided base fee.
///
/// The effective gas price is calculated as min(base_fee + max_priority_fee_per_gas, max_fee_per_gas)
pub async fn calc_required_pre_verification_gas<UO: UserOperation, E: DAGasProvider<UO = UO>>(
    chain_spec: &ChainSpec,
    entry_point: &E,
    op: &UO,
    block: BlockHashOrNumber,
    base_fee: u128,
) -> anyhow::Result<(u128, DAGasUOData)> {
    let (da_gas, uo_data) = if chain_spec.da_pre_verification_gas {
        let (da_gas, uo_data, _) = entry_point
            .calc_da_gas(op.clone(), block, op.gas_price(base_fee))
            .await?;
        (da_gas, uo_data)
    } else {
        (0, DAGasUOData::Empty)
    };

    // Currently assume 1 op bundle
    Ok((
        op.required_pre_verification_gas(chain_spec, 1, da_gas),
        uo_data,
    ))
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
    ) -> u128 {
        match *self {
            PriorityFeeMode::BaseFeePercent(percent) => {
                math::percent(math::percent(base_fee, base_fee_accept_percent), percent)
            }
            PriorityFeeMode::PriorityFeeIncreasePercent(percent) => {
                math::increase_by_percent(min_max_priority_fee_per_gas, percent)
            }
        }
    }
}

/// Trait for a fee estimator.
#[cfg_attr(feature = "test-utils", automock)]
#[async_trait::async_trait]
pub trait FeeEstimator: Send + Sync {
    /// Returns the required fees for the given bundle fees.
    ///
    /// `min_fees` is used to set the minimum fees to use for the bundle. Typically used if a
    /// bundle has already been submitted and its fees must at least be a certain amount above the
    /// already submitted fees.
    ///
    /// Returns the required fees and the current base fee.
    async fn required_bundle_fees(
        &self,
        min_fees: Option<GasFees>,
    ) -> anyhow::Result<(GasFees, u128)>;

    /// Returns the required operation fees for the given bundle fees.
    fn required_op_fees(&self, bundle_fees: GasFees) -> GasFees;
}

/// Gas fee estimator for a 4337 user operation.
#[derive(Clone)]
pub struct FeeEstimatorImpl<P, O> {
    provider: P,
    priority_fee_mode: PriorityFeeMode,
    bundle_base_fee_overhead_percent: u32,
    bundle_priority_fee_overhead_percent: u32,
    fee_oracle: O,
}

impl<P: EvmProvider, O: FeeOracle> FeeEstimatorImpl<P, O> {
    /// Create a new fee estimator.
    ///
    /// `priority_fee_mode` is used to determine how the required priority fee is calculated.
    ///
    /// `bundle_priority_fee_overhead_percent` is used to determine the overhead percentage to add
    /// to the network returned priority fee to ensure the bundle priority fee is high enough.
    pub fn new(
        provider: P,
        fee_oracle: O,
        priority_fee_mode: PriorityFeeMode,
        bundle_base_fee_overhead_percent: u32,
        bundle_priority_fee_overhead_percent: u32,
    ) -> Self {
        Self {
            provider,
            fee_oracle,
            priority_fee_mode,
            bundle_base_fee_overhead_percent,
            bundle_priority_fee_overhead_percent,
        }
    }

    async fn get_pending_base_fee(&self) -> anyhow::Result<u128> {
        Ok(self.provider.get_pending_base_fee().await?)
    }

    async fn get_priority_fee(&self) -> anyhow::Result<u128> {
        self.fee_oracle
            .estimate_priority_fee()
            .await
            .context("should get priority fee")
    }
}

#[async_trait::async_trait]
impl<P: EvmProvider, O: FeeOracle> FeeEstimator for FeeEstimatorImpl<P, O> {
    async fn required_bundle_fees(
        &self,
        min_fees: Option<GasFees>,
    ) -> anyhow::Result<(GasFees, u128)> {
        let (base_fee, priority_fee) =
            try_join!(self.get_pending_base_fee(), self.get_priority_fee())?;

        let base_fee = math::increase_by_percent(base_fee, self.bundle_base_fee_overhead_percent);
        let priority_fee =
            math::increase_by_percent(priority_fee, self.bundle_priority_fee_overhead_percent);

        let required_fees = min_fees.unwrap_or_default();

        let max_priority_fee_per_gas = required_fees.max_priority_fee_per_gas.max(priority_fee);

        let max_fee_per_gas = required_fees
            .max_fee_per_gas
            .max(base_fee + max_priority_fee_per_gas);
        Ok((
            GasFees {
                max_fee_per_gas,
                max_priority_fee_per_gas,
            },
            base_fee,
        ))
    }

    fn required_op_fees(&self, bundle_fees: GasFees) -> GasFees {
        self.priority_fee_mode.required_fees(bundle_fees)
    }
}
