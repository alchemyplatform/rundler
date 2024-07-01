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

use std::{cmp, fmt::Debug, sync::Arc};

use anyhow::Context;
use ethers::types::U256;
use rundler_provider::{EntryPoint, L1GasProvider, Provider};
use rundler_types::{
    chain::{self, ChainSpec},
    GasFees, UserOperation,
};
use rundler_utils::math;
use tokio::try_join;

use super::oracle::{
    ConstantOracle, FeeOracle, ProviderOracle, UsageBasedFeeOracle, UsageBasedFeeOracleConfig,
};

/// Returns the required pre_verification_gas for the given user operation
///
/// `full_op` is either the user operation submitted via `sendUserOperation`
/// or the user operation that was submitted via `estimateUserOperationGas` and filled
/// in via its `max_fill()` call. It is used to calculate the static portion of the pre_verification_gas
///
/// `random_op` is either the user operation submitted via `sendUserOperation`
/// or the user operation that was submitted via `estimateUserOperationGas` and filled
/// in via its `random_fill()` call. It is used to calculate the dynamic portion of the pre_verification_gas
/// on networks that require it.
///
/// Networks that require dynamic pre_verification_gas are typically those that charge extra calldata fees
/// that can scale based on dynamic gas prices.
pub async fn estimate_pre_verification_gas<
    UO: UserOperation,
    E: EntryPoint + L1GasProvider<UO = UO>,
>(
    chain_spec: &ChainSpec,
    entry_point: &E,
    full_op: &UO,
    random_op: &UO,
    gas_price: U256,
) -> anyhow::Result<U256> {
    let static_gas = full_op.calc_static_pre_verification_gas(chain_spec, true);
    if !chain_spec.calldata_pre_verification_gas {
        return Ok(static_gas);
    }

    let dynamic_gas = entry_point
        .calc_l1_gas(entry_point.address(), random_op.clone(), gas_price)
        .await?;

    Ok(static_gas.saturating_add(dynamic_gas))
}

/// Calculate the required pre_verification_gas for the given user operation and the provided base fee.
///
/// The effective gas price is calculated as min(base_fee + max_priority_fee_per_gas, max_fee_per_gas)
pub async fn calc_required_pre_verification_gas<
    UO: UserOperation,
    E: EntryPoint + L1GasProvider<UO = UO>,
>(
    chain_spec: &ChainSpec,
    entry_point: &E,
    op: &UO,
    base_fee: U256,
) -> anyhow::Result<U256> {
    let static_gas = op.calc_static_pre_verification_gas(chain_spec, true);
    if !chain_spec.calldata_pre_verification_gas {
        return Ok(static_gas);
    }

    let gas_price = cmp::min(
        base_fee + op.max_priority_fee_per_gas(),
        op.max_fee_per_gas(),
    );

    let dynamic_gas = entry_point
        .calc_l1_gas(entry_point.address(), op.clone(), gas_price)
        .await?;

    Ok(static_gas + dynamic_gas)
}

/// Gas limit functions
///
/// Gas limit: Total as limit for the bundle transaction
///     - This value is required to be high enough so that the bundle transaction does not
///         run out of gas.
/// Execution gas limit: Gas spent during the execution part of the bundle transaction
///     - This value is typically limited by block builders/sequencers and is the value by which
///         we will limit the amount of gas used in a bundle.
///
/// For example, on Arbitrum chains the L1 gas portion is added at the beginning of transaction execution
/// and uses up the gas limit of the transaction. However, this L1 portion is not part of the maximum gas
/// allowed by the sequencer per block.
///
/// If calculating the gas limit value to put on a bundle transaction, use the gas limit functions.
/// If limiting the size of a bundle transaction to adhere to block gas limit, use the execution gas limit functions.

/// Returns the gas limit for the user operation that applies to bundle transaction's limit
///
/// On an L2 this is the total gas limit for the bundle transaction ~including~ any potential L1 costs
/// if the chain requires it.
///
/// This is needed to set the gas limit for the bundle transaction.
pub fn user_operation_gas_limit<UO: UserOperation>(
    chain_spec: &ChainSpec,
    uo: &UO,
    assume_single_op_bundle: bool,
) -> U256 {
    user_operation_pre_verification_gas_limit(chain_spec, uo, assume_single_op_bundle)
        + uo.total_verification_gas_limit()
        + uo.required_pre_execution_buffer()
        + uo.call_gas_limit()
}

/// Returns the gas limit for the user operation that applies to bundle transaction's execution limit
///
/// On an L2 this is the total gas limit for the bundle transaction ~excluding~ any potential L1 costs.
///
/// This is needed to limit the size of the bundle transaction to adhere to the block gas limit.
pub fn user_operation_execution_gas_limit<UO: UserOperation>(
    chain_spec: &ChainSpec,
    uo: &UO,
    assume_single_op_bundle: bool,
) -> U256 {
    user_operation_pre_verification_execution_gas_limit(chain_spec, uo, assume_single_op_bundle)
        + uo.total_verification_gas_limit()
        + uo.required_pre_execution_buffer()
        + uo.call_gas_limit()
}

/// Returns the static pre-verification gas cost of a user operation
///
/// On an L2 this is the total gas limit for the bundle transaction ~excluding~ any potential L1 costs
pub fn user_operation_pre_verification_execution_gas_limit<UO: UserOperation>(
    chain_spec: &ChainSpec,
    uo: &UO,
    include_fixed_gas_overhead: bool,
) -> U256 {
    // On some chains (OP bedrock, Arbitrum) the L1 gas fee is charged via pre_verification_gas
    // but this not part of the EXECUTION gas limit of the transaction.
    // In such cases we only consider the static portion of the pre_verification_gas in the gas limit.
    if chain_spec.calldata_pre_verification_gas {
        uo.calc_static_pre_verification_gas(chain_spec, include_fixed_gas_overhead)
    } else {
        uo.pre_verification_gas()
    }
}

/// Returns the gas limit for the user operation that applies to bundle transaction's limit
///
/// On an L2 this is the total gas limit for the bundle transaction ~including~ any potential L1 costs
pub fn user_operation_pre_verification_gas_limit<UO: UserOperation>(
    chain_spec: &ChainSpec,
    uo: &UO,
    include_fixed_gas_overhead: bool,
) -> U256 {
    // On some chains (OP bedrock) the L1 gas fee is charged via pre_verification_gas
    // but this not part of the execution TOTAL limit of the transaction.
    // In such cases we only consider the static portion of the pre_verification_gas in the gas limit.
    if chain_spec.calldata_pre_verification_gas && !chain_spec.include_l1_gas_in_gas_limit {
        uo.calc_static_pre_verification_gas(chain_spec, include_fixed_gas_overhead)
    } else {
        uo.pre_verification_gas()
    }
}

/// Different modes for calculating the required priority fee
/// for the bundler to include a user operation in a bundle.
#[derive(Debug, Clone, Copy)]
pub enum PriorityFeeMode {
    /// The priority fee is required to be a percentage of the bundle base fee.
    BaseFeePercent(u64),
    /// The priority fee is required to be a percentage above the bundle priority fee.
    PriorityFeeIncreasePercent(u64),
}

impl PriorityFeeMode {
    /// Try to create a priority fee mode from a string and value.
    pub fn try_from(kind: &str, value: u64) -> anyhow::Result<Self> {
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
        base_fee: U256,
        base_fee_accept_percent: u64,
        min_max_priority_fee_per_gas: U256,
    ) -> U256 {
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

/// Gas fee estimator for a 4337 user operation.
#[derive(Debug, Clone)]
pub struct FeeEstimator<P> {
    provider: Arc<P>,
    priority_fee_mode: PriorityFeeMode,
    bundle_priority_fee_overhead_percent: u64,
    fee_oracle: Arc<dyn FeeOracle>,
}

impl<P: Provider> FeeEstimator<P> {
    /// Create a new fee estimator.
    ///
    /// `priority_fee_mode` is used to determine how the required priority fee is calculated.
    ///
    /// `bundle_priority_fee_overhead_percent` is used to determine the overhead percentage to add
    /// to the network returned priority fee to ensure the bundle priority fee is high enough.
    pub fn new(
        chain_spec: &ChainSpec,
        provider: Arc<P>,
        priority_fee_mode: PriorityFeeMode,
        bundle_priority_fee_overhead_percent: u64,
    ) -> Self {
        Self {
            provider: provider.clone(),
            priority_fee_mode,
            bundle_priority_fee_overhead_percent,
            fee_oracle: get_fee_oracle(chain_spec, provider),
        }
    }

    /// Returns the required fees for the given bundle fees.
    ///
    /// `min_fees` is used to set the minimum fees to use for the bundle. Typically used if a
    /// bundle has already been submitted and its fees must at least be a certain amount above the
    /// already submitted fees.
    ///
    /// Returns the required fees and the current base fee.
    pub async fn required_bundle_fees(
        &self,
        min_fees: Option<GasFees>,
    ) -> anyhow::Result<(GasFees, U256)> {
        let (base_fee, priority_fee) = try_join!(self.get_base_fee(), self.get_priority_fee())?;

        let required_fees = min_fees.unwrap_or_default();

        let max_priority_fee_per_gas =
            required_fees
                .max_priority_fee_per_gas
                .max(math::increase_by_percent(
                    priority_fee,
                    self.bundle_priority_fee_overhead_percent,
                ));

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

    /// Returns the required operation fees for the given bundle fees.
    pub fn required_op_fees(&self, bundle_fees: GasFees) -> GasFees {
        self.priority_fee_mode.required_fees(bundle_fees)
    }

    async fn get_base_fee(&self) -> anyhow::Result<U256> {
        Ok(self.provider.get_base_fee().await?)
    }

    async fn get_priority_fee(&self) -> anyhow::Result<U256> {
        self.fee_oracle
            .estimate_priority_fee()
            .await
            .context("should get priority fee")
    }
}

fn get_fee_oracle<P>(chain_spec: &ChainSpec, provider: Arc<P>) -> Arc<dyn FeeOracle>
where
    P: Provider + Debug,
{
    if !chain_spec.eip1559_enabled {
        return Arc::new(ConstantOracle::new(U256::zero()));
    }

    match chain_spec.priority_fee_oracle_type {
        chain::PriorityFeeOracleType::Provider => Arc::new(ProviderOracle::new(
            provider,
            chain_spec.min_max_priority_fee_per_gas,
        )),
        chain::PriorityFeeOracleType::UsageBased => {
            let config = UsageBasedFeeOracleConfig {
                minimum_fee: chain_spec.min_max_priority_fee_per_gas,
                maximum_fee: chain_spec.max_max_priority_fee_per_gas,
                congestion_trigger_usage_ratio_threshold: chain_spec
                    .congestion_trigger_usage_ratio_threshold,
                ..Default::default()
            };
            Arc::new(UsageBasedFeeOracle::new(provider, config))
        }
    }
}
