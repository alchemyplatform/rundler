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
use ethers::{
    abi::AbiEncode,
    types::{Address, U256},
};

use alloy_chains::NamedChain;
use rundler_provider::Provider;
use rundler_types::{
    chain::{
        ARBITRUM_CHAIN_IDS, OP_BEDROCK_CHAIN_IDS, POLYGON_CHAIN_IDS, POLYGON_TESTNET_CHAIN_IDS,
    },
    GasFees, UserOperation,
};
use rundler_utils::math;
use tokio::try_join;

use super::oracle::{
    ConstantOracle, FeeOracle, ProviderOracle, UsageBasedFeeOracle, UsageBasedFeeOracleConfig,
};

/// Gas overheads for user operations used in calculating the pre-verification gas. See: https://github.com/eth-infinitism/bundler/blob/main/packages/sdk/src/calcPreVerificationGas.ts
#[derive(Clone, Copy, Debug)]
pub struct GasOverheads {
    /// The Entrypoint requires a gas buffer for the bundle to account for the gas spent outside of the major steps in the processing of UOs
    pub bundle_transaction_gas_buffer: U256,
    /// The fixed gas overhead for any EVM transaction
    pub transaction_gas_overhead: U256,
    per_user_op: U256,
    per_user_op_word: U256,
    zero_byte: U256,
    non_zero_byte: U256,
}

impl Default for GasOverheads {
    fn default() -> Self {
        Self {
            bundle_transaction_gas_buffer: 5_000.into(),
            transaction_gas_overhead: 21_000.into(),
            per_user_op: 18_300.into(),
            per_user_op_word: 4.into(),
            zero_byte: 4.into(),
            non_zero_byte: 16.into(),
        }
    }
}

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
pub async fn estimate_pre_verification_gas<P: Provider>(
    full_op: &UserOperation,
    random_op: &UserOperation,
    entry_point: Address,
    provider: Arc<P>,
    chain_id: u64,
    gas_price: U256,
) -> anyhow::Result<U256> {
    let static_gas = calc_static_pre_verification_gas(full_op, true);
    let dynamic_gas = match chain_id {
        _ if ARBITRUM_CHAIN_IDS.contains(&chain_id) => {
            provider
                .clone()
                .calc_arbitrum_l1_gas(entry_point, random_op.clone())
                .await?
        }
        _ if OP_BEDROCK_CHAIN_IDS.contains(&chain_id) => {
            provider
                .clone()
                .calc_optimism_l1_gas(entry_point, random_op.clone(), gas_price)
                .await?
        }
        _ => U256::zero(),
    };

    Ok(static_gas + dynamic_gas)
}

/// Calculate the required pre_verification_gas for the given user operation and the provided base fee.
///
/// The effective gas price is calculated as min(base_fee + max_priority_fee_per_gas, max_fee_per_gas)
pub async fn calc_required_pre_verification_gas<P: Provider>(
    op: &UserOperation,
    entry_point: Address,
    provider: Arc<P>,
    chain_id: u64,
    base_fee: U256,
) -> anyhow::Result<U256> {
    let static_gas = calc_static_pre_verification_gas(op, true);
    let dynamic_gas = match chain_id {
        _ if ARBITRUM_CHAIN_IDS.contains(&chain_id) => {
            provider
                .clone()
                .calc_arbitrum_l1_gas(entry_point, op.clone())
                .await?
        }
        _ if OP_BEDROCK_CHAIN_IDS.contains(&chain_id) => {
            let gas_price = cmp::min(base_fee + op.max_priority_fee_per_gas, op.max_fee_per_gas);

            provider
                .clone()
                .calc_optimism_l1_gas(entry_point, op.clone(), gas_price)
                .await?
        }
        _ => U256::zero(),
    };

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
pub fn user_operation_gas_limit(
    uo: &UserOperation,
    chain_id: u64,
    assume_single_op_bundle: bool,
    paymaster_post_op: bool,
) -> U256 {
    user_operation_pre_verification_gas_limit(uo, chain_id, assume_single_op_bundle)
        + uo.call_gas_limit
        + uo.verification_gas_limit
            * verification_gas_limit_multiplier(assume_single_op_bundle, paymaster_post_op)
}

/// Returns the gas limit for the user operation that applies to bundle transaction's execution limit
pub fn user_operation_execution_gas_limit(
    uo: &UserOperation,
    chain_id: u64,
    assume_single_op_bundle: bool,
    paymaster_post_op: bool,
) -> U256 {
    user_operation_pre_verification_execution_gas_limit(uo, chain_id, assume_single_op_bundle)
        + uo.call_gas_limit
        + uo.verification_gas_limit
            * verification_gas_limit_multiplier(assume_single_op_bundle, paymaster_post_op)
}

/// Returns the static pre-verification gas cost of a user operation
pub fn user_operation_pre_verification_execution_gas_limit(
    uo: &UserOperation,
    chain_id: u64,
    include_fixed_gas_overhead: bool,
) -> U256 {
    // On some chains (OP bedrock, Arbitrum) the L1 gas fee is charged via pre_verification_gas
    // but this not part of the EXECUTION gas limit of the transaction.
    // In such cases we only consider the static portion of the pre_verification_gas in the gas limit.
    if OP_BEDROCK_CHAIN_IDS.contains(&chain_id) | ARBITRUM_CHAIN_IDS.contains(&chain_id) {
        calc_static_pre_verification_gas(uo, include_fixed_gas_overhead)
    } else {
        uo.pre_verification_gas
    }
}

/// Returns the gas limit for the user operation that applies to bundle transaction's limit
pub fn user_operation_pre_verification_gas_limit(
    uo: &UserOperation,
    chain_id: u64,
    include_fixed_gas_overhead: bool,
) -> U256 {
    // On some chains (OP bedrock) the L1 gas fee is charged via pre_verification_gas
    // but this not part of the execution TOTAL limit of the transaction.
    // In such cases we only consider the static portion of the pre_verification_gas in the gas limit.
    if OP_BEDROCK_CHAIN_IDS.contains(&chain_id) {
        calc_static_pre_verification_gas(uo, include_fixed_gas_overhead)
    } else {
        uo.pre_verification_gas
    }
}

fn calc_static_pre_verification_gas(op: &UserOperation, include_fixed_gas_overhead: bool) -> U256 {
    let ov = GasOverheads::default();
    let encoded_op = op.clone().encode();
    let length_in_words = encoded_op.len() / 32; // size of packed user op is always a multiple of 32 bytes
    let call_data_cost: U256 = encoded_op
        .iter()
        .map(|&x| {
            if x == 0 {
                ov.zero_byte
            } else {
                ov.non_zero_byte
            }
        })
        .reduce(|a, b| a + b)
        .unwrap_or_default();

    call_data_cost
        + ov.per_user_op
        + ov.per_user_op_word * length_in_words
        + (if include_fixed_gas_overhead {
            ov.transaction_gas_overhead
        } else {
            0.into()
        })
}

fn verification_gas_limit_multiplier(
    assume_single_op_bundle: bool,
    paymaster_post_op: bool,
) -> u64 {
    // If using a paymaster that has a postOp, we need to account for potentially 2 postOp calls which can each use up to verification_gas_limit gas.
    // otherwise the entrypoint expects the gas for 1 postOp call that uses verification_gas_limit plus the actual verification call
    // we only add the additional verification_gas_limit only if we know for sure that this is a single op bundle, which what we do to get a worst-case upper bound
    if paymaster_post_op {
        3
    } else if assume_single_op_bundle {
        2
    } else {
        1
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
    fee_oracle: Arc<Box<dyn FeeOracle>>,
}

impl<P: Provider> FeeEstimator<P> {
    /// Create a new fee estimator.
    ///
    /// `priority_fee_mode` is used to determine how the required priority fee is calculated.
    ///
    /// `bundle_priority_fee_overhead_percent` is used to determine the overhead percentage to add
    /// to the network returned priority fee to ensure the bundle priority fee is high enough.
    pub fn new(
        provider: Arc<P>,
        chain_id: u64,
        priority_fee_mode: PriorityFeeMode,
        bundle_priority_fee_overhead_percent: u64,
    ) -> Self {
        Self {
            provider: provider.clone(),
            priority_fee_mode,
            bundle_priority_fee_overhead_percent,
            fee_oracle: get_fee_oracle(chain_id, provider),
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

// TODO move all of this to ChainSpec
/// ETHEREUM_MAINNET_MAX_PRIORITY_FEE_MIN
pub const ETHEREUM_MAINNET_MAX_PRIORITY_FEE_MIN: u64 = 100_000_000;
/// Polygon Mumbai max priority fee min
pub const POLYGON_MUMBAI_MAX_PRIORITY_FEE_MIN: u64 = 1_500_000_000;
/// Polygon Mainnet max priority fee min
pub const POLYGON_MAINNET_MAX_PRIORITY_FEE_MIN: u64 = 30_000_000_000;
/// Optimism Bedrock chains max priority fee min
pub const OPTIMISM_BEDROCK_MAX_PRIORITY_FEE_MIN: u64 = 100_000;

/// Returns the minimum max priority fee per gas for the given chain id.
pub fn get_min_max_priority_fee_per_gas(chain_id: u64) -> U256 {
    match chain_id {
        x if x == NamedChain::Mainnet as u64 => ETHEREUM_MAINNET_MAX_PRIORITY_FEE_MIN.into(),
        x if x == NamedChain::Polygon as u64 => POLYGON_MAINNET_MAX_PRIORITY_FEE_MIN.into(),
        x if POLYGON_TESTNET_CHAIN_IDS.contains(&x) => POLYGON_MUMBAI_MAX_PRIORITY_FEE_MIN.into(),
        x if x == 80002 => POLYGON_MUMBAI_MAX_PRIORITY_FEE_MIN.into(),
        x if OP_BEDROCK_CHAIN_IDS.contains(&x) => OPTIMISM_BEDROCK_MAX_PRIORITY_FEE_MIN.into(),
        _ => U256::zero(),
    }
}

fn get_fee_oracle<P>(chain_id: u64, provider: Arc<P>) -> Arc<Box<dyn FeeOracle>>
where
    P: Provider + Debug,
{
    let minimum_fee = get_min_max_priority_fee_per_gas(chain_id);

    if ARBITRUM_CHAIN_IDS.contains(&chain_id) {
        Arc::new(Box::new(ConstantOracle::new(U256::zero())))
    } else if OP_BEDROCK_CHAIN_IDS.contains(&chain_id) || POLYGON_CHAIN_IDS.contains(&chain_id) {
        let config = UsageBasedFeeOracleConfig {
            minimum_fee,
            ..Default::default()
        };
        Arc::new(Box::new(UsageBasedFeeOracle::new(provider, config)))
    } else {
        Arc::new(Box::new(ProviderOracle::new(provider)))
    }
}
