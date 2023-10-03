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

use std::sync::Arc;

use ethers::{
    abi::AbiEncode,
    prelude::gas_oracle::GasCategory,
    types::{Address, Chain, U256},
};
use rundler_provider::Provider;
use rundler_types::{
    chain::{ARBITRUM_CHAIN_IDS, OP_BEDROCK_CHAIN_IDS, POLYGON_CHAIN_IDS},
    GasFees, UserOperation,
};
use rundler_utils::math;
use tokio::try_join;

use super::polygon::Polygon;

// Gas overheads for user operations
// used in calculating the pre-verification gas
// see: https://github.com/eth-infinitism/bundler/blob/main/packages/sdk/src/calcPreVerificationGas.ts
#[derive(Clone, Copy, Debug)]
struct GasOverheads {
    bundle_transaction_gas_buffer: U256,
    transaction_gas_overhead: U256,
    per_user_op: U256,
    per_user_op_word: U256,
    zero_byte: U256,
    non_zero_byte: U256,
}

impl Default for GasOverheads {
    fn default() -> Self {
        Self {
            bundle_transaction_gas_buffer: 5_000.into(), // Entrypoint requires a buffer over the user operation gas limits in the bundle transaction
            transaction_gas_overhead: 21_000.into(), // The fixed gas overhead for any EVM transaction
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
pub async fn calc_pre_verification_gas<P: Provider>(
    full_op: &UserOperation,
    random_op: &UserOperation,
    entry_point: Address,
    provider: Arc<P>,
    chain_id: u64,
) -> anyhow::Result<U256> {
    let static_gas = calc_static_pre_verification_gas(full_op, GasOverheads::default(), true);
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
                .calc_optimism_l1_gas(entry_point, random_op.clone())
                .await?
        }
        _ => U256::zero(),
    };

    Ok(static_gas + dynamic_gas)
}

/// Compute the gas limit for the bundle composed of the given user operations
pub fn bundle_gas_limit<'a, I>(iter_ops: I, chain_id: u64) -> U256
where
    I: Iterator<Item = &'a UserOperation>,
{
    let ov = GasOverheads::default();
    iter_ops
        .map(|op| user_operation_gas_limit(op, chain_id, false))
        .fold(
            ov.bundle_transaction_gas_buffer + ov.transaction_gas_overhead,
            |acc, c| acc + c,
        )
}

/// Returns the gas limit for the user operation that applies to bundle transaction's limit
pub fn user_operation_gas_limit(
    uo: &UserOperation,
    chain_id: u64,
    include_fixed_gas_overhead: bool,
) -> U256 {
    // On some chains (OP bedrock, Arbitrum) the L1 gas fee is charged via pre_verification_gas
    // but this not part of the execution gas limit of the transaction.
    // In such cases we only consider the static portion of the pre_verification_gas in the gas limit.
    let pvg = if OP_BEDROCK_CHAIN_IDS.contains(&chain_id) | ARBITRUM_CHAIN_IDS.contains(&chain_id) {
        calc_static_pre_verification_gas(uo, GasOverheads::default(), include_fixed_gas_overhead)
    } else {
        uo.pre_verification_gas
    };

    pvg + uo.call_gas_limit + uo.verification_gas_limit * verification_gas_limit_multiplier(uo)
}

/// Returns the maximum cost, in wei, of this user operation
pub fn user_operation_max_gas_cost(uo: &UserOperation) -> U256 {
    let mul = if uo.paymaster().is_some() { 3 } else { 1 };
    uo.max_fee_per_gas
        * (uo.pre_verification_gas + uo.call_gas_limit + uo.verification_gas_limit * mul)
}

fn calc_static_pre_verification_gas(
    op: &UserOperation,
    ov: GasOverheads,
    include_fixed_gas_overhead: bool,
) -> U256 {
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

fn verification_gas_limit_multiplier(uo: &UserOperation) -> u64 {
    // If using a paymaster, we need to account for potentially 2 postOp
    // calls (even though it won't be called).
    // Else the entrypoint expects the gas for 1 postOp call that
    // uses verification_gas_limit plus the actual verification call
    if uo.paymaster().is_some() {
        3
    } else {
        2
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
}

/// Gas fee estimator for a 4337 user operation.
#[derive(Debug, Clone)]
pub struct FeeEstimator<P: Provider> {
    provider: Arc<P>,
    priority_fee_mode: PriorityFeeMode,
    use_bundle_priority_fee: bool,
    bundle_priority_fee_overhead_percent: u64,
    chain_id: u64,
}

impl<P: Provider> FeeEstimator<P> {
    /// Create a new fee estimator.
    ///
    /// `priority_fee_mode` is used to determine how the required priority fee is calculated.
    ///
    /// `use_bundle_priority_fee` is used to determine if the bundle priority fee should be used.
    /// Set to true on EIP-1559 chains, false on non-EIP-1559 chains.
    ///
    /// `bundle_priority_fee_overhead_percent` is used to determine the overhead percentage to add
    /// to the network returned priority fee to ensure the bundle priority fee is high enough.
    pub fn new(
        provider: Arc<P>,
        chain_id: u64,
        priority_fee_mode: PriorityFeeMode,
        use_bundle_priority_fee: Option<bool>,
        bundle_priority_fee_overhead_percent: u64,
    ) -> Self {
        Self {
            provider,
            priority_fee_mode,
            use_bundle_priority_fee: use_bundle_priority_fee
                .unwrap_or_else(|| !is_known_non_eip_1559_chain(chain_id)),
            bundle_priority_fee_overhead_percent,
            chain_id,
        }
    }

    /// Returns the required fees for the given bundle fees.
    ///
    /// `min_fees` is used to set the minimum fees to use for the bundle. Typically used if a
    /// bundle has already been submitted and its fees must at least be a certain amount above the
    /// already submitted fees.
    pub async fn required_bundle_fees(&self, min_fees: Option<GasFees>) -> anyhow::Result<GasFees> {
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
        Ok(GasFees {
            max_fee_per_gas,
            max_priority_fee_per_gas,
        })
    }

    /// Returns the required operation fees for the given bundle fees.
    pub fn required_op_fees(&self, bundle_fees: GasFees) -> GasFees {
        self.priority_fee_mode.required_fees(bundle_fees)
    }

    async fn get_base_fee(&self) -> anyhow::Result<U256> {
        Ok(self.provider.get_base_fee().await?)
    }

    async fn get_priority_fee(&self) -> anyhow::Result<U256> {
        if POLYGON_CHAIN_IDS.contains(&self.chain_id) {
            let gas_oracle =
                Polygon::new(Arc::clone(&self.provider), self.chain_id).category(GasCategory::Fast);
            Ok(gas_oracle.estimate_priority_fee().await?)
        } else if self.use_bundle_priority_fee {
            Ok(self.provider.get_max_priority_fee().await?)
        } else {
            Ok(U256::zero())
        }
    }
}

const NON_EIP_1559_CHAIN_IDS: &[u64] = &[
    Chain::Arbitrum as u64,
    Chain::ArbitrumNova as u64,
    Chain::ArbitrumGoerli as u64,
];

fn is_known_non_eip_1559_chain(chain_id: u64) -> bool {
    NON_EIP_1559_CHAIN_IDS.contains(&chain_id)
}
