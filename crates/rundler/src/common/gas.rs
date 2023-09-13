use std::sync::Arc;

use anyhow::Context;
use ethers::{
    prelude::gas_oracle::{GasCategory, GasOracle, Polygon},
    types::{Address, Chain, U256},
};
use rundler_provider::Provider;
use rundler_types::{GasFees, UserOperation};
use rundler_utils::math;
use tokio::try_join;

use super::types::{ARBITRUM_CHAIN_IDS, OP_BEDROCK_CHAIN_IDS, POLYGON_CHAIN_IDS};

/// Gas overheads for user operations
/// used in calculating the pre-verification gas
/// see: https://github.com/eth-infinitism/bundler/blob/main/packages/sdk/src/calcPreVerificationGas.ts
#[derive(Clone, Copy, Debug)]
struct GasOverheads {
    pub fixed: U256,
    pub per_user_op: U256,
    pub per_user_op_word: U256,
    pub zero_byte: U256,
    pub non_zero_byte: U256,
    pub bundle_size: U256,
}

impl Default for GasOverheads {
    fn default() -> Self {
        Self {
            fixed: 21000.into(),
            per_user_op: 18300.into(),
            per_user_op_word: 4.into(),
            zero_byte: 4.into(),
            non_zero_byte: 16.into(),
            bundle_size: 1.into(),
        }
    }
}

pub async fn calc_pre_verification_gas<P: Provider>(
    full_op: &UserOperation,
    random_op: &UserOperation,
    entry_point: Address,
    provider: Arc<P>,
    chain_id: u64,
) -> anyhow::Result<U256> {
    let static_gas = calc_static_pre_verification_gas(full_op);
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

pub fn calc_static_pre_verification_gas(op: &UserOperation) -> U256 {
    let ov = GasOverheads::default();
    let packed = op.pack();
    let length_in_words = (packed.len() + 31) / 32;
    let call_data_cost: U256 = packed
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

    ov.fixed / ov.bundle_size
        + call_data_cost
        + ov.per_user_op
        + ov.per_user_op_word * length_in_words
}

/// Returns the gas limit for the user operation that should will be used onchain.
pub fn user_operation_gas_limit(uo: &UserOperation, chain_id: u64) -> U256 {
    // On some chains (OP bedrock) the L1 gas fee is charged via pre_verification_gas
    // but this not part of the execution gas of the transaction. Thus we only consider
    // the static portion of the pre_verification_gas in the onchain gas limit.
    //
    // On other chains (Arbitrum) the L1 gas fee is charged via pre_verification_gas
    // and this IS part of the execution gas of the transaction, and thus needs to be
    // accounted for in the bundle gas limit
    let pvg = if OP_BEDROCK_CHAIN_IDS.contains(&chain_id) {
        calc_static_pre_verification_gas(uo)
    } else {
        uo.pre_verification_gas
    };

    pvg + uo.call_gas_limit + uo.verification_gas_limit * verification_gas_limit_multiplier(uo)
}

/// Returns the execution gas limit for the user operation that applies to a blocks' gas cap
pub fn user_operation_execution_gas_limit(uo: &UserOperation, chain_id: u64) -> U256 {
    // On some chains (OP bedrock) the L1 gas fee is charged via pre_verification_gas
    // but this not part of the execution gas of the transaction.
    //
    // On other chains (Arbitrum) the L1 gas fee is charged via pre_verification_gas and this
    // IS part of the execution gas of the transaction but does NOT apply to the blocks exectution gas cap
    // thus it is not included in the execution gas limit.
    //
    // In both cases we only consider the static portion of the pre_verification_gas in the execution gas limit.
    let pvg = if OP_BEDROCK_CHAIN_IDS.contains(&chain_id) | ARBITRUM_CHAIN_IDS.contains(&chain_id) {
        calc_static_pre_verification_gas(uo)
    } else {
        uo.pre_verification_gas
    };

    pvg + uo.call_gas_limit + uo.verification_gas_limit * verification_gas_limit_multiplier(uo)
}

pub fn user_operation_max_gas_cost(uo: &UserOperation, chain_id: u64) -> U256 {
    user_operation_gas_limit(uo, chain_id) * uo.max_fee_per_gas
}

fn verification_gas_limit_multiplier(uo: &UserOperation) -> u64 {
    // If using a paymaster, we need to account for potentially 2 postOp
    // calls (even though it won't be called).
    // Else the entrypoint expects the gas for 1 postOp call that
    // uses vefification_gas_limit plus the actual verification call
    if uo.paymaster().is_some() {
        3
    } else {
        2
    }
}

#[derive(Debug, Clone, Copy)]
pub enum PriorityFeeMode {
    BaseFeePercent(u64),
    PriorityFeeIncreasePercent(u64),
}

impl PriorityFeeMode {
    pub fn try_from(kind: &str, value: u64) -> anyhow::Result<Self> {
        match kind {
            "base_fee_percent" => Ok(Self::BaseFeePercent(value)),
            "priority_fee_increase_percent" => Ok(Self::PriorityFeeIncreasePercent(value)),
            _ => anyhow::bail!("Invalid priority fee mode: {}", kind),
        }
    }

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

#[derive(Debug, Clone)]
pub struct FeeEstimator<P: Provider> {
    provider: Arc<P>,
    priority_fee_mode: PriorityFeeMode,
    use_bundle_priority_fee: bool,
    bundle_priority_fee_overhead_percent: u64,
    chain_id: u64,
}

impl<P: Provider> FeeEstimator<P> {
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

    pub fn required_op_fees(&self, bundle_fees: GasFees) -> GasFees {
        self.priority_fee_mode.required_fees(bundle_fees)
    }

    async fn get_base_fee(&self) -> anyhow::Result<U256> {
        self.provider.get_base_fee().await
    }

    async fn get_priority_fee(&self) -> anyhow::Result<U256> {
        if POLYGON_CHAIN_IDS.contains(&self.chain_id) {
            let gas_oracle =
                Polygon::new(Chain::try_from(self.chain_id)?)?.category(GasCategory::Fast);
            let fees = gas_oracle
                .estimate_eip1559_fees()
                .await
                .context("failed to query polygon gasstation")?;
            Ok(fees.1)
        } else if self.use_bundle_priority_fee {
            self.provider.get_max_priority_fee().await
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
