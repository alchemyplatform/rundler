use std::sync::Arc;

use ethers::types::{Address, U256};

use super::types::ProviderLike;
use crate::common::types::UserOperation;

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

pub async fn calc_pre_verification_gas<P: ProviderLike>(
    full_op: UserOperation,
    random_op: UserOperation,
    entry_point: Address,
    provider: Arc<P>,
    chain_id: u64,
) -> anyhow::Result<U256> {
    let static_gas = calc_static_pre_verification_gas(&full_op);
    let dynamic_gas = match chain_id {
        42161 | 421613 => {
            provider
                .clone()
                .calc_arbitrum_l1_gas(entry_point, random_op)
                .await?
        }
        _ => U256::zero(),
    };

    Ok(static_gas + dynamic_gas)
}

fn calc_static_pre_verification_gas(op: &UserOperation) -> U256 {
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
