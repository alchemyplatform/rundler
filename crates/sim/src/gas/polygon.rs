use std::sync::Arc;

use ethers::{
    prelude::gas_oracle::{GasCategory, Result},
    providers::ProviderError,
    types::{BlockNumber, Chain, U256},
};
use rundler_provider::Provider;
use serde::Deserialize;

const MUMBAI_MAX_PRIORITY_FEE_DEFAULT: u64 = 1_500_000_000;
const MAINNET_MAX_PRIORITY_FEE_DEFAULT: u64 = 30_000_000_000;

#[derive(Debug)]
pub(crate) struct Polygon<P> {
    provider: Arc<P>,
    gas_category: GasCategory,
    chain_id: u64,
}

#[derive(Clone, Copy, Deserialize, PartialEq)]
pub(crate) struct GasEstimate {
    pub(crate) max_priority_fee: U256,
    pub(crate) max_fee: U256,
}

impl<P> Polygon<P>
where
    P: Provider,
{
    pub(crate) fn new(provider: Arc<P>, chain_id: u64) -> Self {
        Self {
            provider,
            gas_category: GasCategory::Standard,
            chain_id,
        }
    }

    /// Sets the gas price category to be used when fetching the gas price.
    pub(crate) fn category(mut self, gas_category: GasCategory) -> Self {
        self.gas_category = gas_category;
        self
    }
    /// Chooses percentile to use based on the set category for eth_feeHistory
    fn gas_category_percentile(&self) -> f64 {
        match self.gas_category {
            GasCategory::SafeLow => 10.0,
            GasCategory::Standard => 25.0,
            GasCategory::Fast | GasCategory::Fastest => 50.0,
        }
    }

    /// Estimates max and priority gas and converts to U256
    pub(crate) async fn estimate_eip1559_fees(&self) -> Result<(U256, U256), ProviderError> {
        let estimate = self.calculate_fees().await?;
        let max = estimate.max_fee;
        let prio = estimate.max_priority_fee;
        Ok((max, prio))
    }

    /// Perform a request to the gas price API and deserialize the response.
    pub(crate) async fn calculate_fees(&self) -> Result<GasEstimate, ProviderError> {
        let gas_percentile = self.gas_category_percentile();
        let fee_history = self
            .provider
            .fee_history(15, BlockNumber::Latest, &[gas_percentile])
            .await?;

        let (base_fee_per_gas, _mod) = fee_history
            .base_fee_per_gas
            .iter()
            .fold(U256::from(0), |acc, val| acc.saturating_add(*val))
            .div_mod(U256::from(fee_history.base_fee_per_gas.len()));

        let estimate =
            calculate_estimate_from_rewards(&fee_history.reward, base_fee_per_gas, self.chain_id);

        Ok(estimate)
    }
}

/// Calculates the estimate based on the index of inner vector
/// and skips the average if block is empty
fn calculate_estimate_from_rewards(
    reward: &[Vec<U256>],
    base_fee_per_gas: U256,
    chain_id: u64,
) -> GasEstimate {
    let (sum, count): (U256, U256) = reward
        .iter()
        .filter(|b| !b[0].is_zero())
        .map(|b| b[0])
        .fold((0.into(), 0.into()), |(sum, count), val| {
            (sum.saturating_add(val), count.saturating_add(1.into()))
        });

    let mut average = sum;

    if !count.is_zero() {
        let (avg, _mod) = average.div_mod(count);
        average = avg;
    } else {
        let fallback = match chain_id {
            x if x == Chain::Polygon as u64 => MAINNET_MAX_PRIORITY_FEE_DEFAULT.into(),
            x if x == Chain::PolygonMumbai as u64 => MUMBAI_MAX_PRIORITY_FEE_DEFAULT.into(),
            _ => U256::zero(),
        };
        average = fallback;
    }

    GasEstimate {
        max_priority_fee: average,
        max_fee: base_fee_per_gas + average,
    }
}
