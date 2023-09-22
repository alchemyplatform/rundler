use std::sync::Arc;

use ethers::{
    prelude::gas_oracle::GasCategory,
    types::{BlockNumber, Chain, U256},
};
use futures_util::TryFutureExt;
use serde::Deserialize;

use crate::common::types::ProviderLike;

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
    P: ProviderLike,
{
    pub(crate) fn new(provider: Arc<P>, chain_id: u64) -> Self {
        Self {
            provider,
            gas_category: GasCategory::Standard,
            chain_id,
        }
    }

    /// Sets the gas price category to be used when fetching the gas price.
    pub fn category(mut self, gas_category: GasCategory) -> Self {
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
    pub(crate) async fn estimate_eip1559_fees(&self) -> anyhow::Result<(U256, U256)> {
        let estimate = self.calculate_fees().await?;
        Ok((estimate.max_fee, estimate.max_priority_fee))
    }

    /// Perform a request to the gas price API and deserialize the response.
    pub(crate) async fn calculate_fees(&self) -> anyhow::Result<GasEstimate> {
        let gas_percentile = Vec::from([self.gas_category_percentile()]);
        let base_fee_fut = self.provider.get_base_fee();
        let fee_history_fut = self
            .provider
            .fee_history(15, BlockNumber::Latest, &gas_percentile);
        let (base_fee_per_gas, fee_history) = tokio::try_join!(
            base_fee_fut,
            fee_history_fut.map_err(|e| anyhow::anyhow!("Failed to get fee history {e:?}"))
        )?;

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
