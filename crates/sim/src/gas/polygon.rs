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

use std::{cmp, sync::Arc};

use ethers::{
    prelude::gas_oracle::GasCategory,
    types::{BlockNumber, Chain, U256},
};
use futures_util::TryFutureExt;
use rundler_provider::Provider;
use serde::Deserialize;
use tokio::try_join;

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
    pub(crate) async fn estimate_priority_fee(&self) -> anyhow::Result<U256> {
        let (provider_estiamte, fee_history_estimate) = try_join!(
            self.provider.get_max_priority_fee().map_err(|e| e.into()),
            self.calculate_fees()
        )?;

        Ok(cmp::max(provider_estiamte, fee_history_estimate))
    }

    /// Perform a request to the gas price API and deserialize the response.
    async fn calculate_fees(&self) -> anyhow::Result<U256> {
        let gas_percentile = self.gas_category_percentile();
        let fee_history = self
            .provider
            .fee_history(15, BlockNumber::Latest, &[gas_percentile])
            .await?;
        Ok(calculate_estimate_from_rewards(
            &fee_history.reward,
            self.chain_id,
        ))
    }
}

/// Calculates the estimate based on the index of inner vector
/// and skips the average if block is empty
fn calculate_estimate_from_rewards(reward: &[Vec<U256>], chain_id: u64) -> U256 {
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

    average
}
