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

use alloy_primitives::B256;
use alloy_rpc_types_eth::BlockNumberOrTag;
use anyhow::Context;
use rundler_types::{GasFees, PriorityFeeMode, chain::ChainSpec};
use rundler_utils::{cache::LruMap, math};
use tokio::{sync::Mutex as TokioMutex, try_join};
use tracing::instrument;

use crate::{EvmProvider, FeeEstimator, LatestFeeEstimate};

mod oracle;
use oracle::*;

/// Create a new fee estimator.
pub fn new_fee_estimator<P: EvmProvider + Clone + 'static>(
    chain_spec: &ChainSpec,
    provider: P,
    priority_fee_mode: PriorityFeeMode,
    bundle_base_fee_overhead_percent: u32,
    bundle_priority_fee_overhead_percent: u32,
) -> impl FeeEstimator + 'static {
    let fee_oracle = get_fee_oracle(chain_spec, provider.clone());
    FeeEstimatorImpl::new(
        provider,
        fee_oracle,
        priority_fee_mode,
        bundle_base_fee_overhead_percent,
        bundle_priority_fee_overhead_percent,
    )
}

// Gas fee estimator for a 4337 user operation.
struct FeeEstimatorImpl<P, O> {
    provider: P,
    priority_fee_mode: PriorityFeeMode,
    bundle_base_fee_overhead_percent: u32,
    bundle_priority_fee_overhead_percent: u32,
    fee_oracle: O,

    cache: TokioMutex<LruMap<B256, CacheEntry>>,
}

#[derive(Clone, Copy)]
struct CacheEntry {
    base_fee: u128,
    priority_fee: u128,
}

impl<P: EvmProvider, O: FeeOracle> FeeEstimatorImpl<P, O> {
    /// Create a new fee estimator.
    ///
    /// `priority_fee_mode` is used to determine how the required priority fee is calculated.
    ///
    /// `bundle_priority_fee_overhead_percent` is used to determine the overhead percentage to add
    /// to the network returned priority fee to ensure the bundle priority fee is high enough.
    fn new(
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
            cache: TokioMutex::new(LruMap::new(128)),
        }
    }

    #[instrument(skip_all)]
    async fn get_pending_base_fee_and_block_number(&self) -> anyhow::Result<(u128, u64)> {
        let fee_history = self
            .provider
            .fee_history(1, BlockNumberOrTag::Latest, &[])
            .await?;
        let base_fee = fee_history
            .next_block_base_fee()
            .context("should have a next block base fee")?;
        Ok((base_fee, fee_history.oldest_block))
    }

    #[instrument(skip_all)]
    async fn get_priority_fee(&self) -> anyhow::Result<u128> {
        self.fee_oracle
            .estimate_priority_fee()
            .await
            .context("should get priority fee")
    }
}

#[async_trait::async_trait]
impl<P: EvmProvider, O: FeeOracle> FeeEstimator for FeeEstimatorImpl<P, O> {
    #[instrument(skip_all)]
    async fn latest_bundle_fees(&self) -> anyhow::Result<(GasFees, u128)> {
        let estimate = self.latest_fee_estimate().await?;
        let bundle_fees = GasFees {
            max_fee_per_gas: estimate
                .required_base_fee
                .saturating_add(estimate.required_priority_fee),
            max_priority_fee_per_gas: estimate.required_priority_fee,
        };

        Ok((bundle_fees, estimate.required_base_fee))
    }

    #[instrument(skip_all)]
    async fn latest_fee_estimate(&self) -> anyhow::Result<LatestFeeEstimate> {
        let ((base_fee, block_number), priority_fee) = try_join!(
            self.get_pending_base_fee_and_block_number(),
            self.get_priority_fee()
        )?;

        let required_base_fee =
            math::increase_by_percent(base_fee, self.bundle_base_fee_overhead_percent);
        let required_priority_fee =
            math::increase_by_percent(priority_fee, self.bundle_priority_fee_overhead_percent);

        Ok(LatestFeeEstimate {
            block_number,
            base_fee,
            required_base_fee,
            required_priority_fee,
        })
    }

    #[instrument(skip_all)]
    async fn required_bundle_fees(
        &self,
        block_hash: B256,
        min_fees: Option<GasFees>,
    ) -> anyhow::Result<(GasFees, u128)> {
        let mut cache = self.cache.lock().await;
        let entry = match cache.get(&block_hash) {
            Some(entry) => *entry,
            None => {
                let ((base_fee, _), priority_fee) = try_join!(
                    self.get_pending_base_fee_and_block_number(),
                    self.get_priority_fee()
                )?;

                let entry = CacheEntry {
                    base_fee,
                    priority_fee,
                };
                cache.insert(block_hash, entry);
                entry
            }
        };

        Ok(self.calc_bundle_fees(entry.base_fee, entry.priority_fee, min_fees))
    }

    fn required_op_fees(&self, bundle_fees: GasFees) -> GasFees {
        self.priority_fee_mode.required_fees(bundle_fees)
    }
}

impl<P: EvmProvider, O: FeeOracle> FeeEstimatorImpl<P, O> {
    fn calc_bundle_fees(
        &self,
        base_fee: u128,
        priority_fee: u128,
        min_fees: Option<GasFees>,
    ) -> (GasFees, u128) {
        let base_fee = math::increase_by_percent(base_fee, self.bundle_base_fee_overhead_percent);
        let priority_fee =
            math::increase_by_percent(priority_fee, self.bundle_priority_fee_overhead_percent);

        let required_fees = min_fees.unwrap_or_default();

        let max_priority_fee_per_gas = required_fees.max_priority_fee_per_gas.max(priority_fee);

        let max_fee_per_gas = required_fees
            .max_fee_per_gas
            .max(base_fee + max_priority_fee_per_gas);
        (
            GasFees {
                max_fee_per_gas,
                max_priority_fee_per_gas,
            },
            base_fee,
        )
    }
}
