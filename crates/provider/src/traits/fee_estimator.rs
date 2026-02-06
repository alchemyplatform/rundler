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
use rundler_types::GasFees;

/// Latest fee estimates for bundling.
#[derive(Debug, Clone, Copy)]
pub struct LatestFeeEstimate {
    /// Block number this estimate is based on.
    pub block_number: u64,
    /// Current pending base fee (without bundler overhead).
    pub base_fee: u128,
    /// Base fee with bundler overhead applied.
    pub required_base_fee: u128,
    /// Priority fee with bundler overhead applied.
    pub required_priority_fee: u128,
}

/// Trait for a fee estimator.
#[async_trait::async_trait]
#[auto_impl::auto_impl(&, &mut, Rc, Arc, Box)]
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
        block_hash: B256,
        min_fees: Option<GasFees>,
    ) -> anyhow::Result<(GasFees, u128)>;

    /// Returns the latest bundle fees.
    async fn latest_bundle_fees(&self) -> anyhow::Result<(GasFees, u128)>;

    /// Returns the latest fee estimate including base fee, priority fee (with bundler overhead), and block number.
    async fn latest_fee_estimate(&self) -> anyhow::Result<LatestFeeEstimate>;

    /// Returns the required operation fees for the given bundle fees.
    fn required_op_fees(&self, bundle_fees: GasFees) -> GasFees;
}
