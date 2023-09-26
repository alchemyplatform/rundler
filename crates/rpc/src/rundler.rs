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

use async_trait::async_trait;
use ethers::types::U256;
use jsonrpsee::{core::RpcResult, proc_macros::rpc, types::error::INTERNAL_ERROR_CODE};
use rundler_provider::Provider;
use rundler_sim::{FeeEstimator, PrecheckSettings};

use crate::error::rpc_err;

#[rpc(client, server, namespace = "rundler")]
pub trait RundlerApi {
    /// Returns the maximum priority fee per gas required by Rundler
    #[method(name = "maxPriorityFeePerGas")]
    async fn max_priority_fee_per_gas(&self) -> RpcResult<U256>;
}

pub(crate) struct RundlerApi<P: Provider> {
    fee_estimator: FeeEstimator<P>,
}

impl<P> RundlerApi<P>
where
    P: Provider,
{
    pub(crate) fn new(provider: Arc<P>, chain_id: u64, settings: PrecheckSettings) -> Self {
        Self {
            fee_estimator: FeeEstimator::new(
                provider,
                chain_id,
                settings.priority_fee_mode,
                settings.use_bundle_priority_fee,
                settings.bundle_priority_fee_overhead_percent,
            ),
        }
    }
}

#[async_trait]
impl<P> RundlerApiServer for RundlerApi<P>
where
    P: Provider,
{
    async fn max_priority_fee_per_gas(&self) -> RpcResult<U256> {
        let bundle_fees = self
            .fee_estimator
            .required_bundle_fees(None)
            .await
            .map_err(|e| rpc_err(INTERNAL_ERROR_CODE, e.to_string()))?;
        Ok(self
            .fee_estimator
            .required_op_fees(bundle_fees)
            .max_priority_fee_per_gas)
    }
}
