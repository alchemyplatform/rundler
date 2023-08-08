use std::sync::Arc;

use ethers::types::{U256, U64};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use serde::{Deserialize, Serialize};
use tonic::async_trait;

use crate::common::{
    gas::{FeeEstimator, GasFees},
    precheck,
    types::ProviderLike,
};

#[rpc(client, server, namespace = "rundler")]
pub trait RundlerApi {
    #[method(name = "getLocalRequiredFees")]
    async fn get_local_required_fees(&self) -> RpcResult<RequiredFees>;
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequiredFees {
    block_number: U64,
    base_fee_per_gas: U256,
    minimum: GasFees,
    recommended: GasFees,
}

pub struct RundlerApi<P: ProviderLike> {
    fee_estimator: FeeEstimator<P>,
}

impl<P> RundlerApi<P>
where
    P: ProviderLike,
{
    pub fn new(provider: Arc<P>, chain_id: u64, settings: precheck::Settings) -> Self {
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
    P: ProviderLike,
{
    async fn get_local_required_fees(&self) -> RpcResult<RequiredFees> {
        let (block_number, base_fee_per_gas, bundle_fees) =
            self.fee_estimator.required_bundle_fees(None).await?;
        let minimum = self.fee_estimator.required_op_fees(bundle_fees);

        let recommended_base = base_fee_per_gas * 5 / 4;
        let recommended_prio = minimum.max_priority_fee_per_gas * 5 / 4;
        let recommended_max = recommended_base + recommended_prio;

        let recommended = GasFees {
            max_fee_per_gas: recommended_max,
            max_priority_fee_per_gas: recommended_prio,
        };

        Ok(RequiredFees {
            block_number,
            base_fee_per_gas,
            minimum,
            recommended,
        })
    }
}
