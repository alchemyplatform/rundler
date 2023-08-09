use std::sync::Arc;

use ethers::types::U256;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use tonic::async_trait;

use crate::common::{gas::FeeEstimator, precheck, types::ProviderLike};

#[rpc(client, server, namespace = "rundler")]
pub trait RundlerApi {
    #[method(name = "maxPriorityFeePerGas")]
    async fn max_priority_fee_per_gas(&self) -> RpcResult<U256>;
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
    async fn max_priority_fee_per_gas(&self) -> RpcResult<U256> {
        let bundle_fees = self.fee_estimator.required_bundle_fees(None).await?;
        Ok(self
            .fee_estimator
            .required_op_fees(bundle_fees)
            .max_priority_fee_per_gas)
    }
}
