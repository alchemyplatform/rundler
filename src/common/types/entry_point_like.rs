use std::ops::Deref;

use ethers::{
    abi::AbiDecode,
    contract::ContractError,
    providers::Middleware,
    types::{Address, U256},
};
#[cfg(test)]
use mockall::automock;
use tonic::async_trait;

use crate::common::contracts::{
    i_entry_point::{FailedOp, IEntryPoint, SignatureValidationFailed},
    shared_types::UserOpsPerAggregator,
};

#[cfg_attr(test, automock)]
#[async_trait]
pub trait EntryPointLike: Send + Sync {
    fn address(&self) -> Address;

    async fn estimate_handle_ops_gas(
        &self,
        ops_per_aggregator: Vec<UserOpsPerAggregator>,
        beneficiary: Address,
    ) -> anyhow::Result<HandleOpsOut>;
}

#[derive(Clone, Debug)]
pub enum HandleOpsOut {
    SuccessWithGas(U256),
    FailedOp(usize, String),
    SignatureValidationFailed(Address),
}

#[async_trait]
impl<M> EntryPointLike for IEntryPoint<M>
where
    M: Middleware + 'static,
{
    fn address(&self) -> Address {
        self.deref().address()
    }

    async fn estimate_handle_ops_gas(
        &self,
        mut ops_per_aggregator: Vec<UserOpsPerAggregator>,
        beneficiary: Address,
    ) -> anyhow::Result<HandleOpsOut> {
        let result = if ops_per_aggregator.len() == 1
            && ops_per_aggregator[0].aggregator == Address::zero()
        {
            self.handle_ops(ops_per_aggregator.swap_remove(0).user_ops, beneficiary)
                .estimate_gas()
                .await
        } else {
            self.handle_aggregated_ops(ops_per_aggregator, beneficiary)
                .estimate_gas()
                .await
        };
        let error = match result {
            Ok(gas) => return Ok(HandleOpsOut::SuccessWithGas(gas)),
            Err(error) => error,
        };
        if let ContractError::Revert(revert_data) = &error {
            if let Ok(FailedOp { op_index, reason }) = FailedOp::decode(revert_data) {
                return Ok(HandleOpsOut::FailedOp(op_index.as_usize(), reason));
            }
            if let Ok(failure) = SignatureValidationFailed::decode(revert_data) {
                return Ok(HandleOpsOut::SignatureValidationFailed(failure.aggregator));
            }
        }
        Err(error)?
    }
}
