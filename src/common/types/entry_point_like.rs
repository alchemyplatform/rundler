use std::{ops::Deref, sync::Arc};

use anyhow::Context;
use ethers::{
    abi::AbiDecode,
    contract::{ContractError, FunctionCall},
    providers::Middleware,
    types::{Address, Bytes, H256, U256},
};
#[cfg(test)]
use mockall::automock;
use tonic::async_trait;

use crate::common::{
    contracts::{
        i_entry_point::{ExecutionResult, FailedOp, IEntryPoint, SignatureValidationFailed},
        shared_types::UserOpsPerAggregator,
    },
    types::UserOperation,
};

#[cfg_attr(test, automock)]
#[async_trait]
pub trait EntryPointLike: Send + Sync + 'static {
    fn address(&self) -> Address;

    async fn estimate_handle_ops_gas(
        &self,
        ops_per_aggregator: Vec<UserOpsPerAggregator>,
        beneficiary: Address,
    ) -> anyhow::Result<HandleOpsOut>;

    async fn send_bundle(
        &self,
        ops_per_aggregator: Vec<UserOpsPerAggregator>,
        beneficiary: Address,
        gas: U256,
    ) -> anyhow::Result<H256>;

    async fn get_deposit(&self, address: Address, block_hash: H256) -> anyhow::Result<U256>;

    async fn call_simulate_op(
        &self,
        op: UserOperation,
        block_hash: H256,
    ) -> anyhow::Result<Result<ExecutionResult, String>>;
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
        ops_per_aggregator: Vec<UserOpsPerAggregator>,
        beneficiary: Address,
    ) -> anyhow::Result<HandleOpsOut> {
        let result = get_handle_ops_call(self, ops_per_aggregator, beneficiary)
            .estimate_gas()
            .await;
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

    async fn send_bundle(
        &self,
        ops_per_aggregator: Vec<UserOpsPerAggregator>,
        beneficiary: Address,
        gas: U256,
    ) -> anyhow::Result<H256> {
        Ok(get_handle_ops_call(self, ops_per_aggregator, beneficiary)
            .gas(gas)
            .send()
            .await
            .context("should send bundle transaction")?
            .tx_hash())
    }

    async fn get_deposit(&self, address: Address, block_hash: H256) -> anyhow::Result<U256> {
        let deposit_info = self
            .get_deposit_info(address)
            .block(block_hash)
            .call()
            .await
            .context("entry point should return deposit info")?;
        Ok(deposit_info.deposit.into())
    }

    async fn call_simulate_op(
        &self,
        op: UserOperation,
        block_hash: H256,
    ) -> anyhow::Result<Result<ExecutionResult, String>> {
        let error = self
            .simulate_handle_op(op, Address::zero(), Bytes::new())
            .block(block_hash)
            .call()
            .await
            .err()
            .context("simulateHandleOp should revert")?;
        let ContractError::Revert(revert_data) = &error else {
            Err(error).context("simulateHandleOp should revert")?
        };
        if let Ok(result) = ExecutionResult::decode(revert_data) {
            Ok(Ok(result))
        } else if let Ok(failed_op) = FailedOp::decode(revert_data) {
            Ok(Err(failed_op.reason))
        } else {
            Ok(Err(String::new()))
        }
    }
}

fn get_handle_ops_call<M: Middleware>(
    entry_point: &IEntryPoint<M>,
    mut ops_per_aggregator: Vec<UserOpsPerAggregator>,
    beneficiary: Address,
) -> FunctionCall<Arc<M>, M, ()> {
    if ops_per_aggregator.len() == 1 && ops_per_aggregator[0].aggregator == Address::zero() {
        entry_point.handle_ops(ops_per_aggregator.swap_remove(0).user_ops, beneficiary)
    } else {
        entry_point.handle_aggregated_ops(ops_per_aggregator, beneficiary)
    }
}
