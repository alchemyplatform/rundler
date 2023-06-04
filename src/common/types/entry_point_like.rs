use std::{ops::Deref, sync::Arc};

use anyhow::Context;
use ethers::{
    abi::AbiDecode,
    contract::{ContractError, FunctionCall},
    providers::{spoof, Middleware, RawCall},
    types::{
        transaction::eip2718::TypedTransaction, Address, Bytes, Eip1559TransactionRequest, H256,
        U256,
    },
};
#[cfg(test)]
use mockall::automock;
use tonic::async_trait;

use crate::common::{
    contracts::{
        i_entry_point::{ExecutionResult, FailedOp, IEntryPoint, SignatureValidationFailed},
        shared_types::UserOpsPerAggregator,
    },
    eth,
    gas::GasFees,
    types::UserOperation,
};

#[cfg_attr(test, automock)]
#[async_trait]
pub trait EntryPointLike: Send + Sync + 'static {
    fn address(&self) -> Address;

    async fn call_handle_ops(
        &self,
        ops_per_aggregator: Vec<UserOpsPerAggregator>,
        beneficiary: Address,
        gas: U256,
    ) -> anyhow::Result<HandleOpsOut>;

    async fn balance_of(&self, address: Address) -> anyhow::Result<U256>;

    async fn get_deposit(&self, address: Address, block_hash: H256) -> anyhow::Result<U256>;

    async fn call_spoofed_simulate_op(
        &self,
        op: UserOperation,
        target: Address,
        target_call_data: Bytes,
        block_hash: H256,
        gas: U256,
        spoofed_state: &spoof::State,
    ) -> anyhow::Result<Result<ExecutionResult, String>>;

    fn get_send_bundle_transaction(
        &self,
        ops_per_aggregator: Vec<UserOpsPerAggregator>,
        beneficiary: Address,
        gas: U256,
        gas_fees: GasFees,
    ) -> TypedTransaction;
}

#[derive(Clone, Debug)]
pub enum HandleOpsOut {
    Success,
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

    async fn call_handle_ops(
        &self,
        ops_per_aggregator: Vec<UserOpsPerAggregator>,
        beneficiary: Address,
        gas: U256,
    ) -> anyhow::Result<HandleOpsOut> {
        let result = get_handle_ops_call(self, ops_per_aggregator, beneficiary, gas)
            .call()
            .await;
        let error = match result {
            Ok(()) => return Ok(HandleOpsOut::Success),
            Err(error) => error,
        };
        if let ContractError::Revert(revert_data) = &error {
            if let Ok(FailedOp { op_index, reason }) = FailedOp::decode(revert_data) {
                match &reason[..4] {
                    "AA95" => anyhow::bail!("Handle ops called with insufficent gas"),
                    _ => return Ok(HandleOpsOut::FailedOp(op_index.as_usize(), reason)),
                }
            }
            if let Ok(failure) = SignatureValidationFailed::decode(revert_data) {
                return Ok(HandleOpsOut::SignatureValidationFailed(failure.aggregator));
            }
        }
        Err(error)?
    }

    async fn balance_of(&self, address: Address) -> anyhow::Result<U256> {
        self.balance_of(address)
            .call()
            .await
            .context("entry point should return balance")
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

    async fn call_spoofed_simulate_op(
        &self,
        op: UserOperation,
        target: Address,
        target_call_data: Bytes,
        block_hash: H256,
        gas: U256,
        spoofed_state: &spoof::State,
    ) -> anyhow::Result<Result<ExecutionResult, String>> {
        let contract_error = self
            .simulate_handle_op(op, target, target_call_data)
            .block(block_hash)
            .gas(gas)
            .call_raw()
            .state(spoofed_state)
            .await
            .err()
            .context("simulateHandleOp succeeded, but should always revert")?;
        let revert_data = eth::get_revert_bytes(contract_error)
            .context("simulateHandleOps should return revert data")?;
        if let Ok(result) = ExecutionResult::decode(&revert_data) {
            Ok(Ok(result))
        } else if let Ok(failed_op) = FailedOp::decode(&revert_data) {
            Ok(Err(failed_op.reason))
        } else {
            Ok(Err(String::new()))
        }
    }

    fn get_send_bundle_transaction(
        &self,
        ops_per_aggregator: Vec<UserOpsPerAggregator>,
        beneficiary: Address,
        gas: U256,
        gas_fees: GasFees,
    ) -> TypedTransaction {
        let tx: Eip1559TransactionRequest =
            get_handle_ops_call(self, ops_per_aggregator, beneficiary, gas)
                .tx
                .into();
        tx.max_fee_per_gas(gas_fees.max_fee_per_gas)
            .max_priority_fee_per_gas(gas_fees.max_priority_fee_per_gas)
            .into()
    }
}

fn get_handle_ops_call<M: Middleware>(
    entry_point: &IEntryPoint<M>,
    mut ops_per_aggregator: Vec<UserOpsPerAggregator>,
    beneficiary: Address,
    gas: U256,
) -> FunctionCall<Arc<M>, M, ()> {
    let call =
        if ops_per_aggregator.len() == 1 && ops_per_aggregator[0].aggregator == Address::zero() {
            entry_point.handle_ops(ops_per_aggregator.swap_remove(0).user_ops, beneficiary)
        } else {
            entry_point.handle_aggregated_ops(ops_per_aggregator, beneficiary)
        };
    call.gas(gas)
}
