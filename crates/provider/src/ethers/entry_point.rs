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

use std::{ops::Deref, sync::Arc};

use anyhow::Context;
use ethers::{
    abi::AbiDecode,
    contract::{ContractError, FunctionCall},
    providers::{spoof, Middleware, RawCall},
    types::{
        transaction::eip2718::TypedTransaction, Address, BlockId, Bytes, Eip1559TransactionRequest,
        H256, U256,
    },
};
use rundler_types::{
    contracts::{
        i_entry_point::{ExecutionResult, FailedOp, IEntryPoint, SignatureValidationFailed},
        shared_types::UserOpsPerAggregator,
    },
    GasFees, UserOperation,
};
use rundler_utils::eth::{self, ContractRevertError};

use crate::traits::{EntryPoint, HandleOpsOut};

#[async_trait::async_trait]
impl<M> EntryPoint for IEntryPoint<M>
where
    M: Middleware + 'static,
{
    fn address(&self) -> Address {
        self.deref().address()
    }

    async fn simulate_validation(
        &self,
        user_op: UserOperation,
        max_validation_gas: u64,
    ) -> anyhow::Result<TypedTransaction> {
        let pvg = user_op.pre_verification_gas;

        let tx = self
            .simulate_validation(user_op)
            .gas(U256::from(max_validation_gas) + pvg)
            .tx;

        Ok(tx)
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

    async fn balance_of(
        &self,
        address: Address,
        block_id: Option<BlockId>,
    ) -> anyhow::Result<U256> {
        block_id
            .map_or(self.balance_of(address), |bid| {
                self.balance_of(address).block(bid)
            })
            .call()
            .await
            .context("entry point should return balance")
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
        return Ok(self.decode_simulate_handle_ops_revert(revert_data));
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

    fn decode_simulate_handle_ops_revert(
        &self,
        revert_data: Bytes,
    ) -> Result<ExecutionResult, String> {
        if let Ok(result) = ExecutionResult::decode(&revert_data) {
            Ok(result)
        } else if let Ok(failed_op) = FailedOp::decode(&revert_data) {
            Err(failed_op.reason)
        } else if let Ok(err) = ContractRevertError::decode(&revert_data) {
            Err(err.reason)
        } else {
            Err(String::new())
        }
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
