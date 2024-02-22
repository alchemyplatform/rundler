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

use anyhow::Context;
use ethers::{
    abi::AbiDecode,
    contract::{ContractError, FunctionCall},
    providers::{spoof, Middleware, RawCall},
    types::{
        transaction::eip2718::TypedTransaction, Address, BlockId, Bytes, Eip1559TransactionRequest,
        H256, U256,
    },
    utils::hex,
};
use rundler_types::{
    contracts::{
        get_balances::{GetBalancesResult, GETBALANCES_BYTECODE},
        i_entry_point::{ExecutionResult, FailedOp, IEntryPoint, SignatureValidationFailed},
        shared_types::UserOpsPerAggregator,
    },
    DepositInfo, GasFees, UserOperation, ValidationOutput,
};
use rundler_utils::eth::{self, ContractRevertError};

use crate::{
    traits::{EntryPoint, HandleOpsOut},
    Provider,
};

const REVERT_REASON_MAX_LEN: usize = 2048;

/// Implementation of the `EntryPoint` trait for the v0.6 version of the entry point contract using ethers
#[derive(Debug)]
pub struct EntryPointImpl<P: Provider + Middleware> {
    i_entry_point: IEntryPoint<P>,
    provider: Arc<P>,
}

impl<P> Clone for EntryPointImpl<P>
where
    P: Provider + Middleware,
{
    fn clone(&self) -> Self {
        Self {
            i_entry_point: self.i_entry_point.clone(),
            provider: self.provider.clone(),
        }
    }
}

impl<P> EntryPointImpl<P>
where
    P: Provider + Middleware,
{
    /// Create a new `EntryPointImpl` instance
    pub fn new(entry_point_address: Address, provider: Arc<P>) -> Self {
        Self {
            i_entry_point: IEntryPoint::new(entry_point_address, Arc::clone(&provider)),
            provider,
        }
    }
}

#[async_trait::async_trait]
impl<P> EntryPoint for EntryPointImpl<P>
where
    P: Provider + Middleware + Send + Sync + 'static,
{
    fn address(&self) -> Address {
        self.i_entry_point.address()
    }

    async fn get_simulate_validation_call(
        &self,
        user_op: UserOperation,
        max_validation_gas: u64,
    ) -> anyhow::Result<TypedTransaction> {
        let pvg = user_op.pre_verification_gas;
        let tx = self
            .i_entry_point
            .simulate_validation(user_op)
            .gas(U256::from(max_validation_gas) + pvg)
            .tx;
        Ok(tx)
    }

    async fn call_simulate_validation(
        &self,
        user_op: UserOperation,
        max_validation_gas: u64,
    ) -> anyhow::Result<ValidationOutput> {
        let pvg = user_op.pre_verification_gas;
        match self
            .i_entry_point
            .simulate_validation(user_op)
            .gas(U256::from(max_validation_gas) + pvg)
            .call()
            .await
        {
            Ok(()) => anyhow::bail!("simulateValidation should always revert"),
            Err(ContractError::Revert(revert_data)) => ValidationOutput::decode(revert_data)
                .context("entry point should return validation output"),
            Err(error) => Err(error).context("call simulation RPC failed")?,
        }
    }

    async fn call_handle_ops(
        &self,
        ops_per_aggregator: Vec<UserOpsPerAggregator>,
        beneficiary: Address,
        gas: U256,
    ) -> anyhow::Result<HandleOpsOut> {
        let result = get_handle_ops_call(&self.i_entry_point, ops_per_aggregator, beneficiary, gas)
            .call()
            .await;
        let error = match result {
            Ok(()) => return Ok(HandleOpsOut::Success),
            Err(error) => error,
        };
        if let ContractError::Revert(revert_data) = &error {
            if let Ok(FailedOp { op_index, reason }) = FailedOp::decode(revert_data) {
                match &reason[..4] {
                    "AA95" => anyhow::bail!("Handle ops called with insufficient gas"),
                    _ => return Ok(HandleOpsOut::FailedOp(op_index.as_usize(), reason)),
                }
            }
            if let Ok(failure) = SignatureValidationFailed::decode(revert_data) {
                return Ok(HandleOpsOut::SignatureValidationFailed(failure.aggregator));
            }
            // Special handling for a bug in the 0.6 entry point contract to detect the bug where
            // the `returndatacopy` opcode reverts due to a postOp revert and the revert data is too short.
            // See https://github.com/eth-infinitism/account-abstraction/pull/325 for more details.
            // NOTE: this error message is copied directly from Geth and assumes it will not change.
            if error.to_string().contains("return data out of bounds") {
                return Ok(HandleOpsOut::PostOpRevert);
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
            .map_or(self.i_entry_point.balance_of(address), |bid| {
                self.i_entry_point.balance_of(address).block(bid)
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
            .i_entry_point
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
            get_handle_ops_call(&self.i_entry_point, ops_per_aggregator, beneficiary, gas)
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
            Err(hex::encode(&revert_data[..REVERT_REASON_MAX_LEN]))
        }
    }

    async fn get_deposit_info(&self, address: Address) -> anyhow::Result<DepositInfo> {
        Ok(self
            .i_entry_point
            .get_deposit_info(address)
            .await
            .context("should get deposit info")?)
    }

    async fn get_balances(&self, addresses: Vec<Address>) -> anyhow::Result<Vec<U256>> {
        let out: GetBalancesResult = self
            .provider
            .call_constructor(
                &GETBALANCES_BYTECODE,
                (self.address(), addresses),
                None,
                &spoof::state(),
            )
            .await
            .context("should compute balances")?;
        Ok(out.balances)
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
