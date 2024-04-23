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
    contract::{ContractError, EthCall, FunctionCall},
    providers::{spoof, Middleware, RawCall},
    types::{
        transaction::eip2718::TypedTransaction, Address, BlockId, Bytes, Eip1559TransactionRequest,
        H256, U256,
    },
};
use rundler_types::{
    chain::ChainSpec,
    contracts::v0_6::{
        get_balances::{GetBalancesResult, GETBALANCES_BYTECODE},
        i_aggregator::IAggregator,
        i_entry_point::{
            self, DepositInfo as DepositInfoV0_6, ExecutionResult as ExecutionResultV0_6, FailedOp,
            IEntryPoint, SignatureValidationFailed,
            UserOpsPerAggregator as UserOpsPerAggregatorV0_6,
        },
    },
    v0_6::UserOperation,
    GasFees, UserOpsPerAggregator, ValidationError, ValidationOutput, ValidationRevert,
};
use rundler_utils::eth::{self, ContractRevertError};

use super::L1GasOracle;
use crate::{
    traits::HandleOpsOut, AggregatorOut, AggregatorSimOut, BundleHandler, DepositInfo,
    EntryPoint as EntryPointTrait, EntryPointProvider, ExecutionResult, L1GasProvider, Provider,
    SignatureAggregator, SimulateOpCallData, SimulationProvider,
};

/// Implementation of the `EntryPoint` trait for the v0.6 version of the entry point contract using ethers
#[derive(Debug)]
pub struct EntryPoint<P: Provider + Middleware> {
    i_entry_point: IEntryPoint<P>,
    provider: Arc<P>,
    l1_gas_oracle: L1GasOracle<P>,
    max_aggregation_gas: u64,
}

impl<P> Clone for EntryPoint<P>
where
    P: Provider + Middleware,
{
    fn clone(&self) -> Self {
        Self {
            i_entry_point: self.i_entry_point.clone(),
            provider: self.provider.clone(),
            l1_gas_oracle: self.l1_gas_oracle.clone(),
            max_aggregation_gas: self.max_aggregation_gas,
        }
    }
}

impl<P> EntryPoint<P>
where
    P: Provider + Middleware,
{
    /// Create a new `EntryPointV0_6` instance
    pub fn new(
        entry_point_address: Address,
        chain_spec: &ChainSpec,
        max_aggregation_gas: u64,
        provider: Arc<P>,
    ) -> Self {
        Self {
            i_entry_point: IEntryPoint::new(entry_point_address, Arc::clone(&provider)),
            provider: Arc::clone(&provider),
            l1_gas_oracle: L1GasOracle::new(chain_spec, provider),
            max_aggregation_gas,
        }
    }
}

#[async_trait::async_trait]
impl<P> EntryPointTrait for EntryPoint<P>
where
    P: Provider + Middleware + Send + Sync + 'static,
{
    fn address(&self) -> Address {
        self.i_entry_point.address()
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

    async fn get_deposit_info(&self, address: Address) -> anyhow::Result<DepositInfo> {
        Ok(self
            .i_entry_point
            .get_deposit_info(address)
            .await
            .context("should get deposit info")?
            .into())
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

#[async_trait::async_trait]
impl<P> SignatureAggregator for EntryPoint<P>
where
    P: Provider + Middleware + Send + Sync + 'static,
{
    type UO = UserOperation;

    async fn aggregate_signatures(
        &self,
        aggregator_address: Address,
        ops: Vec<UserOperation>,
    ) -> anyhow::Result<Option<Bytes>> {
        let aggregator = IAggregator::new(aggregator_address, Arc::clone(&self.provider));
        let result = aggregator
            .aggregate_signatures(ops)
            .gas(self.max_aggregation_gas)
            .call()
            .await;
        match result {
            Ok(bytes) => Ok(Some(bytes)),
            Err(ContractError::Revert(_)) => Ok(None),
            Err(error) => Err(error).context("aggregator contract should aggregate signatures")?,
        }
    }

    async fn validate_user_op_signature(
        &self,
        aggregator_address: Address,
        user_op: UserOperation,
        gas_cap: u64,
    ) -> anyhow::Result<AggregatorOut> {
        let aggregator = IAggregator::new(aggregator_address, Arc::clone(&self.provider));

        let result = aggregator
            .validate_user_op_signature(user_op)
            .gas(gas_cap)
            .call()
            .await;

        match result {
            Ok(sig) => Ok(AggregatorOut::SuccessWithInfo(AggregatorSimOut {
                address: aggregator_address,
                signature: sig,
            })),
            Err(ContractError::Revert(_)) => Ok(AggregatorOut::ValidationReverted),
            Err(error) => Err(error).context("should call aggregator to validate signature")?,
        }
    }
}

#[async_trait::async_trait]
impl<P> BundleHandler for EntryPoint<P>
where
    P: Provider + Middleware + Send + Sync + 'static,
{
    type UO = UserOperation;

    async fn call_handle_ops(
        &self,
        ops_per_aggregator: Vec<UserOpsPerAggregator<UserOperation>>,
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

    fn get_send_bundle_transaction(
        &self,
        ops_per_aggregator: Vec<UserOpsPerAggregator<UserOperation>>,
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
}

#[async_trait::async_trait]
impl<P> L1GasProvider for EntryPoint<P>
where
    P: Provider + Middleware + Send + Sync + 'static,
{
    type UO = UserOperation;

    async fn calc_l1_gas(
        &self,
        entry_point_address: Address,
        user_op: UserOperation,
        gas_price: U256,
    ) -> anyhow::Result<U256> {
        let data = self
            .i_entry_point
            .handle_ops(vec![user_op], Address::random())
            .calldata()
            .context("should get calldata for entry point handle ops")?;

        self.l1_gas_oracle
            .estimate_l1_gas(entry_point_address, data, gas_price)
            .await
    }
}

#[async_trait::async_trait]
impl<P> SimulationProvider for EntryPoint<P>
where
    P: Provider + Middleware + Send + Sync + 'static,
{
    type UO = UserOperation;

    fn get_tracer_simulate_validation_call(
        &self,
        user_op: UserOperation,
        max_validation_gas: u64,
    ) -> (TypedTransaction, spoof::State) {
        let pvg = user_op.pre_verification_gas;
        let call = self
            .i_entry_point
            .simulate_validation(user_op)
            .gas(U256::from(max_validation_gas) + pvg)
            .tx;
        (call, spoof::State::default())
    }

    async fn call_simulate_validation(
        &self,
        user_op: UserOperation,
        max_validation_gas: u64,
        block_hash: Option<H256>,
    ) -> Result<ValidationOutput, ValidationError> {
        let pvg = user_op.pre_verification_gas;
        let blockless = self
            .i_entry_point
            .simulate_validation(user_op)
            .gas(U256::from(max_validation_gas) + pvg);
        let call = match block_hash {
            Some(block_hash) => blockless.block(block_hash),
            None => blockless,
        };

        match call.call().await {
            Ok(()) => Err(anyhow::anyhow!("simulateValidation should always revert"))?,
            Err(ContractError::Revert(revert_data)) => {
                if let Ok(result) = ValidationOutput::decode_v0_6(&revert_data) {
                    Ok(result)
                } else if let Ok(failed_op) = FailedOp::decode(&revert_data) {
                    Err(ValidationRevert::from(failed_op))?
                } else if let Ok(err) = ContractRevertError::decode(&revert_data) {
                    Err(ValidationRevert::from(err))?
                } else {
                    Err(ValidationRevert::Unknown(revert_data))?
                }
            }
            Err(error) => Err(error).context("call simulation RPC failed")?,
        }
    }

    fn decode_simulate_handle_ops_revert(
        &self,
        revert_data: Bytes,
    ) -> Result<ExecutionResult, ValidationRevert> {
        if let Ok(result) = ExecutionResultV0_6::decode(&revert_data) {
            Ok(result.into())
        } else if let Ok(failed_op) = FailedOp::decode(&revert_data) {
            Err(ValidationRevert::EntryPoint(failed_op.reason))
        } else if let Ok(err) = ContractRevertError::decode(&revert_data) {
            Err(ValidationRevert::EntryPoint(err.reason))
        } else {
            Err(ValidationRevert::Unknown(revert_data))
        }
    }

    fn get_simulate_op_call_data(
        &self,
        op: UserOperation,
        spoofed_state: &spoof::State,
    ) -> SimulateOpCallData {
        let call_data = eth::call_data_of(
            i_entry_point::SimulateHandleOpCall::selector(),
            (op.clone(), Address::zero(), Bytes::new()),
        );
        SimulateOpCallData {
            call_data,
            spoofed_state: spoofed_state.clone(),
        }
    }

    async fn call_spoofed_simulate_op(
        &self,
        user_op: UserOperation,
        target: Address,
        target_call_data: Bytes,
        block_hash: H256,
        gas: U256,
        spoofed_state: &spoof::State,
    ) -> anyhow::Result<Result<ExecutionResult, ValidationRevert>> {
        let contract_error = self
            .i_entry_point
            .simulate_handle_op(user_op, target, target_call_data)
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

    fn simulation_should_revert(&self) -> bool {
        true
    }
}

impl<P> EntryPointProvider<UserOperation> for EntryPoint<P> where
    P: Provider + Middleware + Send + Sync + 'static
{
}

fn get_handle_ops_call<M: Middleware>(
    entry_point: &IEntryPoint<M>,
    ops_per_aggregator: Vec<UserOpsPerAggregator<UserOperation>>,
    beneficiary: Address,
    gas: U256,
) -> FunctionCall<Arc<M>, M, ()> {
    let mut ops_per_aggregator: Vec<UserOpsPerAggregatorV0_6> = ops_per_aggregator
        .into_iter()
        .map(|uoa| UserOpsPerAggregatorV0_6 {
            user_ops: uoa.user_ops,
            aggregator: uoa.aggregator,
            signature: uoa.signature,
        })
        .collect();
    let call =
        if ops_per_aggregator.len() == 1 && ops_per_aggregator[0].aggregator == Address::zero() {
            entry_point.handle_ops(ops_per_aggregator.swap_remove(0).user_ops, beneficiary)
        } else {
            entry_point.handle_aggregated_ops(ops_per_aggregator, beneficiary)
        };
    call.gas(gas)
}

impl From<ExecutionResultV0_6> for ExecutionResult {
    fn from(result: ExecutionResultV0_6) -> Self {
        ExecutionResult {
            pre_op_gas: result.pre_op_gas,
            paid: result.paid,
            valid_after: result.valid_after.into(),
            valid_until: result.valid_until.into(),
            target_success: result.target_success,
            target_result: result.target_result,
        }
    }
}

impl From<DepositInfoV0_6> for DepositInfo {
    fn from(info: DepositInfoV0_6) -> Self {
        DepositInfo {
            deposit: info.deposit.into(),
            staked: info.staked,
            stake: info.stake,
            unstake_delay_sec: info.unstake_delay_sec,
            withdraw_time: info.withdraw_time,
        }
    }
}
