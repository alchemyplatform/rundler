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

use alloy_contract::Error as ContractError;
use alloy_eips::eip7702::SignedAuthorization;
use alloy_primitives::{Address, Bytes, U256};
use alloy_provider::network::{AnyNetwork, TransactionBuilder7702};
use alloy_rpc_types_eth::{
    state::{AccountOverride, StateOverride},
    BlockId,
};
use alloy_sol_types::{ContractError as SolContractError, SolInterface};
use alloy_transport::TransportError;
use anyhow::Context;
use rundler_contracts::v0_6::{
    DepositInfo as DepositInfoV0_6, GetEntryPointBalances, IAggregator,
    IEntryPoint::{
        ExecutionResult as ExecutionResultV0_6, FailedOp, IEntryPointCalls, IEntryPointErrors,
        IEntryPointInstance,
    },
    UserOperation as ContractUserOperation, UserOpsPerAggregator as UserOpsPerAggregatorV0_6,
    ENTRY_POINT_V0_6_DEPLOYED_BYTECODE,
};
use rundler_types::{
    chain::ChainSpec,
    constants::SIMULATION_SENDER,
    da::{DAGasBlockData, DAGasData},
    v0_6::{UserOperation, UserOperationBuilder},
    EntryPointVersion, GasFees, UserOperation as _, UserOpsPerAggregator, ValidationOutput,
    ValidationRevert,
};
use rundler_utils::authorization_utils;
use tracing::instrument;

use crate::{
    AggregatorOut, AggregatorSimOut, AlloyProvider, BlockHashOrNumber, BundleHandler, DAGasOracle,
    DAGasProvider, DepositInfo, EntryPoint, EntryPointProvider as EntryPointProviderTrait,
    ExecutionResult, HandleOpsOut, ProviderResult, SignatureAggregator, SimulationProvider,
    TransactionRequest,
};

/// Entry point provider for v0.6
#[derive(Clone)]
pub struct EntryPointProvider<AP, D> {
    i_entry_point: IEntryPointInstance<AP, AnyNetwork>,
    da_gas_oracle: D,
    max_verification_gas: u64,
    max_simulate_handle_op_gas: u64,
    max_gas_estimation_gas: u64,
    max_aggregation_gas: u64,
    chain_spec: ChainSpec,
}

impl<AP, D> EntryPointProvider<AP, D>
where
    AP: AlloyProvider + Clone,
    D: DAGasOracle,
{
    /// Create a new `EntryPoint` instance for v0.6
    pub fn new(
        chain_spec: ChainSpec,
        max_verification_gas: u64,
        max_simulate_handle_op_gas: u64,
        max_gas_estimation_gas: u64,
        max_aggregation_gas: u64,
        provider: AP,
        da_gas_oracle: D,
    ) -> Self {
        Self {
            i_entry_point: IEntryPointInstance::new(
                chain_spec.entry_point_address_v0_6,
                provider.clone(),
            ),
            da_gas_oracle,
            max_verification_gas,
            max_simulate_handle_op_gas,
            max_gas_estimation_gas,
            max_aggregation_gas,
            chain_spec,
        }
    }
}

#[async_trait::async_trait]
impl<AP, D> EntryPoint for EntryPointProvider<AP, D>
where
    AP: AlloyProvider,
    D: Send + Sync,
{
    fn version(&self) -> EntryPointVersion {
        EntryPointVersion::V0_6
    }

    fn address(&self) -> &Address {
        self.i_entry_point.address()
    }

    #[instrument(skip_all)]
    async fn balance_of(
        &self,
        address: Address,
        block_id: Option<BlockId>,
    ) -> ProviderResult<U256> {
        let ret = block_id
            .map_or(self.i_entry_point.balanceOf(address), |bid| {
                self.i_entry_point.balanceOf(address).block(bid)
            })
            .call()
            .await?;

        Ok(ret)
    }

    #[instrument(skip_all)]
    async fn get_deposit_info(&self, address: Address) -> ProviderResult<DepositInfo> {
        self.i_entry_point
            .getDepositInfo(address)
            .call()
            .await
            .map_err(Into::into)
            .map(|r| r.into())
    }

    #[instrument(skip_all)]
    async fn get_balances(&self, addresses: Vec<Address>) -> ProviderResult<Vec<U256>> {
        let helper_addr = Address::random();
        let helper = GetEntryPointBalances::new(helper_addr, self.i_entry_point.provider());
        let mut overrides = StateOverride::default();
        let account = AccountOverride {
            code: Some(GetEntryPointBalances::DEPLOYED_BYTECODE.clone()),
            ..Default::default()
        };
        overrides.insert(helper_addr, account);
        let ret = helper
            .getBalances(*self.address(), addresses.clone())
            .state(overrides)
            .call()
            .await?;

        if ret.len() != addresses.len() {
            return Err(anyhow::anyhow!(
                "expected {} balances, got {}",
                addresses.len(),
                ret.len()
            )
            .into());
        }
        Ok(ret)
    }
}

#[async_trait::async_trait]
impl<AP, D> SignatureAggregator for EntryPointProvider<AP, D>
where
    AP: AlloyProvider,
    D: Send + Sync,
{
    type UO = UserOperation;

    async fn aggregate_signatures(
        &self,
        aggregator_address: Address,
        ops: Vec<Self::UO>,
    ) -> ProviderResult<Option<Bytes>> {
        let aggregator = IAggregator::new(aggregator_address, self.i_entry_point.provider());
        let ops_len = ops.len();
        let da_gas: u64 = ops
            .iter()
            .map(|op| {
                op.pre_verification_da_gas_limit(&self.chain_spec, Some(ops_len))
                    .try_into()
                    .unwrap_or(u64::MAX)
            })
            .sum::<u64>();
        let ops: Vec<ContractUserOperation> = ops.into_iter().map(Into::into).collect();

        let result = aggregator
            .aggregateSignatures(ops)
            .gas(self.max_aggregation_gas.saturating_add(da_gas))
            .call()
            .await;

        match result {
            Ok(ret) => Ok(Some(ret)),
            Err(ContractError::TransportError(TransportError::ErrorResp(resp))) => {
                if let Some(revert) = resp.as_revert_data() {
                    let msg = format!(
                        "Aggregator contract should aggregate signatures. Revert: {revert}",
                    );
                    tracing::error!(msg);
                    Err(anyhow::anyhow!(msg).into())
                } else {
                    Err(TransportError::ErrorResp(resp).into())
                }
            }
            Err(error) => Err(error).context("aggregator contract should aggregate signatures")?,
        }
    }

    async fn validate_user_op_signature(
        &self,
        aggregator_address: Address,
        user_op: Self::UO,
    ) -> ProviderResult<AggregatorOut> {
        let aggregator = IAggregator::new(aggregator_address, self.i_entry_point.provider());
        let da_gas = user_op
            .pre_verification_da_gas_limit(&self.chain_spec, Some(1))
            .try_into()
            .unwrap_or(u64::MAX);

        let result = aggregator
            .validateUserOpSignature(user_op.into())
            .gas(self.max_verification_gas.saturating_add(da_gas))
            .call()
            .await;

        match result {
            Ok(ret) => Ok(AggregatorOut::SuccessWithInfo(AggregatorSimOut {
                address: aggregator_address,
                signature: ret,
            })),
            Err(ContractError::TransportError(TransportError::ErrorResp(resp))) => {
                if let Some(revert) = resp.as_revert_data() {
                    Ok(AggregatorOut::ValidationReverted(revert))
                } else {
                    Err(TransportError::ErrorResp(resp).into())
                }
            }
            Err(error) => Err(error.into()),
        }
    }
}

#[async_trait::async_trait]
impl<AP, D> BundleHandler for EntryPointProvider<AP, D>
where
    AP: AlloyProvider,
    D: Send + Sync,
{
    type UO = UserOperation;

    #[instrument(skip_all)]
    async fn call_handle_ops(
        &self,
        ops_per_aggregator: Vec<UserOpsPerAggregator<UserOperation>>,
        sender_eoa: Address,
        gas_limit: u64,
        gas_fees: GasFees,
        proxy: Option<Address>,
        _validation_only: bool,
    ) -> ProviderResult<HandleOpsOut> {
        let tx = get_handle_ops_call(
            &self.i_entry_point,
            ops_per_aggregator,
            sender_eoa,
            gas_limit,
            gas_fees,
            proxy,
            self.chain_spec.id,
        );
        let res = self.i_entry_point.provider().call(tx.into()).await;

        match res {
            Ok(_) => return Ok(HandleOpsOut::Success),
            Err(TransportError::ErrorResp(resp)) => {
                Self::decode_handle_ops_revert(&resp.message, &resp.as_revert_data())
                    .ok_or_else(|| TransportError::ErrorResp(resp).into())
            }
            Err(error) => Err(error.into()),
        }
    }

    fn get_send_bundle_transaction(
        &self,
        ops_per_aggregator: Vec<UserOpsPerAggregator<UserOperation>>,
        sender_eoa: Address,
        gas_limit: u64,
        gas_fees: GasFees,
        proxy: Option<Address>,
    ) -> TransactionRequest {
        get_handle_ops_call(
            &self.i_entry_point,
            ops_per_aggregator,
            sender_eoa,
            gas_limit,
            gas_fees,
            proxy,
            self.chain_spec.id,
        )
    }

    fn decode_handle_ops_revert(
        message: &str,
        revert_data: &Option<Bytes>,
    ) -> Option<HandleOpsOut> {
        if let Some(revert_data) = revert_data {
            let ret = if let Ok(err) = IEntryPointErrors::abi_decode(revert_data) {
                match err {
                    IEntryPointErrors::FailedOp(FailedOp { opIndex, reason }) => {
                        HandleOpsOut::FailedOp(opIndex.try_into().unwrap_or(usize::MAX), reason)
                    }
                    IEntryPointErrors::SignatureValidationFailed(err) => {
                        HandleOpsOut::SignatureValidationFailed(err.aggregator)
                    }
                    IEntryPointErrors::ValidationResult(_)
                    | IEntryPointErrors::ValidationResultWithAggregation(_)
                    | IEntryPointErrors::ExecutionResult(_) => {
                        HandleOpsOut::Revert(revert_data.clone())
                    }
                }
            } else {
                HandleOpsOut::Revert(revert_data.clone())
            };
            Some(ret)
        } else if message.contains("return data out of bounds") {
            // Special handling for a bug in the 0.6 entry point contract to detect the bug where
            // the `returndatacopy` opcode reverts due to a postOp revert and the revert data is too short.
            // See https://github.com/eth-infinitism/account-abstraction/pull/325 for more details.
            // NOTE: this error message is copied directly from Geth and assumes it will not change.
            Some(HandleOpsOut::PostOpRevert)
        } else {
            None
        }
    }

    fn decode_ops_from_calldata(
        chain_spec: &ChainSpec,
        calldata: &Bytes,
    ) -> Vec<UserOpsPerAggregator<UserOperation>> {
        decode_ops_from_calldata(chain_spec, calldata)
    }
}

#[async_trait::async_trait]
impl<AP, D> DAGasProvider for EntryPointProvider<AP, D>
where
    AP: AlloyProvider,
    D: DAGasOracle,
{
    type UO = UserOperation;

    #[instrument(skip_all)]
    async fn calc_da_gas(
        &self,
        user_op: UserOperation,
        block: BlockHashOrNumber,
        gas_price: u128,
        bundle_size: usize,
    ) -> ProviderResult<(u128, DAGasData, DAGasBlockData)> {
        let au = user_op.authorization_tuple().cloned();
        let extra_data_len = user_op.extra_data_len(bundle_size);

        let txn_request = self
            .i_entry_point
            .handleOps(vec![user_op.into()], Address::random())
            .from(SIMULATION_SENDER)
            .into_transaction_request();

        let data = txn_request.inner.input.into_input().unwrap();

        // TODO(bundle): assuming a bundle size of 1
        let bundle_data = super::max_bundle_transaction_data(
            *self.i_entry_point.address(),
            data,
            gas_price,
            au.as_ref(),
        );

        self.da_gas_oracle
            .estimate_da_gas(
                bundle_data,
                *self.i_entry_point.address(),
                block,
                gas_price,
                extra_data_len,
            )
            .await
    }
}

#[async_trait::async_trait]
impl<AP, D> SimulationProvider for EntryPointProvider<AP, D>
where
    AP: AlloyProvider,
    D: Send + Sync,
{
    type UO = UserOperation;

    fn get_tracer_simulate_validation_call(
        &self,
        user_op: UserOperation,
    ) -> ProviderResult<(TransactionRequest, StateOverride)> {
        let da_gas = user_op
            .pre_verification_da_gas_limit(&self.chain_spec, Some(1))
            .try_into()
            .unwrap_or(u64::MAX);
        let call = self
            .i_entry_point
            .simulateValidation(user_op.into())
            .from(SIMULATION_SENDER)
            .gas(self.max_verification_gas.saturating_add(da_gas))
            .into_transaction_request();
        Ok((call.inner, StateOverride::default()))
    }

    #[instrument(skip_all)]
    async fn simulate_validation(
        &self,
        user_op: UserOperation,
        block_id: Option<BlockId>,
    ) -> ProviderResult<Result<ValidationOutput, ValidationRevert>> {
        let da_gas = user_op
            .pre_verification_da_gas_limit(&self.chain_spec, Some(1))
            .try_into()
            .unwrap_or(u64::MAX);

        let blockless = self
            .i_entry_point
            .simulateValidation(user_op.into())
            .from(SIMULATION_SENDER)
            .gas(self.max_verification_gas.saturating_add(da_gas));
        let call = match block_id {
            Some(block_id) => blockless.block(block_id),
            None => blockless,
        };

        match call.call().await {
            Ok(_) => Err(anyhow::anyhow!("simulateValidation should always revert"))?,
            Err(ContractError::TransportError(TransportError::ErrorResp(resp))) => {
                if let Some(err) =
                    resp.as_decoded_interface_error::<SolContractError<IEntryPointErrors>>()
                {
                    match err {
                        // success cases
                        SolContractError::CustomError(IEntryPointErrors::ValidationResult(s)) => {
                            Ok(Ok(s.try_into().map_err(anyhow::Error::msg)?))
                        }
                        SolContractError::CustomError(
                            IEntryPointErrors::ValidationResultWithAggregation(s),
                        ) => Ok(Ok(s.try_into().map_err(anyhow::Error::msg)?)),
                        // failure cases
                        SolContractError::CustomError(IEntryPointErrors::FailedOp(f)) => {
                            Ok(Err(f.into()))
                        }
                        SolContractError::Revert(r) => Ok(Err(r.into())),
                        // unexpected case or unknown error
                        _ => Err(TransportError::ErrorResp(resp).into()),
                    }
                } else {
                    Err(TransportError::ErrorResp(resp).into())
                }
            }
            Err(error) => Err(error.into()),
        }
    }

    #[instrument(skip_all)]
    async fn simulate_handle_op(
        &self,
        op: Self::UO,
        target: Address,
        target_call_data: Bytes,
        block_id: BlockId,
        state_override: StateOverride,
    ) -> ProviderResult<Result<ExecutionResult, ValidationRevert>> {
        simulate_handle_op_inner::<Self, AP>(
            &self.chain_spec,
            self.max_simulate_handle_op_gas,
            &self.i_entry_point,
            op,
            target,
            target_call_data,
            block_id,
            state_override,
        )
        .await
    }

    #[instrument(skip_all)]
    async fn simulate_handle_op_estimate_gas(
        &self,
        op: Self::UO,
        target: Address,
        target_call_data: Bytes,
        block_id: BlockId,
        state_override: StateOverride,
    ) -> ProviderResult<Result<ExecutionResult, ValidationRevert>> {
        simulate_handle_op_inner::<Self, AP>(
            &self.chain_spec,
            self.max_gas_estimation_gas,
            &self.i_entry_point,
            op,
            target,
            target_call_data,
            block_id,
            state_override,
        )
        .await
    }

    fn decode_simulate_handle_ops_revert(
        payload: &Bytes,
    ) -> ProviderResult<Result<ExecutionResult, ValidationRevert>> {
        let ret = if let Ok(err) = SolContractError::<IEntryPointErrors>::abi_decode(payload) {
            match err {
                // success case
                SolContractError::CustomError(IEntryPointErrors::ExecutionResult(e)) => {
                    Ok(e.try_into()?)
                }
                // failure cases
                SolContractError::CustomError(IEntryPointErrors::FailedOp(f)) => Err(f.into()),
                SolContractError::CustomError(IEntryPointErrors::SignatureValidationFailed(f)) => {
                    Err(ValidationRevert::EntryPoint(format!(
                        "Aggregator signature validation failed: {}",
                        f.aggregator
                    )))
                }
                SolContractError::Revert(r) => Err(r.into()),
                // unexpected cases
                SolContractError::CustomError(IEntryPointErrors::ValidationResult(_))
                | SolContractError::CustomError(
                    IEntryPointErrors::ValidationResultWithAggregation(_),
                ) => Err(ValidationRevert::EntryPoint(
                    "simulateHandleOp returned ValidationResult or ValidationResultWithAggregation, unexpected type".to_string()
                )),
                SolContractError::Panic(p) => Err(p.into()),
            }
        } else {
            Err(ValidationRevert::Unknown(payload.clone()))
        };

        Ok(ret)
    }

    fn simulation_should_revert(&self) -> bool {
        true
    }

    fn get_simulations_bytecode(&self) -> &Bytes {
        &ENTRY_POINT_V0_6_DEPLOYED_BYTECODE
    }
}

impl<AP, D> EntryPointProviderTrait<UserOperation> for EntryPointProvider<AP, D>
where
    AP: AlloyProvider,
    D: DAGasOracle,
{
}

fn get_handle_ops_call<AP: AlloyProvider>(
    entry_point: &IEntryPointInstance<AP, AnyNetwork>,
    ops_per_aggregator: Vec<UserOpsPerAggregator<UserOperation>>,
    sender_eoa: Address,
    gas_limit: u64,
    gas_fees: GasFees,
    proxy: Option<Address>,
    chain_id: u64,
) -> TransactionRequest {
    let mut eip7702_auth_list: Vec<SignedAuthorization> = vec![];
    let mut ops_per_aggregator: Vec<UserOpsPerAggregatorV0_6> = ops_per_aggregator
        .into_iter()
        .map(|uoa| UserOpsPerAggregatorV0_6 {
            userOps: uoa
                .user_ops
                .into_iter()
                .map(|op| {
                    if let Some(authorization) = op.authorization_tuple() {
                        eip7702_auth_list.push(SignedAuthorization::from(authorization.clone()));
                    }
                    op.into()
                })
                .collect(),
            aggregator: uoa.aggregator,
            signature: uoa.signature,
        })
        .collect();

    let mut txn_request =
        if ops_per_aggregator.len() == 1 && ops_per_aggregator[0].aggregator == Address::ZERO {
            entry_point
                .handleOps(ops_per_aggregator.swap_remove(0).userOps, sender_eoa)
                .chain_id(chain_id)
                .from(SIMULATION_SENDER)
                .into_transaction_request()
                .inner
        } else {
            entry_point
                .handleAggregatedOps(ops_per_aggregator, sender_eoa)
                .chain_id(chain_id)
                .from(SIMULATION_SENDER)
                .into_transaction_request()
                .inner
        };

    txn_request = txn_request
        .from(sender_eoa)
        .gas_limit(gas_limit)
        .max_fee_per_gas(gas_fees.max_fee_per_gas)
        .max_priority_fee_per_gas(gas_fees.max_priority_fee_per_gas);

    if !eip7702_auth_list.is_empty() {
        txn_request = txn_request.with_authorization_list(eip7702_auth_list);
    }
    if let Some(proxy) = proxy {
        txn_request = txn_request.to(proxy);
    }

    txn_request
}

/// Decode user ops from calldata
pub fn decode_ops_from_calldata(
    chain_spec: &ChainSpec,
    calldata: &Bytes,
) -> Vec<UserOpsPerAggregator<UserOperation>> {
    let entry_point_calls = match IEntryPointCalls::abi_decode(calldata) {
        Ok(entry_point_calls) => entry_point_calls,
        Err(_) => return vec![],
    };

    match entry_point_calls {
        IEntryPointCalls::handleOps(handle_ops_call) => {
            let ops = handle_ops_call
                .ops
                .into_iter()
                .filter_map(|op| {
                    UserOperationBuilder::from_contract(chain_spec, op)
                        .ok()
                        .map(|b| b.build())
                })
                .collect();

            vec![UserOpsPerAggregator {
                user_ops: ops,
                aggregator: Address::ZERO,
                signature: Bytes::new(),
            }]
        }
        IEntryPointCalls::handleAggregatedOps(handle_aggregated_ops_call) => {
            handle_aggregated_ops_call
                .opsPerAggregator
                .into_iter()
                .map(|ops| UserOpsPerAggregator {
                    user_ops: ops
                        .userOps
                        .into_iter()
                        .filter_map(move |op| {
                            UserOperationBuilder::from_contract(chain_spec, op)
                                .ok()
                                .map(|b| b.aggregator(ops.aggregator).build())
                        })
                        .collect(),
                    aggregator: ops.aggregator,
                    signature: ops.signature,
                })
                .collect()
        }
        _ => vec![],
    }
}

#[allow(clippy::too_many_arguments)]
async fn simulate_handle_op_inner<S: SimulationProvider, AP: AlloyProvider>(
    chain_spec: &ChainSpec,
    execution_gas_limit: u64,
    entry_point: &IEntryPointInstance<AP, AnyNetwork>,
    op: UserOperation,
    target: Address,
    target_call_data: Bytes,
    block_id: BlockId,
    mut state_override: StateOverride,
) -> ProviderResult<Result<ExecutionResult, ValidationRevert>> {
    let da_gas = op
        .pre_verification_da_gas_limit(chain_spec, Some(1))
        .try_into()
        .unwrap_or(u64::MAX);

    if let Some(authorization) = op.authorization_tuple() {
        authorization_utils::apply_7702_overrides(
            &mut state_override,
            op.sender(),
            authorization.address,
        );
    }

    let contract_error = entry_point
        .simulateHandleOp(op.into(), target, target_call_data)
        .block(block_id)
        .gas(execution_gas_limit.saturating_add(da_gas))
        .state(state_override)
        .from(SIMULATION_SENDER)
        .call()
        .await
        .err()
        .context("simulateHandleOp succeeded, but should always revert")?;
    match contract_error {
        ContractError::TransportError(TransportError::ErrorResp(resp)) => {
            match resp.as_revert_data() {
                Some(err_bytes) => Ok(S::decode_simulate_handle_ops_revert(&err_bytes)?),
                None => Err(TransportError::ErrorResp(resp).into()),
            }
        }
        _ => Err(contract_error.into()),
    }
}

impl TryFrom<ExecutionResultV0_6> for ExecutionResult {
    type Error = anyhow::Error;

    fn try_from(result: ExecutionResultV0_6) -> Result<Self, Self::Error> {
        Ok(ExecutionResult {
            pre_op_gas: result
                .preOpGas
                .try_into()
                .context("preOpGas should fit in u128")?,
            paid: result.paid,
            valid_after: result.validAfter.to::<u64>().into(),
            valid_until: result.validUntil.to::<u64>().into(),
            target_success: result.targetSuccess,
            target_result: result.targetResult,
        })
    }
}

impl From<DepositInfoV0_6> for DepositInfo {
    fn from(deposit_info: DepositInfoV0_6) -> Self {
        Self {
            deposit: U256::from(deposit_info.deposit),
            staked: deposit_info.staked,
            stake: U256::from(deposit_info.stake),
            unstake_delay_sec: deposit_info.unstakeDelaySec,
            withdraw_time: deposit_info.withdrawTime.to(),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy_provider::RootProvider;

    use super::*;
    use crate::ZeroDAGasOracle;

    #[test]
    fn test_decode_handle_ops_revert_return_data_out_of_bounds() {
        let result = EntryPointProvider::<RootProvider<AnyNetwork>, ZeroDAGasOracle>::decode_handle_ops_revert(
            "return data out of bounds",
            &None,
        );
        assert_eq!(result, Some(HandleOpsOut::PostOpRevert));
    }
}
