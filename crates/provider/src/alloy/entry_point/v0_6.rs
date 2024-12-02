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
use alloy_provider::{network::TransactionBuilder7702, Provider as AlloyProvider};
use alloy_rpc_types_eth::{state::StateOverride, BlockId, TransactionRequest};
use alloy_sol_types::{ContractError as SolContractError, SolCall, SolError, SolInterface};
use alloy_transport::{Transport, TransportError};
use anyhow::Context;
use rundler_contracts::v0_6::{
    DepositInfo as DepositInfoV0_6,
    GetBalances::{self, GetBalancesResult},
    IAggregator,
    IEntryPoint::{
        self, ExecutionResult as ExecutionResultV0_6, FailedOp, IEntryPointErrors,
        IEntryPointInstance,
    },
    UserOperation as ContractUserOperation, UserOpsPerAggregator as UserOpsPerAggregatorV0_6,
};
use rundler_types::{
    chain::ChainSpec,
    da::{DAGasBlockData, DAGasUOData},
    v0_6::UserOperation,
    GasFees, UserOperation as _, UserOpsPerAggregator, ValidationOutput, ValidationRevert,
};

use crate::{
    AggregatorOut, AggregatorSimOut, BlockHashOrNumber, BundleHandler, DAGasOracle, DAGasProvider,
    DepositInfo, EntryPoint, EntryPointProvider as EntryPointProviderTrait, EvmCall,
    ExecutionResult, HandleOpsOut, ProviderResult, SignatureAggregator, SimulationProvider,
};

/// Entry point provider for v0.6
#[derive(Clone)]
pub struct EntryPointProvider<AP, T, D> {
    i_entry_point: IEntryPointInstance<T, AP>,
    da_gas_oracle: D,
    max_verification_gas: u64,
    max_simulate_handle_op_gas: u64,
    max_aggregation_gas: u64,
    chain_spec: ChainSpec,
}

impl<AP, T, D> EntryPointProvider<AP, T, D>
where
    T: Transport + Clone,
    AP: AlloyProvider<T> + Clone,
    D: DAGasOracle,
{
    /// Create a new `EntryPoint` instance for v0.6
    pub fn new(
        chain_spec: ChainSpec,
        max_verification_gas: u64,
        max_simulate_handle_op_gas: u64,
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
            max_aggregation_gas,
            chain_spec,
        }
    }
}

#[async_trait::async_trait]
impl<AP, T, D> EntryPoint for EntryPointProvider<AP, T, D>
where
    T: Transport + Clone,
    AP: AlloyProvider<T>,
    D: Send + Sync,
{
    fn address(&self) -> &Address {
        self.i_entry_point.address()
    }

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

        Ok(ret._0)
    }

    async fn get_deposit_info(&self, address: Address) -> ProviderResult<DepositInfo> {
        self.i_entry_point
            .getDepositInfo(address)
            .call()
            .await
            .map_err(Into::into)
            .map(|r| r.info.into())
    }

    async fn get_balances(&self, addresses: Vec<Address>) -> ProviderResult<Vec<U256>> {
        let provider = self.i_entry_point.provider();
        let call = GetBalances::deploy_builder(provider, *self.address(), addresses)
            .into_transaction_request();
        let out = provider
            .call(&call)
            .await
            .err()
            .context("get balances call should revert")?;
        let out = GetBalancesResult::abi_decode(
            &out.as_error_resp()
                .context("get balances call should revert")?
                .as_revert_data()
                .context("should get revert data from get balances call")?,
            false,
        )
        .context("should decode revert data from get balances call")?;

        Ok(out.balances)
    }
}

#[async_trait::async_trait]
impl<AP, T, D> SignatureAggregator for EntryPointProvider<AP, T, D>
where
    T: Transport + Clone,
    AP: AlloyProvider<T>,
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
            .map(|op: &UserOperation| {
                op.pre_verification_da_gas_limit(&self.chain_spec, Some(ops_len))
            })
            .sum::<u128>()
            .try_into()
            .unwrap_or(u64::MAX);
        let ops: Vec<ContractUserOperation> = ops.into_iter().map(Into::into).collect();

        let result = aggregator
            .aggregateSignatures(ops)
            .gas(self.max_aggregation_gas.saturating_add(da_gas))
            .call()
            .await;

        match result {
            Ok(ret) => Ok(Some(ret.aggregatedSignature)),
            Err(ContractError::TransportError(TransportError::ErrorResp(resp))) => {
                if resp.as_revert_data().is_some() {
                    Ok(None)
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
        let da_gas: u64 = user_op
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
                signature: ret.sigForUserOp,
            })),
            Err(ContractError::TransportError(TransportError::ErrorResp(resp))) => {
                if resp.as_revert_data().is_some() {
                    Ok(AggregatorOut::ValidationReverted)
                } else {
                    Err(TransportError::ErrorResp(resp).into())
                }
            }
            Err(error) => Err(error.into()),
        }
    }
}

#[async_trait::async_trait]
impl<AP, T, D> BundleHandler for EntryPointProvider<AP, T, D>
where
    T: Transport + Clone,
    AP: AlloyProvider<T>,
    D: Send + Sync,
{
    type UO = UserOperation;

    async fn call_handle_ops(
        &self,
        ops_per_aggregator: Vec<UserOpsPerAggregator<UserOperation>>,
        beneficiary: Address,
        gas_limit: Option<u64>,
    ) -> ProviderResult<HandleOpsOut> {
        let gas_limit = gas_limit.unwrap_or(self.max_simulate_handle_op_gas);
        let tx = get_handle_ops_call(
            &self.i_entry_point,
            ops_per_aggregator,
            beneficiary,
            gas_limit,
        );
        let res = self.i_entry_point.provider().call(&tx).await;

        match res {
            Ok(_) => return Ok(HandleOpsOut::Success),
            Err(TransportError::ErrorResp(resp)) => {
                if let Some(err) =
                    resp.as_decoded_error::<SolContractError<IEntryPointErrors>>(false)
                {
                    match err {
                        SolContractError::CustomError(IEntryPointErrors::FailedOp(FailedOp {
                            opIndex,
                            reason,
                        })) => {
                            match &reason[..4] {
                                // This revert is a bundler issue, not a user op issue, handle it differently
                                "AA95" => {
                                    Err(anyhow::anyhow!("Handle ops called with insufficient gas")
                                        .into())
                                }
                                _ => Ok(HandleOpsOut::FailedOp(
                                    opIndex
                                        .try_into()
                                        .context("returned opIndex out of bounds")?,
                                    reason,
                                )),
                            }
                        }
                        SolContractError::CustomError(
                            IEntryPointErrors::SignatureValidationFailed(err),
                        ) => Ok(HandleOpsOut::SignatureValidationFailed(err.aggregator)),
                        SolContractError::Revert(r) => {
                            // Special handling for a bug in the 0.6 entry point contract to detect the bug where
                            // the `returndatacopy` opcode reverts due to a postOp revert and the revert data is too short.
                            // See https://github.com/eth-infinitism/account-abstraction/pull/325 for more details.
                            // NOTE: this error message is copied directly from Geth and assumes it will not change.
                            if r.reason.contains("return data out of bounds") {
                                Ok(HandleOpsOut::PostOpRevert)
                            } else {
                                Err(TransportError::ErrorResp(resp).into())
                            }
                        }
                        _ => Err(TransportError::ErrorResp(resp).into()),
                    }
                } else {
                    Err(TransportError::ErrorResp(resp).into())
                }
            }
            Err(error) => Err(error.into()),
        }
    }

    fn get_send_bundle_transaction(
        &self,
        ops_per_aggregator: Vec<UserOpsPerAggregator<UserOperation>>,
        beneficiary: Address,
        gas_limit: u64,
        gas_fees: GasFees,
    ) -> TransactionRequest {
        get_handle_ops_call(
            &self.i_entry_point,
            ops_per_aggregator,
            beneficiary,
            gas_limit,
        )
        .max_fee_per_gas(gas_fees.max_fee_per_gas)
        .max_priority_fee_per_gas(gas_fees.max_priority_fee_per_gas)
    }
}

#[async_trait::async_trait]
impl<AP, T, D> DAGasProvider for EntryPointProvider<AP, T, D>
where
    T: Transport + Clone,
    AP: AlloyProvider<T>,
    D: DAGasOracle,
{
    type UO = UserOperation;

    async fn calc_da_gas(
        &self,
        user_op: UserOperation,
        block: BlockHashOrNumber,
        gas_price: u128,
    ) -> ProviderResult<(u128, DAGasUOData, DAGasBlockData)> {
        let data = self
            .i_entry_point
            .handleOps(vec![user_op.into()], Address::random())
            .into_transaction_request()
            .input
            .into_input()
            .unwrap();

        let bundle_data =
            super::max_bundle_transaction_data(*self.i_entry_point.address(), data, gas_price);

        self.da_gas_oracle
            .estimate_da_gas(bundle_data, *self.i_entry_point.address(), block, gas_price)
            .await
    }
}

#[async_trait::async_trait]
impl<AP, T, D> SimulationProvider for EntryPointProvider<AP, T, D>
where
    T: Transport + Clone,
    AP: AlloyProvider<T>,
    D: Send + Sync,
{
    type UO = UserOperation;

    fn get_tracer_simulate_validation_call(
        &self,
        user_op: UserOperation,
    ) -> ProviderResult<(TransactionRequest, StateOverride)> {
        let da_gas: u64 = user_op
            .pre_verification_da_gas_limit(&self.chain_spec, Some(1))
            .try_into()
            .unwrap_or(u64::MAX);
        let call = self
            .i_entry_point
            .simulateValidation(user_op.into())
            .gas(self.max_verification_gas.saturating_add(da_gas))
            .into_transaction_request();
        Ok((call, StateOverride::default()))
    }

    async fn simulate_validation(
        &self,
        user_op: UserOperation,
        block_id: Option<BlockId>,
    ) -> ProviderResult<Result<ValidationOutput, ValidationRevert>> {
        let da_gas: u64 = user_op
            .pre_verification_da_gas_limit(&self.chain_spec, Some(1))
            .try_into()
            .unwrap_or(u64::MAX);
        let blockless = self
            .i_entry_point
            .simulateValidation(user_op.into())
            .gas(self.max_verification_gas.saturating_add(da_gas));
        let call = match block_id {
            Some(block_id) => blockless.block(block_id),
            None => blockless,
        };

        match call.call().await {
            Ok(_) => Err(anyhow::anyhow!("simulateValidation should always revert"))?,
            Err(ContractError::TransportError(TransportError::ErrorResp(resp))) => {
                if let Some(err) =
                    resp.as_decoded_error::<SolContractError<IEntryPointErrors>>(false)
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

    fn get_simulate_handle_op_call(&self, op: Self::UO, state_override: StateOverride) -> EvmCall {
        let data = IEntryPoint::simulateHandleOpCall {
            op: op.into(),
            target: Address::ZERO,
            targetCallData: Bytes::new(),
        }
        .abi_encode()
        .into();

        EvmCall {
            to: *self.i_entry_point.address(),
            data,
            value: U256::ZERO,
            state_override,
        }
    }

    async fn simulate_handle_op(
        &self,
        op: Self::UO,
        target: Address,
        target_call_data: Bytes,
        block_id: BlockId,
        state_override: StateOverride,
    ) -> ProviderResult<Result<ExecutionResult, ValidationRevert>> {
        let da_gas: u64 = op
            .pre_verification_da_gas_limit(&self.chain_spec, Some(1))
            .try_into()
            .unwrap_or(u64::MAX);
        let authorization_tuple = op.authorization_tuple.clone();

        let mut request = self
            .i_entry_point
            .simulateHandleOp(op.into(), target, target_call_data)
            .block(block_id)
            .gas(self.max_simulate_handle_op_gas.saturating_add(da_gas))
            .state(state_override);

        request = request.map(|mut req| {
            if let Some(authorization) = authorization_tuple {
                req.set_authorization_list(vec![SignedAuthorization::from(authorization.clone())]);
            }
            req
        });

        let contract_error = request
            .call()
            .await
            .err()
            .context("simulateHandleOp succeeded, but should always revert")?;

        match contract_error {
            ContractError::TransportError(TransportError::ErrorResp(resp)) => {
                match resp.as_revert_data() {
                    Some(err_bytes) => Ok(Self::decode_simulate_handle_ops_revert(&err_bytes)?),
                    None => Ok(Err(ValidationRevert::Unknown(Bytes::default()))),
                }
            }
            _ => Err(contract_error.into()),
        }
    }

    fn decode_simulate_handle_ops_revert(
        payload: &Bytes,
    ) -> ProviderResult<Result<ExecutionResult, ValidationRevert>> {
        let ret = if let Ok(err) = SolContractError::<IEntryPointErrors>::abi_decode(payload, false)
        {
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
}

impl<AP, T, D> EntryPointProviderTrait<UserOperation> for EntryPointProvider<AP, T, D>
where
    T: Transport + Clone,
    AP: AlloyProvider<T>,
    D: DAGasOracle,
{
}

fn get_handle_ops_call<AP: AlloyProvider<T>, T: Transport + Clone>(
    entry_point: &IEntryPointInstance<T, AP>,
    ops_per_aggregator: Vec<UserOpsPerAggregator<UserOperation>>,
    beneficiary: Address,
    gas: u64,
) -> TransactionRequest {
    let mut authorization_list: Vec<SignedAuthorization> = vec![];

    let mut ops_per_aggregator: Vec<UserOpsPerAggregatorV0_6> = ops_per_aggregator
        .into_iter()
        .map(|uoa| UserOpsPerAggregatorV0_6 {
            userOps: uoa
                .user_ops
                .into_iter()
                .map(|op| {
                    if let Some(authorization) = &op.authorization_tuple {
                        authorization_list.push(SignedAuthorization::from(authorization.clone()))
                    }
                    op.into()
                })
                .collect(),
            aggregator: uoa.aggregator,
            signature: uoa.signature,
        })
        .collect();
    if ops_per_aggregator.len() == 1 && ops_per_aggregator[0].aggregator == Address::ZERO {
        entry_point
            .handleOps(ops_per_aggregator.swap_remove(0).userOps, beneficiary)
            .gas(gas)
            .into_transaction_request()
    } else {
        entry_point
            .handleAggregatedOps(ops_per_aggregator, beneficiary)
            .gas(gas)
            .into_transaction_request()
            .with_authorization_list(authorization_list)
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
