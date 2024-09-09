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
use alloy_json_rpc::ErrorPayload;
use alloy_primitives::{ruint::UintTryTo, Address, Bytes, U256};
use alloy_provider::Provider as AlloyProvider;
use alloy_rpc_types_eth::{
    state::{AccountOverride, StateOverride},
    BlockId, TransactionRequest,
};
use alloy_sol_types::{ContractError as SolContractError, SolCall, SolError, SolValue};
use alloy_transport::{Transport, TransportError};
use anyhow::Context;
use rundler_contracts::v0_7::{
    DepositInfo as DepositInfoV0_7,
    GetBalances::{self, GetBalancesResult},
    IAggregator,
    IEntryPoint::{FailedOp, IEntryPointErrors, IEntryPointInstance},
    IEntryPointSimulations::{
        self, ExecutionResult as ExecutionResultV0_7, IEntryPointSimulationsInstance,
    },
    UserOpsPerAggregator as UserOpsPerAggregatorV0_7, ValidationResult as ValidationResultV0_7,
    ENTRY_POINT_SIMULATIONS_V0_7_DEPLOYED_BYTECODE,
};
use rundler_types::{
    chain::ChainSpec, v0_7::UserOperation, GasFees, UserOpsPerAggregator, ValidationOutput,
    ValidationRevert,
};

use super::L1GasOracle;
use crate::{
    AggregatorOut, AggregatorSimOut, BundleHandler, DepositInfo, EntryPoint,
    EntryPointProvider as EntryPointProviderTrait, EvmCall, ExecutionResult, HandleOpsOut,
    L1GasProvider, ProviderResult, SignatureAggregator, SimulationProvider,
};

/// Entry point provider for v0.7
pub struct EntryPointProvider<AP, T> {
    i_entry_point: IEntryPointInstance<T, AP>,
    l1_gas_oracle: L1GasOracle,
    max_aggregation_gas: u128,
}

impl<AP, T> EntryPointProvider<AP, T>
where
    T: Transport + Clone,
    AP: AlloyProvider<T>,
{
    /// Create a new `EntryPoint` instance for v0.7
    pub fn new(
        entry_point_address: Address,
        chain_spec: &ChainSpec,
        max_aggregation_gas: u128,
        provider: AP,
    ) -> Self {
        Self {
            i_entry_point: IEntryPointInstance::new(entry_point_address, provider),
            l1_gas_oracle: L1GasOracle::new(chain_spec),
            max_aggregation_gas,
        }
    }
}

#[async_trait::async_trait]
impl<AP, T> EntryPoint for EntryPointProvider<AP, T>
where
    T: Transport + Clone,
    AP: AlloyProvider<T>,
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
impl<AP, T> SignatureAggregator for EntryPointProvider<AP, T>
where
    T: Transport + Clone,
    AP: AlloyProvider<T>,
{
    type UO = UserOperation;

    async fn aggregate_signatures(
        &self,
        aggregator_address: Address,
        ops: Vec<Self::UO>,
    ) -> ProviderResult<Option<Bytes>> {
        let aggregator = IAggregator::new(aggregator_address, self.i_entry_point.provider());

        let packed_ops = ops.into_iter().map(|op| op.pack()).collect();

        let result = aggregator
            .aggregateSignatures(packed_ops)
            .gas(self.max_aggregation_gas)
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
        gas_cap: u128,
    ) -> ProviderResult<AggregatorOut> {
        let aggregator = IAggregator::new(aggregator_address, self.i_entry_point.provider());

        let result = aggregator
            .validateUserOpSignature(user_op.pack())
            .gas(gas_cap)
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
impl<AP, T> BundleHandler for EntryPointProvider<AP, T>
where
    T: Transport + Clone,
    AP: AlloyProvider<T>,
{
    type UO = UserOperation;

    async fn call_handle_ops(
        &self,
        ops_per_aggregator: Vec<UserOpsPerAggregator<UserOperation>>,
        beneficiary: Address,
        gas: u128,
    ) -> ProviderResult<HandleOpsOut> {
        let tx = get_handle_ops_call(&self.i_entry_point, ops_per_aggregator, beneficiary, gas);
        let res = self.i_entry_point.provider().call(&tx).await;

        match res {
            Ok(_) => return Ok(HandleOpsOut::Success),
            Err(TransportError::ErrorResp(resp)) => {
                if let Some(err) = resp.as_decoded_error::<IEntryPointErrors>(false) {
                    match err {
                        IEntryPointErrors::FailedOp(FailedOp { opIndex, reason }) => {
                            match &reason[..4] {
                                // This revert is a bundler issue, not a user op issue, handle it differently
                                "AA95" => {
                                    Err(anyhow::anyhow!("Handle ops called with insufficient gas")
                                        .into())
                                }
                                _ => Ok(HandleOpsOut::FailedOp(
                                    opIndex
                                        .uint_try_to()
                                        .context("returned opIndex out of bounds")?,
                                    reason,
                                )),
                            }
                        }
                        IEntryPointErrors::SignatureValidationFailed(failure) => {
                            Ok(HandleOpsOut::SignatureValidationFailed(failure.aggregator))
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
        gas: u128,
        gas_fees: GasFees,
    ) -> TransactionRequest {
        let tx = get_handle_ops_call(&self.i_entry_point, ops_per_aggregator, beneficiary, gas);
        tx.max_fee_per_gas(gas_fees.max_fee_per_gas)
            .max_priority_fee_per_gas(gas_fees.max_priority_fee_per_gas)
    }
}

#[async_trait::async_trait]
impl<AP, T> L1GasProvider for EntryPointProvider<AP, T>
where
    T: Transport + Clone,
    AP: AlloyProvider<T>,
{
    type UO = UserOperation;

    async fn calc_l1_gas(
        &self,
        entry_point_address: Address,
        user_op: UserOperation,
        gas_price: u128,
    ) -> ProviderResult<u128> {
        let data = self
            .i_entry_point
            .handleOps(vec![user_op.pack()], Address::random())
            .into_transaction_request()
            .input
            .into_input()
            .unwrap();

        self.l1_gas_oracle
            .estimate_l1_gas(
                self.i_entry_point.provider(),
                entry_point_address,
                data,
                gas_price,
            )
            .await
    }
}

#[async_trait::async_trait]
impl<AP, T> SimulationProvider for EntryPointProvider<AP, T>
where
    T: Transport + Clone,
    AP: AlloyProvider<T>,
{
    type UO = UserOperation;

    fn get_tracer_simulate_validation_call(
        &self,
        user_op: Self::UO,
        max_validation_gas: u128,
    ) -> ProviderResult<(TransactionRequest, StateOverride)> {
        let addr = *self.i_entry_point.address();
        let pvg: u128 = user_op
            .pre_verification_gas
            .uint_try_to()
            .context("pre verification gas out of bounds")?;
        let mut override_ep = StateOverride::default();
        add_simulations_override(&mut override_ep, addr);

        let ep_simulations =
            IEntryPointSimulationsInstance::new(addr, self.i_entry_point.provider());

        let call = ep_simulations
            .simulateValidation(user_op.pack())
            .gas(max_validation_gas + pvg)
            .into_transaction_request();

        Ok((call, override_ep))
    }

    async fn simulate_validation(
        &self,
        user_op: Self::UO,
        max_validation_gas: u128,
        block_id: Option<BlockId>,
    ) -> ProviderResult<Result<ValidationOutput, ValidationRevert>> {
        let (tx, overrides) =
            self.get_tracer_simulate_validation_call(user_op, max_validation_gas)?;
        let mut call = self.i_entry_point.provider().call(&tx);
        if let Some(block_id) = block_id {
            call = call.block(block_id);
        }

        let result = call.overrides(&overrides).await;

        match result {
            Ok(output) => {
                let out = ValidationResultV0_7::abi_decode(&output, false)
                    .context("failed to decode validation result")?;
                Ok(Ok(out.into()))
            }
            Err(TransportError::ErrorResp(resp)) => Ok(Err(decode_validation_revert(resp))),
            Err(error) => Err(error.into()),
        }
    }

    fn get_simulate_handle_op_call(
        &self,
        op: Self::UO,
        mut state_override: StateOverride,
    ) -> EvmCall {
        add_simulations_override(&mut state_override, *self.i_entry_point.address());

        let data = IEntryPointSimulations::simulateHandleOpCall {
            op: op.pack(),
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
        gas: u128,
        mut state_override: StateOverride,
    ) -> ProviderResult<Result<ExecutionResult, ValidationRevert>> {
        add_simulations_override(&mut state_override, *self.i_entry_point.address());
        let ep_simulations = IEntryPointSimulations::new(
            *self.i_entry_point.address(),
            self.i_entry_point.provider(),
        );
        let res = ep_simulations
            .simulateHandleOp(op.pack(), target, target_call_data)
            .block(block_id)
            .gas(gas)
            .state(state_override)
            .call()
            .await;

        match res {
            Ok(output) => Ok(Ok(output._0.into())),
            Err(ContractError::TransportError(TransportError::ErrorResp(resp))) => {
                Ok(Err(decode_validation_revert(resp)))
            }
            Err(error) => Err(error.into()),
        }
    }

    fn decode_simulate_handle_ops_revert(
        revert_data: ErrorPayload,
    ) -> Result<ExecutionResult, ValidationRevert> {
        // v0.7 doesn't encode execution results in the revert data
        // so we can just decode as validation revert
        Err(decode_validation_revert(revert_data))
    }

    fn simulation_should_revert(&self) -> bool {
        false
    }
}

impl<AP, T> EntryPointProviderTrait<UserOperation> for EntryPointProvider<AP, T>
where
    T: Transport + Clone,
    AP: AlloyProvider<T>,
{
}

fn add_simulations_override(state_override: &mut StateOverride, addr: Address) {
    state_override.insert(
        addr,
        AccountOverride {
            code: Some(ENTRY_POINT_SIMULATIONS_V0_7_DEPLOYED_BYTECODE.clone()),
            ..Default::default()
        },
    );
}

fn get_handle_ops_call<AP: AlloyProvider<T>, T: Transport + Clone>(
    entry_point: &IEntryPointInstance<T, AP>,
    ops_per_aggregator: Vec<UserOpsPerAggregator<UserOperation>>,
    beneficiary: Address,
    gas: u128,
) -> TransactionRequest {
    let mut ops_per_aggregator: Vec<UserOpsPerAggregatorV0_7> = ops_per_aggregator
        .into_iter()
        .map(|uoa| UserOpsPerAggregatorV0_7 {
            userOps: uoa.user_ops.into_iter().map(|op| op.pack()).collect(),
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
    }
}

fn decode_validation_revert(err: ErrorPayload) -> ValidationRevert {
    if let Some(rev) = err.as_decoded_error::<SolContractError<IEntryPointErrors>>(false) {
        match rev {
            SolContractError::CustomError(IEntryPointErrors::FailedOp(f)) => f.into(),
            SolContractError::CustomError(IEntryPointErrors::FailedOpWithRevert(f)) => f.into(),
            SolContractError::CustomError(IEntryPointErrors::SignatureValidationFailed(f)) => {
                ValidationRevert::EntryPoint(format!(
                    "Aggregator signature validation failed: {}",
                    f.aggregator
                ))
            }
            SolContractError::Revert(r) => r.into(),
            SolContractError::Panic(p) => p.into(),
        }
    } else {
        ValidationRevert::Unknown(err.as_revert_data().unwrap_or_default())
    }
}

impl From<DepositInfoV0_7> for DepositInfo {
    fn from(deposit_info: DepositInfoV0_7) -> Self {
        Self {
            deposit: deposit_info.deposit,
            staked: deposit_info.staked,
            stake: UintTryTo::<u128>::uint_try_to(&deposit_info.stake).unwrap(),
            unstake_delay_sec: deposit_info.unstakeDelaySec,
            withdraw_time: UintTryTo::<u64>::uint_try_to(&deposit_info.withdrawTime).unwrap(),
        }
    }
}

impl From<ExecutionResultV0_7> for ExecutionResult {
    fn from(result: ExecutionResultV0_7) -> Self {
        let account = rundler_types::parse_validation_data(result.accountValidationData);
        let paymaster = rundler_types::parse_validation_data(result.paymasterValidationData);
        let intersect_range = account
            .valid_time_range()
            .intersect(paymaster.valid_time_range());

        ExecutionResult {
            pre_op_gas: result.preOpGas,
            paid: result.paid,
            valid_after: intersect_range.valid_after,
            valid_until: intersect_range.valid_until,
            target_success: result.targetSuccess,
            target_result: result.targetResult,
        }
    }
}
