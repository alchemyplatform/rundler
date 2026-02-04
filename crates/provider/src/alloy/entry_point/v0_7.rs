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
    BlockId,
    state::{AccountOverride, StateOverride},
};
use alloy_sol_types::{ContractError as SolContractError, SolInterface, SolValue};
use alloy_transport::TransportError;
use anyhow::Context;
use rundler_contracts::{
    v0_7::{
        DepositInfo as DepositInfoV0_7, ENTRY_POINT_SIMULATIONS_V0_7_DEPLOYED_BYTECODE,
        GetEntryPointBalances, IAggregator,
        IEntryPoint::{
            FailedOp, FailedOpWithRevert, IEntryPointCalls, IEntryPointErrors, IEntryPointInstance,
        },
        IEntryPointSimulations::{
            self, ExecutionResult as ExecutionResultV0_7, IEntryPointSimulationsInstance,
        },
        UserOpsPerAggregator as UserOpsPerAggregatorV0_7, ValidationResult as ValidationResultV0_7,
    },
    v0_8::ENTRY_POINT_SIMULATIONS_V0_8_DEPLOYED_BYTECODE,
    v0_9::ENTRY_POINT_SIMULATIONS_V0_9_DEPLOYED_BYTECODE,
};
use rundler_types::{
    EntryPointVersion, GasFees, UserOperation as _, UserOpsPerAggregator, ValidationOutput,
    ValidationRevert,
    authorization::Eip7702Auth,
    chain::ChainSpec,
    constants::SIMULATION_SENDER,
    da::{DAGasBlockData, DAGasData},
    v0_7::{UserOperation, UserOperationBuilder, UserOperationRequiredFields},
};
use rundler_utils::authorization_utils;
use tracing::instrument;

use crate::{
    AggregatorOut, AggregatorSimOut, AlloyProvider, BlockHashOrNumber, BundleHandler, DAGasOracle,
    DAGasProvider, DepositInfo, EntryPoint, EntryPointProvider as EntryPointProviderTrait,
    ExecutionResult, HandleOpsOut, ProviderResult, SignatureAggregator, SimulationProvider,
    TransactionRequest,
};

/// Entry point provider for v0.7
#[derive(Clone)]
pub struct EntryPointProvider<AP, D> {
    i_entry_point: IEntryPointInstance<AP, AnyNetwork>,
    da_gas_oracle: D,
    max_verification_gas: u64,
    max_simulate_handle_ops_gas: u64,
    max_gas_estimation_gas: u64,
    max_aggregation_gas: u64,
    chain_spec: ChainSpec,
    ep_version: EntryPointVersion,
}

impl<AP, D> EntryPointProvider<AP, D>
where
    AP: AlloyProvider + Clone,
{
    /// Create a new `EntryPoint` instance for v0.7 ABI
    /// PANICS if entry point version is < v0.7
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_spec: ChainSpec,
        ep_version: EntryPointVersion,
        max_verification_gas: u64,
        max_simulate_handle_ops_gas: u64,
        max_gas_estimation_gas: u64,
        max_aggregation_gas: u64,
        provider: AP,
        da_gas_oracle: D,
    ) -> Self {
        if ep_version < EntryPointVersion::V0_7 {
            panic!("entry point version must be >= v0.7")
        }

        Self {
            i_entry_point: IEntryPointInstance::new(
                chain_spec.entry_point_address(ep_version),
                provider.clone(),
            ),
            da_gas_oracle,
            max_verification_gas,
            max_simulate_handle_ops_gas,
            max_gas_estimation_gas,
            max_aggregation_gas,
            chain_spec,
            ep_version,
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
        EntryPointVersion::V0_7
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

    #[instrument(skip_all)]
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

        let packed_ops = ops.into_iter().map(|op| op.pack()).collect();

        let result = aggregator
            .aggregateSignatures(packed_ops)
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

    #[instrument(skip_all)]
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
            .validateUserOpSignature(user_op.pack())
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
        mut ops_per_aggregator: Vec<UserOpsPerAggregator<UserOperation>>,
        sender_eoa: Address,
        gas_limit: u64,
        gas_fees: GasFees,
        proxy: Option<Address>,
        validation_only: bool,
    ) -> ProviderResult<HandleOpsOut> {
        let mut expected_failure_index: Option<usize> = None;
        if validation_only && proxy.is_none() {
            expected_failure_index = Some(
                ops_per_aggregator
                    .iter()
                    .map(|agg| agg.user_ops.len())
                    .sum::<usize>(),
            );

            let Some(last_agg) = ops_per_aggregator.last_mut() else {
                return Err(anyhow::anyhow!("bundle must have at least one aggregator").into());
            };

            last_agg.user_ops.push(
                // Trigger an AA10 error
                UserOperationBuilder::new(
                    &self.chain_spec,
                    self.ep_version,
                    UserOperationRequiredFields {
                        sender: self.chain_spec.entry_point_address(self.ep_version),
                        nonce: U256::ZERO,
                        call_data: Bytes::new(),
                        call_gas_limit: 0,
                        verification_gas_limit: 0,
                        pre_verification_gas: 0,
                        max_fee_per_gas: 0,
                        max_priority_fee_per_gas: 0,
                        signature: Bytes::new(),
                    },
                )
                .factory(
                    self.chain_spec.entry_point_address(self.ep_version),
                    Bytes::new(),
                )
                .build(),
            );
        }

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
                let ret = Self::decode_handle_ops_revert(&resp.message, &resp.as_revert_data())
                    .ok_or_else(|| TransportError::ErrorResp(resp))?;

                let Some(expected_failure_index) = expected_failure_index else {
                    return Ok(ret);
                };

                match ret {
                    HandleOpsOut::Success => {
                        tracing::error!(
                            "v0.7 bundle validation should always fail due to injected op"
                        );
                        Err(anyhow::anyhow!(
                            "v0.7 bundle validation should always fail due to injected op"
                        )
                        .into())
                    }
                    HandleOpsOut::FailedOp(index, message) => {
                        if index == expected_failure_index {
                            Ok(HandleOpsOut::Success)
                        } else {
                            Ok(HandleOpsOut::FailedOp(index, message))
                        }
                    }
                    _ => Ok(ret),
                }
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
        _message: &str,
        revert_data: &Option<Bytes>,
    ) -> Option<HandleOpsOut> {
        decode_handle_ops_revert(revert_data)
    }

    fn decode_ops_from_calldata(
        chain_spec: &ChainSpec,
        address: Address,
        calldata: &Bytes,
        auth_list: &[Eip7702Auth],
    ) -> Vec<UserOpsPerAggregator<UserOperation>> {
        decode_ops_from_calldata(chain_spec, address, calldata, auth_list)
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

        let txn_req = self
            .i_entry_point
            .handleOps(vec![user_op.pack()], Address::random())
            .from(SIMULATION_SENDER)
            .into_transaction_request();

        let data = txn_req.inner.input.into_input().unwrap();

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
        user_op: Self::UO,
    ) -> ProviderResult<(TransactionRequest, StateOverride)> {
        let addr = *self.i_entry_point.address();
        let da_gas = user_op
            .pre_verification_da_gas_limit(&self.chain_spec, Some(1))
            .try_into()
            .unwrap_or(u64::MAX);

        let mut override_ep = StateOverride::default();
        add_simulations_override(
            self.get_simulations_bytecode().clone(),
            &mut override_ep,
            addr,
        );

        add_authorization_tuple(
            user_op.sender(),
            user_op.authorization_tuple(),
            &mut override_ep,
        );

        let ep_simulations =
            IEntryPointSimulationsInstance::new(addr, self.i_entry_point.provider());

        let call = ep_simulations
            .simulateValidation(user_op.pack())
            .gas(self.max_verification_gas.saturating_add(da_gas))
            .from(SIMULATION_SENDER)
            .into_transaction_request();

        Ok((call.inner, override_ep))
    }

    #[instrument(skip_all)]
    async fn simulate_validation(
        &self,
        user_op: Self::UO,
        block_id: Option<BlockId>,
    ) -> ProviderResult<Result<ValidationOutput, ValidationRevert>> {
        let (tx, overrides) = self.get_tracer_simulate_validation_call(user_op)?;
        let mut call = self.i_entry_point.provider().call(tx.into());
        if let Some(block_id) = block_id {
            call = call.block(block_id);
        }

        let result = call.overrides(overrides).await;

        match result {
            Ok(output) => {
                let out = ValidationResultV0_7::abi_decode(&output)
                    .context("failed to decode validation result")?;
                Ok(Ok(out.try_into().map_err(anyhow::Error::msg)?))
            }
            Err(TransportError::ErrorResp(resp)) => {
                if let Some(revert) = resp.as_revert_data() {
                    Ok(Err(decode_validation_revert(&revert)))
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
        simulate_handle_op_inner(
            &self.chain_spec,
            self.get_simulations_bytecode().clone(),
            self.max_simulate_handle_ops_gas,
            &self.i_entry_point,
            op,
            target,
            target_call_data,
            block_id,
            state_override,
            false,
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
        simulate_handle_op_inner(
            &self.chain_spec,
            self.get_simulations_bytecode().clone(),
            self.max_gas_estimation_gas,
            &self.i_entry_point,
            op,
            target,
            target_call_data,
            block_id,
            state_override,
            true,
        )
        .await
    }

    fn decode_simulate_handle_ops_revert(
        revert_data: &Bytes,
    ) -> ProviderResult<Result<ExecutionResult, ValidationRevert>> {
        // v0.7 doesn't encode execution results in the revert data
        // so we can just decode as validation revert
        Ok(Err(decode_validation_revert(revert_data)))
    }

    fn simulation_should_revert(&self) -> bool {
        false
    }

    fn get_simulations_bytecode(&self) -> &Bytes {
        match self.ep_version {
            EntryPointVersion::V0_6 => {
                unreachable!("v0.7 entry point ABI created with v0.6 entry point version")
            }
            EntryPointVersion::V0_7 => &ENTRY_POINT_SIMULATIONS_V0_7_DEPLOYED_BYTECODE,
            EntryPointVersion::V0_8 => &ENTRY_POINT_SIMULATIONS_V0_8_DEPLOYED_BYTECODE,
            EntryPointVersion::V0_9 => &ENTRY_POINT_SIMULATIONS_V0_9_DEPLOYED_BYTECODE,
        }
    }
}

impl<AP, D> EntryPointProviderTrait<UserOperation> for EntryPointProvider<AP, D>
where
    AP: AlloyProvider,
    D: DAGasOracle,
{
}

fn add_simulations_override(
    simulations_bytecode: Bytes,
    state_override: &mut StateOverride,
    addr: Address,
) {
    // Do nothing if the caller has already overridden the entry point code.
    // We'll trust they know what they're doing and not replace their code.
    // This is needed for call gas estimation, where the entry point is
    // replaced with a proxy and the simulations bytecode is elsewhere.
    state_override
        .entry(addr)
        .or_insert_with(|| AccountOverride {
            code: Some(simulations_bytecode),
            ..Default::default()
        });
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
    let mut authorization_list: Vec<SignedAuthorization> = vec![];
    let mut ops_per_aggregator: Vec<UserOpsPerAggregatorV0_7> = ops_per_aggregator
        .into_iter()
        .map(|uoa| UserOpsPerAggregatorV0_7 {
            userOps: uoa
                .user_ops
                .into_iter()
                .map(|op| {
                    if let Some(authorization) = op.authorization_tuple() {
                        authorization_list.push(SignedAuthorization::from(authorization.clone()));
                    }
                    op.pack()
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

    if !authorization_list.is_empty() {
        txn_request = txn_request.with_authorization_list(authorization_list);
    }
    if let Some(proxy) = proxy {
        txn_request = txn_request.to(proxy);
    }

    txn_request
}

/// Decodes raw validation revert bytes from a v0.7 entry point
pub fn decode_validation_revert(err_bytes: &Bytes) -> ValidationRevert {
    if let Ok(rev) = SolContractError::<IEntryPointErrors>::abi_decode(err_bytes) {
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
        ValidationRevert::Unknown(err_bytes.clone())
    }
}

/// Decode user ops from calldata
pub fn decode_ops_from_calldata(
    chain_spec: &ChainSpec,
    address: Address,
    calldata: &Bytes,
    tx_auth_list: &[Eip7702Auth],
) -> Vec<UserOpsPerAggregator<UserOperation>> {
    let entry_point_calls = match IEntryPointCalls::abi_decode(calldata) {
        Ok(entry_point_calls) => entry_point_calls,
        Err(_) => return vec![],
    };
    let Some(ep_version) = chain_spec.entry_point_version(address) else {
        return vec![];
    };

    match entry_point_calls {
        IEntryPointCalls::handleOps(handle_ops_call) => {
            let ops = handle_ops_call
                .ops
                .into_iter()
                .filter_map(|op| {
                    let maybe_auth = tx_auth_list
                        .iter()
                        .find(|auth| auth.recover_authority().is_ok_and(|addr| addr == op.sender))
                        .cloned();

                    UserOperationBuilder::from_packed(op, chain_spec, ep_version, maybe_auth)
                        .ok()
                        .map(|uo| uo.build())
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
                        .filter_map(|op| {
                            let maybe_auth = tx_auth_list
                                .iter()
                                .find(|auth| {
                                    auth.recover_authority().is_ok_and(|addr| addr == op.sender)
                                })
                                .cloned();

                            UserOperationBuilder::from_packed(
                                op, chain_spec, ep_version, maybe_auth,
                            )
                            .ok()
                            .map(|uo| uo.build())
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

/// Decode the revert data from a call to `handleOps` for v0.7+
pub fn decode_handle_ops_revert(revert_data: &Option<Bytes>) -> Option<HandleOpsOut> {
    let Some(revert_data) = revert_data else {
        return None;
    };

    if let Ok(err) = IEntryPointErrors::abi_decode(revert_data) {
        let ret = match err {
            IEntryPointErrors::FailedOp(FailedOp { opIndex, reason }) => {
                HandleOpsOut::FailedOp(opIndex.try_into().unwrap_or(usize::MAX), reason)
            }
            IEntryPointErrors::FailedOpWithRevert(FailedOpWithRevert {
                opIndex,
                reason,
                inner,
            }) => HandleOpsOut::FailedOp(
                opIndex.try_into().unwrap_or(usize::MAX),
                format!("{}:{}", reason, inner),
            ),
            IEntryPointErrors::SignatureValidationFailed(failure) => {
                HandleOpsOut::SignatureValidationFailed(failure.aggregator)
            }
        };
        Some(ret)
    } else {
        Some(HandleOpsOut::Revert(revert_data.clone()))
    }
}

#[allow(clippy::too_many_arguments)]
async fn simulate_handle_op_inner<AP: AlloyProvider>(
    chain_spec: &ChainSpec,
    simulations_bytecode: Bytes,
    execution_gas_limit: u64,
    entry_point: &IEntryPointInstance<AP, AnyNetwork>,
    op: UserOperation,
    target: Address,
    target_call_data: Bytes,
    block_id: BlockId,
    mut state_override: StateOverride,
    skip_post_op: bool,
) -> ProviderResult<Result<ExecutionResult, ValidationRevert>> {
    let da_gas = op
        .pre_verification_da_gas_limit(chain_spec, Some(1))
        .try_into()
        .unwrap_or(u64::MAX);

    add_simulations_override(
        simulations_bytecode,
        &mut state_override,
        *entry_point.address(),
    );

    add_authorization_tuple(op.sender(), op.authorization_tuple(), &mut state_override);

    let ep_simulations =
        IEntryPointSimulations::new(*entry_point.address(), entry_point.provider());

    let res = if skip_post_op {
        ep_simulations
            .simulateHandleOpNoPostOp(op.pack(), target, target_call_data)
            .block(block_id)
            .gas(execution_gas_limit.saturating_add(da_gas))
            .state(state_override)
            .from(SIMULATION_SENDER)
            .call()
            .await
    } else {
        ep_simulations
            .simulateHandleOp(op.pack(), target, target_call_data)
            .block(block_id)
            .gas(execution_gas_limit.saturating_add(da_gas))
            .state(state_override)
            .from(SIMULATION_SENDER)
            .call()
            .await
    };

    match res {
        Ok(output) => Ok(Ok(output.try_into()?)),
        Err(ContractError::TransportError(TransportError::ErrorResp(resp))) => {
            if let Some(revert) = resp.as_revert_data() {
                Ok(Err(decode_validation_revert(&revert)))
            } else {
                Err(TransportError::ErrorResp(resp).into())
            }
        }
        Err(error) => Err(error.into()),
    }
}

impl From<DepositInfoV0_7> for DepositInfo {
    fn from(deposit_info: DepositInfoV0_7) -> Self {
        Self {
            deposit: deposit_info.deposit,
            staked: deposit_info.staked,
            stake: U256::from(deposit_info.stake),
            unstake_delay_sec: deposit_info.unstakeDelaySec,
            withdraw_time: deposit_info.withdrawTime.to(),
        }
    }
}

impl TryFrom<ExecutionResultV0_7> for ExecutionResult {
    type Error = anyhow::Error;

    fn try_from(result: ExecutionResultV0_7) -> Result<Self, Self::Error> {
        let account = rundler_types::parse_validation_data(result.accountValidationData);
        let paymaster = rundler_types::parse_validation_data(result.paymasterValidationData);
        let intersect_range = account
            .valid_time_range()
            .intersect(paymaster.valid_time_range());

        Ok(ExecutionResult {
            pre_op_gas: result
                .preOpGas
                .try_into()
                .context("preOpGas should fit in u128")?,
            paid: result.paid,
            valid_after: intersect_range.valid_after,
            valid_until: intersect_range.valid_until,
            target_success: result.targetSuccess,
            target_result: result.targetResult,
        })
    }
}

fn add_authorization_tuple(
    sender: Address,
    authorization: Option<&Eip7702Auth>,
    state_override: &mut StateOverride,
) {
    if let Some(authorization) = authorization {
        authorization_utils::apply_7702_overrides(state_override, sender, authorization.address);
    }
}
