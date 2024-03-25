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
    providers::{Middleware, RawCall},
    types::{
        spoof, transaction::eip2718::TypedTransaction, Address, BlockId, Bytes,
        Eip1559TransactionRequest, H160, H256, U256,
    },
    utils::hex,
};
use rundler_types::{
    contracts::{
        arbitrum::node_interface::NodeInterface,
        optimism::gas_price_oracle::GasPriceOracle,
        v0_7::{
            entry_point_simulations::{
                EntryPointSimulations, ExecutionResult as ExecutionResultV0_7,
                ENTRYPOINTSIMULATIONS_BYTECODE,
            },
            get_balances::{GetBalancesResult, GETBALANCES_BYTECODE},
            i_aggregator::IAggregator,
            i_entry_point::{
                DepositInfo as DepositInfoV0_7, FailedOp, IEntryPoint, SignatureValidationFailed,
                UserOpsPerAggregator as UserOpsPerAggregatorV0_7,
            },
        },
    },
    v0_7::UserOperation,
    GasFees, UserOpsPerAggregator, ValidationOutput,
};
use rundler_utils::eth::{self, ContractRevertError};

use crate::{
    AggregatorOut, AggregatorSimOut, BundleHandler, DepositInfo, EntryPointProvider,
    ExecutionResult, HandleOpsOut, L1GasProvider, Provider, SignatureAggregator,
    SimulationProvider,
};

// From v0.7 EP contract
const REVERT_REASON_MAX_LEN: usize = 2048;

// TODO(danc): These should be configurable from chain spec
const ARBITRUM_NITRO_NODE_INTERFACE_ADDRESS: Address = H160([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xc8,
]);
const OPTIMISM_BEDROCK_GAS_ORACLE_ADDRESS: Address = H160([
    0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0F,
]);

/// Entry point for the v0.7 contract.
#[derive(Debug, Clone)]
pub struct EntryPoint<P> {
    i_entry_point: IEntryPoint<P>,
    provider: Arc<P>,
    arb_node: NodeInterface<P>,
    opt_gas_oracle: GasPriceOracle<P>,
}

impl<P> EntryPoint<P>
where
    P: Middleware,
{
    /// Create a new `EntryPoint` instance for v0.7
    pub fn new(entry_point_address: Address, provider: Arc<P>) -> Self {
        Self {
            i_entry_point: IEntryPoint::new(entry_point_address, Arc::clone(&provider)),
            provider: Arc::clone(&provider),
            arb_node: NodeInterface::new(
                ARBITRUM_NITRO_NODE_INTERFACE_ADDRESS,
                Arc::clone(&provider),
            ),
            opt_gas_oracle: GasPriceOracle::new(OPTIMISM_BEDROCK_GAS_ORACLE_ADDRESS, provider),
        }
    }
}

#[async_trait::async_trait]
impl<P> crate::traits::EntryPoint for EntryPoint<P>
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

        // pack the ops
        let packed_ops = ops.into_iter().map(|op| op.pack()).collect();

        // TODO: Cap the gas here.
        let result = aggregator.aggregate_signatures(packed_ops).call().await;
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
            .validate_user_op_signature(user_op.pack())
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
                    // This revert is a bundler issue, not a user op issue, handle it differently
                    "AA95" => anyhow::bail!("Handle ops called with insufficient gas"),
                    _ => return Ok(HandleOpsOut::FailedOp(op_index.as_usize(), reason)),
                }
            }
            if let Ok(failure) = SignatureValidationFailed::decode(revert_data) {
                return Ok(HandleOpsOut::SignatureValidationFailed(failure.aggregator));
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

    async fn calc_arbitrum_l1_gas(
        &self,
        entry_point_address: Address,
        user_op: UserOperation,
    ) -> anyhow::Result<U256> {
        let data = self
            .i_entry_point
            .handle_ops(vec![user_op.pack()], Address::random())
            .calldata()
            .context("should get calldata for entry point handle ops")?;

        super::estimate_arbitrum_l1_gas(&self.arb_node, entry_point_address, data).await
    }

    async fn calc_optimism_l1_gas(
        &self,
        entry_point_address: Address,
        user_op: UserOperation,
        gas_price: U256,
    ) -> anyhow::Result<U256> {
        let data = self
            .i_entry_point
            .handle_ops(vec![user_op.pack()], Address::random())
            .calldata()
            .context("should get calldata for entry point handle ops")?;

        super::estimate_optimism_l1_gas(&self.opt_gas_oracle, entry_point_address, data, gas_price)
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
        let addr = self.i_entry_point.address();
        let pvg = user_op.pre_verification_gas;
        let mut spoof_ep = spoof::State::default();
        spoof_ep
            .account(addr)
            .code(ENTRYPOINTSIMULATIONS_BYTECODE.clone());
        let ep_simulations = EntryPointSimulations::new(addr, Arc::clone(&self.provider));

        let call = ep_simulations
            .simulate_validation(user_op.pack())
            .gas(U256::from(max_validation_gas) + pvg)
            .tx;

        (call, spoof_ep)
    }

    async fn call_simulate_validation(
        &self,
        user_op: UserOperation,
        max_validation_gas: u64,
    ) -> anyhow::Result<ValidationOutput> {
        let addr = self.i_entry_point.address();
        let pvg = user_op.pre_verification_gas;
        let mut spoof_ep = spoof::State::default();
        spoof_ep
            .account(addr)
            .code(ENTRYPOINTSIMULATIONS_BYTECODE.clone());

        let ep_simulations = EntryPointSimulations::new(addr, Arc::clone(&self.provider));
        let result = ep_simulations
            .simulate_validation(user_op.pack())
            .gas(U256::from(max_validation_gas) + pvg)
            .call_raw()
            .state(&spoof_ep)
            .await
            .context("should simulate validation")?;
        Ok(result.into())
    }

    fn decode_simulate_handle_ops_revert(
        &self,
        revert_data: Bytes,
    ) -> Result<ExecutionResult, String> {
        if let Ok(result) = ExecutionResultV0_7::decode(&revert_data) {
            Ok(result.into())
        } else if let Ok(failed_op) = FailedOp::decode(&revert_data) {
            Err(failed_op.reason)
        } else if let Ok(err) = ContractRevertError::decode(&revert_data) {
            Err(err.reason)
        } else {
            Err(hex::encode(&revert_data[..REVERT_REASON_MAX_LEN]))
        }
    }

    // NOTE: A spoof of the entry point code will be ignored by this function.
    async fn call_spoofed_simulate_op(
        &self,
        user_op: UserOperation,
        target: Address,
        target_call_data: Bytes,
        block_hash: H256,
        gas: U256,
        spoofed_state: &spoof::State,
    ) -> anyhow::Result<Result<ExecutionResult, String>> {
        let addr = self.i_entry_point.address();
        let mut spoof_ep = spoofed_state.clone();
        spoof_ep
            .account(addr)
            .code(ENTRYPOINTSIMULATIONS_BYTECODE.clone());
        let ep_simulations = EntryPointSimulations::new(addr, Arc::clone(&self.provider));

        let contract_error = ep_simulations
            .simulate_handle_op(user_op.pack(), target, target_call_data)
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
    let mut ops_per_aggregator: Vec<UserOpsPerAggregatorV0_7> = ops_per_aggregator
        .into_iter()
        .map(|uoa| UserOpsPerAggregatorV0_7 {
            user_ops: uoa.user_ops.into_iter().map(|op| op.pack()).collect(),
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

impl From<ExecutionResultV0_7> for ExecutionResult {
    fn from(result: ExecutionResultV0_7) -> Self {
        let account = rundler_types::parse_validation_data(result.account_validation_data);
        let paymaster = rundler_types::parse_validation_data(result.paymaster_validation_data);
        let intersect_range = account
            .valid_time_range()
            .intersect(paymaster.valid_time_range());

        ExecutionResult {
            pre_op_gas: result.pre_op_gas,
            paid: result.paid,
            valid_after: intersect_range.valid_after,
            valid_until: intersect_range.valid_until,
            target_success: result.target_success,
            target_result: result.target_result,
        }
    }
}

impl From<DepositInfoV0_7> for DepositInfo {
    fn from(deposit_info: DepositInfoV0_7) -> Self {
        Self {
            deposit: deposit_info.deposit,
            staked: deposit_info.staked,
            stake: deposit_info.stake,
            unstake_delay_sec: deposit_info.unstake_delay_sec,
            withdraw_time: deposit_info.withdraw_time,
        }
    }
}
