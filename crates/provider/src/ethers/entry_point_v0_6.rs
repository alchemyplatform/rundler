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
        H160, H256, U256, U64,
    },
    utils::hex,
};
use rundler_types::{
    contracts::{
        arbitrum::node_interface::NodeInterface,
        optimism::gas_price_oracle::GasPriceOracle,
        v0_6::{
            get_balances::{GetBalancesResult, GETBALANCES_BYTECODE},
            i_aggregator::IAggregator,
            i_entry_point::{ExecutionResult, FailedOp, IEntryPoint, SignatureValidationFailed},
            shared_types::UserOpsPerAggregator as UserOpsPerAggregatorV0_6,
        },
    },
    DepositInfoV0_6, GasFees, UserOperation, UserOpsPerAggregator, ValidationOutput,
};
use rundler_utils::eth::{self, ContractRevertError};

use crate::{
    traits::{EntryPoint, HandleOpsOut},
    AggregatorOut, AggregatorSimOut, Provider,
};

const ARBITRUM_NITRO_NODE_INTERFACE_ADDRESS: Address = H160([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xc8,
]);

const OPTIMISM_BEDROCK_GAS_ORACLE_ADDRESS: Address = H160([
    0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0F,
]);

const REVERT_REASON_MAX_LEN: usize = 2048;

// TODO(danc):
// - Modify this interface to take only `UserOperationV0_6` and remove the `into_v0_6` calls
// - Places that are already in a V0_6 context can use this directly
// - Implement a wrapper that takes `UserOperation` and dispatches to the correct entry point version
//   based on a constructor from ChainSpec.
// - Use either version depending on the abstraction of the caller.

/// Implementation of the `EntryPoint` trait for the v0.6 version of the entry point contract using ethers
#[derive(Debug)]
pub struct EntryPointV0_6<P: Provider + Middleware> {
    i_entry_point: IEntryPoint<P>,
    provider: Arc<P>,
    arb_node: NodeInterface<P>,
    opt_gas_oracle: GasPriceOracle<P>,
}

impl<P> Clone for EntryPointV0_6<P>
where
    P: Provider + Middleware,
{
    fn clone(&self) -> Self {
        Self {
            i_entry_point: self.i_entry_point.clone(),
            provider: self.provider.clone(),
            arb_node: self.arb_node.clone(),
            opt_gas_oracle: self.opt_gas_oracle.clone(),
        }
    }
}

impl<P> EntryPointV0_6<P>
where
    P: Provider + Middleware,
{
    /// Create a new `EntryPointV0_6` instance
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
impl<P> EntryPoint for EntryPointV0_6<P>
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
        let user_op = user_op
            .into_v0_6()
            .expect("V0_6 EP called with non-V0_6 op");

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
        let user_op = user_op
            .into_v0_6()
            .expect("V0_6 EP called with non-V0_6 op");

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
        user_op: UserOperation,
        target: Address,
        target_call_data: Bytes,
        block_hash: H256,
        gas: U256,
        spoofed_state: &spoof::State,
    ) -> anyhow::Result<Result<ExecutionResult, String>> {
        let user_op = user_op
            .into_v0_6()
            .expect("V0_6 EP called with non-V0_6 op");

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

    async fn get_deposit_info(&self, address: Address) -> anyhow::Result<DepositInfoV0_6> {
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

    async fn aggregate_signatures(
        self: Arc<Self>,
        aggregator_address: Address,
        ops: Vec<UserOperation>,
    ) -> anyhow::Result<Option<Bytes>> {
        let ops = ops
            .into_iter()
            .map(|op| op.into_v0_6().expect("V0_6 EP called with non-V0_6 op"))
            .collect();

        let aggregator = IAggregator::new(aggregator_address, Arc::clone(&self.provider));
        // TODO: Cap the gas here.
        let result = aggregator.aggregate_signatures(ops).call().await;
        match result {
            Ok(bytes) => Ok(Some(bytes)),
            Err(ContractError::Revert(_)) => Ok(None),
            Err(error) => Err(error).context("aggregator contract should aggregate signatures")?,
        }
    }

    async fn validate_user_op_signature(
        self: Arc<Self>,
        aggregator_address: Address,
        user_op: UserOperation,
        gas_cap: u64,
    ) -> anyhow::Result<AggregatorOut> {
        let aggregator = IAggregator::new(aggregator_address, Arc::clone(&self.provider));
        let user_op = user_op
            .into_v0_6()
            .expect("V0_6 EP called with non-V0_6 op");

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

    async fn calc_arbitrum_l1_gas(
        self: Arc<Self>,
        entry_point_address: Address,
        user_op: UserOperation,
    ) -> anyhow::Result<U256> {
        let user_op = user_op
            .into_v0_6()
            .expect("V0_6 EP called with non-V0_6 op");

        let data = self
            .i_entry_point
            .handle_ops(vec![user_op], Address::random())
            .calldata()
            .context("should get calldata for entry point handle ops")?;

        let gas = self
            .arb_node
            .gas_estimate_l1_component(entry_point_address, false, data)
            .call()
            .await?;
        Ok(U256::from(gas.0))
    }

    async fn calc_optimism_l1_gas(
        self: Arc<Self>,
        entry_point_address: Address,
        user_op: UserOperation,
        gas_price: U256,
    ) -> anyhow::Result<U256> {
        let user_op = user_op
            .into_v0_6()
            .expect("V0_6 EP called with non-V0_6 op");

        let data = self
            .i_entry_point
            .handle_ops(vec![user_op], Address::random())
            .calldata()
            .context("should get calldata for entry point handle ops")?;

        // construct an unsigned transaction with default values just for L1 gas estimation
        let tx = Eip1559TransactionRequest::new()
            .from(Address::random())
            .to(entry_point_address)
            .gas(U256::from(1_000_000))
            .max_priority_fee_per_gas(U256::from(100_000_000))
            .max_fee_per_gas(U256::from(100_000_000))
            .value(U256::from(0))
            .data(data)
            .nonce(U256::from(100_000))
            .chain_id(U64::from(100_000))
            .rlp();

        let l1_fee = self.opt_gas_oracle.get_l1_fee(tx).call().await?;
        Ok(l1_fee.checked_div(gas_price).unwrap_or(U256::MAX))
    }
}

fn get_handle_ops_call<M: Middleware>(
    entry_point: &IEntryPoint<M>,
    ops_per_aggregator: Vec<UserOpsPerAggregator>,
    beneficiary: Address,
    gas: U256,
) -> FunctionCall<Arc<M>, M, ()> {
    let mut ops_per_aggregator: Vec<UserOpsPerAggregatorV0_6> =
        ops_per_aggregator.into_iter().map(|x| x.into()).collect();
    let call =
        if ops_per_aggregator.len() == 1 && ops_per_aggregator[0].aggregator == Address::zero() {
            entry_point.handle_ops(ops_per_aggregator.swap_remove(0).user_ops, beneficiary)
        } else {
            entry_point.handle_aggregated_ops(ops_per_aggregator, beneficiary)
        };
    call.gas(gas)
}
