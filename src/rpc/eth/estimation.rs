use std::{ops::Deref, sync::Arc};

use anyhow::{anyhow, Context};
use ethers::{
    abi::AbiDecode,
    contract::EthCall,
    providers::spoof,
    types::{Address, Bytes, H256, U256},
};
#[cfg(test)]
use mockall::automock;
use rand::Rng;
use tokio::join;
use tonic::async_trait;

use crate::{
    common::{
        contracts::{
            call_gas_estimation_proxy::{
                EstimateCallGasArgs, EstimateCallGasCall, EstimateCallGasContinuation,
                EstimateCallGasResult, EstimateCallGasRevertAtMax,
                CALLGASESTIMATIONPROXY_DEPLOYED_BYTECODE,
            },
            i_entry_point,
        },
        eth, gas, math,
        precheck::MIN_CALL_GAS_LIMIT,
        types::{EntryPointLike, ProviderLike, UserOperation},
    },
    rpc::{GasEstimate, UserOperationOptionalGas},
};

/// Gas estimates will be rounded up to the next multiple of this. Increasing
/// this value reduces the number of rounds of `eth_call` needed in binary
/// search, e.g. a value of 1024 means ten fewer `eth_call`s needed for each of
/// verification gas and call gas.
const GAS_ROUNDING: u64 = 4096;

/// Gas estimation will stop when the binary search bounds are within
/// `GAS_ESTIMATION_ERROR_MARGIN` of each other.
const GAS_ESTIMATION_ERROR_MARGIN: f64 = 0.1;

const VERIFICATION_GAS_BUFFER_PERCENT: u64 = 10;

/// This accounts for the gas used during a transfer to the entrypoint contract
/// As well as the cost to initialize a previously 0 storage slot for an account
/// that has yet to deposit.
const GAS_FEE_TRANSFER_COST: u64 = 30000;

/// Offset at which the proxy target address appears in the proxy bytecode. Must
/// be updated whenever `CallGasEstimationProxy.sol` changes.
///
/// The easiest way to get the updated value is to run this module's tests. The
/// failure will tell you the new value.
const PROXY_TARGET_OFFSET: usize = 137;

#[derive(Debug, thiserror::Error)]
pub enum GasEstimationError {
    #[error("{0}")]
    RevertInValidation(String),
    #[error("user operation's call reverted: {0}")]
    RevertInCallWithMessage(String),
    #[error("user operation's call reverted: {0:#x}")]
    RevertInCallWithBytes(Bytes),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[cfg_attr(test, automock)]
#[async_trait]
pub trait GasEstimator: Send + Sync + 'static {
    /// Returns a gas estimate or a revert message, or an anyhow error on any
    /// other error.
    async fn estimate_op_gas(
        &self,
        op: UserOperationOptionalGas,
    ) -> Result<GasEstimate, GasEstimationError>;
}

#[derive(Debug)]
pub struct GasEstimatorImpl<P: ProviderLike, E: EntryPointLike> {
    chain_id: u64,
    provider: Arc<P>,
    entry_point: E,
    settings: Settings,
}

#[derive(Clone, Copy, Debug)]
pub struct Settings {
    pub max_verification_gas: u64,
    pub max_call_gas: u64,
    pub max_simulate_handle_ops_gas: u64,
}

#[async_trait]
impl<P: ProviderLike, E: EntryPointLike> GasEstimator for GasEstimatorImpl<P, E> {
    async fn estimate_op_gas(
        &self,
        op: UserOperationOptionalGas,
    ) -> Result<GasEstimate, GasEstimationError> {
        let Self {
            provider, settings, ..
        } = self;

        let block_hash = provider.get_latest_block_hash().await?;

        // Estimate pre verification gas
        let pre_verification_gas = self.calc_pre_verification_gas(&op).await?;

        // We deviate from the spec here always ignoring `max_fee_per_gas` and setting to zero.
        // If not using a paymaster, the bundler will automatically add 21K to the verification
        // gas limit to account for the gas fee transfer.
        // If using a paymaster, the transfer gas will need to be added by the client to the returned limit.
        let op = UserOperation {
            pre_verification_gas,
            verification_gas_limit: settings.max_verification_gas.into(),
            call_gas_limit: settings.max_call_gas.into(),
            max_fee_per_gas: 0.into(),
            max_priority_fee_per_gas: 0.into(),
            ..op.into_user_operation(settings)
        };

        let verification_future = self.binary_search_verification_gas(&op, block_hash);
        let call_future = self.estimate_call_gas(&op, block_hash);

        // Not try_join! because then the output is nondeterministic if both
        // verification and call estimation fail.
        let timer = std::time::Instant::now();
        let (verification_gas_limit, call_gas_limit) = join!(verification_future, call_future);
        tracing::debug!("gas estimation took {}ms", timer.elapsed().as_millis());

        let verification_gas_limit = verification_gas_limit?;
        let call_gas_limit = call_gas_limit?;
        Ok(GasEstimate {
            pre_verification_gas,
            verification_gas_limit: math::increase_by_percent(
                verification_gas_limit,
                VERIFICATION_GAS_BUFFER_PERCENT,
            )
            .min(settings.max_verification_gas.into()),
            call_gas_limit: call_gas_limit.clamp(MIN_CALL_GAS_LIMIT, settings.max_call_gas.into()),
        })
    }
}

impl<P: ProviderLike, E: EntryPointLike> GasEstimatorImpl<P, E> {
    pub fn new(chain_id: u64, provider: Arc<P>, entry_point: E, settings: Settings) -> Self {
        Self {
            chain_id,
            provider,
            entry_point,
            settings,
        }
    }

    async fn binary_search_verification_gas(
        &self,
        op: &UserOperation,
        block_hash: H256,
    ) -> Result<U256, GasEstimationError> {
        let timer = std::time::Instant::now();
        let simulation_gas = U256::from(self.settings.max_simulate_handle_ops_gas);

        // Make one attempt at max gas, but zero fees, to see if success is possible.
        // Capture the gas usage of this attempt and use as the initial guess in the binary search
        let initial_op = UserOperation {
            verification_gas_limit: simulation_gas,
            call_gas_limit: 0.into(),
            ..op.clone()
        };
        let gas_used = eth::get_gas_used(
            self.provider.deref(),
            self.entry_point.address(),
            U256::zero(),
            eth::call_data_of(
                i_entry_point::SimulateHandleOpCall::selector(),
                (initial_op, Address::zero(), Bytes::new()),
            ),
        )
        .await
        .context("failed to run initial guess")?;
        if gas_used.success {
            Err(anyhow!(
                "simulateHandleOp succeeded, but should always revert"
            ))?;
        }
        if let Some(message) = self
            .entry_point
            .decode_simulate_handle_ops_revert(gas_used.result)
            .err()
        {
            return Err(GasEstimationError::RevertInValidation(message));
        }

        let run_attempt_returning_error = |gas: u64| async move {
            let op = UserOperation {
                verification_gas_limit: gas.into(),
                call_gas_limit: 0.into(),
                ..op.clone()
            };
            let error_message = self
                .entry_point
                .call_spoofed_simulate_op(
                    op,
                    Address::zero(),
                    Bytes::new(),
                    block_hash,
                    simulation_gas,
                    &spoof::state(),
                )
                .await?
                .err();
            Result::<_, anyhow::Error>::Ok(error_message)
        };

        let mut max_failure_gas = 0;
        let mut min_success_gas = self.settings.max_verification_gas;
        let mut guess = gas_used.gas_used.as_u64() * 2;
        let mut num_rounds = 0;
        while (min_success_gas as f64) / (max_failure_gas as f64)
            > (1.0 + GAS_ESTIMATION_ERROR_MARGIN)
        {
            num_rounds += 1;
            let is_failure = run_attempt_returning_error(guess).await?.is_some();
            if is_failure {
                max_failure_gas = guess;
            } else {
                min_success_gas = guess;
            }
            guess = (max_failure_gas + min_success_gas) / 2;
        }

        let mut min_success_gas = min_success_gas;
        if op.paymaster().is_none() {
            // If not using a paymaster, add the gas for the gas fee transfer.
            min_success_gas += GAS_FEE_TRANSFER_COST;
        }
        tracing::debug!(
            "binary search for verification gas took {num_rounds} rounds, {}ms",
            timer.elapsed().as_millis()
        );
        Ok(min_success_gas.into())
    }

    async fn estimate_call_gas(
        &self,
        op: &UserOperation,
        block_hash: H256,
    ) -> Result<U256, GasEstimationError> {
        let timer = std::time::Instant::now();
        // For an explanation of what's going on here, see the comment at the
        // top of `CallGasEstimationProxy.sol`.
        let entry_point_code = self
            .provider
            .get_code(self.entry_point.address(), Some(block_hash))
            .await?;
        // Use a random address for the moved entry point so that users can't
        // intentionally get bad estimates by interacting with the hardcoded
        // address.
        let moved_entry_point_address: Address = rand::thread_rng().gen();
        let estimation_proxy_bytecode =
            estimation_proxy_bytecode_with_target(moved_entry_point_address);
        let mut spoofed_state = spoof::state();
        spoofed_state
            .account(moved_entry_point_address)
            .code(entry_point_code);
        spoofed_state
            .account(self.entry_point.address())
            .code(estimation_proxy_bytecode);
        let callless_op = UserOperation {
            call_gas_limit: 0.into(),
            ..op.clone()
        };
        let mut min_gas = U256::zero();
        let mut max_gas = U256::from(self.settings.max_call_gas);
        let mut is_continuation = false;
        let mut num_rounds = U256::zero();
        loop {
            let target_call_data = eth::call_data_of(
                EstimateCallGasCall::selector(),
                (EstimateCallGasArgs {
                    sender: op.sender,
                    call_data: Bytes::clone(&op.call_data),
                    min_gas,
                    max_gas,
                    rounding: GAS_ROUNDING.into(),
                    is_continuation,
                },),
            );
            let target_revert_data = self
                .entry_point
                .call_spoofed_simulate_op(
                    callless_op.clone(),
                    self.entry_point.address(),
                    target_call_data,
                    block_hash,
                    self.settings.max_simulate_handle_ops_gas.into(),
                    &spoofed_state,
                )
                .await?
                .map_err(GasEstimationError::RevertInCallWithMessage)?
                .target_result;
            if let Ok(result) = EstimateCallGasResult::decode(&target_revert_data) {
                num_rounds += result.num_rounds;
                tracing::debug!(
                    "binary search for call gas took {num_rounds} rounds, {}ms",
                    timer.elapsed().as_millis()
                );
                return Ok(result.gas_estimate);
            } else if let Ok(revert) = EstimateCallGasRevertAtMax::decode(&target_revert_data) {
                let error = if let Some(message) = eth::parse_revert_message(&revert.revert_data) {
                    GasEstimationError::RevertInCallWithMessage(message)
                } else {
                    GasEstimationError::RevertInCallWithBytes(revert.revert_data)
                };
                return Err(error);
            } else if let Ok(continuation) =
                EstimateCallGasContinuation::decode(&target_revert_data)
            {
                if is_continuation
                    && continuation.min_gas <= min_gas
                    && continuation.max_gas >= max_gas
                {
                    // This should never happen, but if it does, bail so we
                    // don't end up in an infinite loop!
                    Err(anyhow!(
                        "estimateCallGas should make progress each time it is called"
                    ))?;
                }
                is_continuation = true;
                min_gas = min_gas.max(continuation.min_gas);
                max_gas = max_gas.min(continuation.max_gas);
                num_rounds += continuation.num_rounds;
            } else {
                Err(anyhow!(
                    "estimateCallGas revert should be a Result or a Continuation"
                ))?;
            }
        }
    }

    async fn calc_pre_verification_gas(
        &self,
        op: &UserOperationOptionalGas,
    ) -> Result<U256, GasEstimationError> {
        Ok(gas::calc_pre_verification_gas(
            op.max_fill(&self.settings),
            op.random_fill(&self.settings),
            self.entry_point.address(),
            self.provider.clone(),
            self.chain_id,
        )
        .await?)
    }
}

/// Replaces the address of the proxy target where it appears in the proxy
/// bytecode so we don't need the same fixed address every time.
fn estimation_proxy_bytecode_with_target(target: Address) -> Bytes {
    let mut vec = CALLGASESTIMATIONPROXY_DEPLOYED_BYTECODE.to_vec();
    vec[PROXY_TARGET_OFFSET..PROXY_TARGET_OFFSET + 20].copy_from_slice(target.as_bytes());
    vec.into()
}

#[cfg(test)]
mod tests {
    use ethers::utils::hex;

    use super::*;

    /// Must match the constant in `CallGasEstimationProxy.sol`.
    const PROXY_TARGET_CONSTANT: &str = "A13dB4eCfbce0586E57D1AeE224FbE64706E8cd3";

    #[test]
    fn test_proxy_target_offset() {
        let proxy_target_bytes = hex::decode(PROXY_TARGET_CONSTANT).unwrap();
        let mut offsets = Vec::<usize>::new();
        for i in 0..CALLGASESTIMATIONPROXY_DEPLOYED_BYTECODE.len() - 20 {
            if CALLGASESTIMATIONPROXY_DEPLOYED_BYTECODE[i..i + 20] == proxy_target_bytes {
                offsets.push(i);
            }
        }
        assert_eq!(vec![PROXY_TARGET_OFFSET], offsets);
    }
}
