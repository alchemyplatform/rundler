use std::sync::Arc;

use anyhow::anyhow;
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
        contracts::call_gas_estimation_proxy::{
            EstimateCallGasArgs, EstimateCallGasCall, EstimateCallGasContinuation,
            EstimateCallGasResult, EstimateCallGasRevertAtMax,
            CALLGASESTIMATIONPROXY_DEPLOYED_BYTECODE,
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
const GAS_ROUNDING: u64 = 1024;

const VERIFICATION_GAS_BUFFER_PERCENT: u64 = 10;

const ESTIMATION_MAX_FEE_PER_GAS: U256 = U256([1_000_000_000_000_000_000u64, 0, 0, 0]); // 1 eth

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

        // Try once with max gas to make sure it's possible to succeed.
        let op = UserOperation {
            pre_verification_gas,
            verification_gas_limit: settings.max_verification_gas.into(),
            call_gas_limit: settings.max_call_gas.into(),
            ..op.into_user_operation(settings)
        };
        let verification_future = self.binary_search_verification_gas(&op, block_hash);
        let call_future = self.estimate_call_gas(&op, block_hash);
        // Not try_join! because then the output is nondeterministic if both
        // verification and call estimation fail.
        let (verification_gas_limit, call_gas_limit) = join!(verification_future, call_future);
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
        let simulation_gas = U256::from(self.settings.max_simulate_handle_ops_gas);
        let mut max_fee_per_gas = op.max_fee_per_gas;
        let mut spoofed_state = spoof::state();
        if op.paymaster().is_none() {
            // Also spoof the sender to have high balance if they don't use a
            // paymaster, so estimation won't fail because their balance is too low.
            // This accommodates the use case of estimating gas on an account with
            // low balance and then funding it afterwards based on the estimate.
            // Make sure to have a high gas fee, because otherwise the required
            // prefund is small and the account skips making a call to transfer
            // eth to the entry point, which causes our estimate to come up short.
            max_fee_per_gas = if max_fee_per_gas.is_zero() {
                ESTIMATION_MAX_FEE_PER_GAS
            } else {
                max_fee_per_gas
            };
            spoofed_state
                .account(op.sender)
                .balance(U256::from(1) << 128);
        } else {
            // If a paymaster is used, set a small, but not too small, gas fee
            // that would trigger any transfers during the paymaster's validation step.
            // This is typically useful for token-based paymasters.
            // NOTE: this cannot cover the case where the paymaster uses some sort of buffering
            // that could cause a transfer based on the user's balance. In that case, the user
            // would need to ensure to add a static amount of gas to their estimate.
            max_fee_per_gas = if max_fee_per_gas.is_zero() {
                100_000_000.into() // 0.1 GWEI
            } else {
                max_fee_per_gas
            };
        }
        // Don't move spoofed_state into the closure, only a reference.
        let spoofed_state = &spoofed_state;
        let run_attempt_returning_error = |gas: u64| async move {
            let op = UserOperation {
                verification_gas_limit: gas.into(),
                call_gas_limit: U256::zero(),
                max_fee_per_gas,
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
                    spoofed_state,
                )
                .await?
                .err();
            Result::<_, anyhow::Error>::Ok(error_message)
        };
        // Make one attempt at max gas to see if success is possible.
        if let Some(message) =
            run_attempt_returning_error(self.settings.max_verification_gas).await?
        {
            return Err(GasEstimationError::RevertInValidation(message));
        }

        // Scale everything down by the rounding constant, then find the
        // smallest scaled number that succeeds, then scale back up.
        let mut scaled_max_failure_gas = 0;
        let mut scaled_min_success_gas =
            (self.settings.max_verification_gas + GAS_ROUNDING - 1) / GAS_ROUNDING;
        while scaled_min_success_gas - scaled_max_failure_gas > 1 {
            let scaled_guess = (scaled_max_failure_gas + scaled_min_success_gas) / 2;
            let guess = scaled_guess * GAS_ROUNDING;
            let is_failure = run_attempt_returning_error(guess).await?.is_some();
            if is_failure {
                scaled_max_failure_gas = scaled_guess;
            } else {
                scaled_min_success_gas = scaled_guess;
            }
        }
        Ok((scaled_min_success_gas * GAS_ROUNDING)
            .min(self.settings.max_verification_gas)
            .into())
    }

    async fn estimate_call_gas(
        &self,
        op: &UserOperation,
        block_hash: H256,
    ) -> Result<U256, GasEstimationError> {
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
            10,
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
