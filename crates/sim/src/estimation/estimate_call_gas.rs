use anyhow::{anyhow, Context};
use async_trait::async_trait;
use ethers::{
    abi::AbiDecode,
    contract::EthCall,
    types::{spoof, Address, Bytes, H256, U128, U256},
};
use rand::Rng;
use rundler_provider::{EntryPoint, SimulationProvider};
use rundler_types::{
    contracts::utils::call_gas_estimation_proxy::{
        EstimateCallGasArgs, EstimateCallGasCall, EstimateCallGasContinuation,
        EstimateCallGasResult, EstimateCallGasRevertAtMax,
        CALLGASESTIMATIONPROXY_DEPLOYED_BYTECODE,
    },
    UserOperation,
};
use rundler_utils::eth;

use super::Settings;
use crate::GasEstimationError;

/// Gas estimates will be rounded up to the next multiple of this. Increasing
/// this value reduces the number of rounds of `eth_call` needed in binary
/// search, e.g. a value of 1024 means ten fewer `eth_call`s needed for each of
/// verification gas and call gas.
const GAS_ROUNDING: u64 = 4096;

/// Offset at which the proxy target address appears in the proxy bytecode. Must
/// be updated whenever `CallGasEstimationProxy.sol` changes.
///
/// The easiest way to get the updated value is to run this module's tests. The
/// failure will tell you the new value.
const PROXY_TARGET_OFFSET: usize = 120;

/// Estimates the gas limit for a user operation
#[async_trait]
pub trait CallGasEstimator: Send + Sync + 'static {
    /// The user operation type estimated by this estimator
    type UO: UserOperation;

    /// Returns a gas estimate or a revert message, or an anyhow error on any
    /// other error
    async fn estimate_call_gas(
        &self,
        op: Self::UO,
        block_hash: H256,
        state_override: spoof::State,
    ) -> Result<U128, GasEstimationError>;
}

/// Implementation of a call gas estimator which performs a binary search with
/// the `target` and `targetData` arguments to `simulateHandleOp`
#[derive(Debug)]
pub struct CallGasEstimatorImpl<E, S> {
    entry_point: E,
    settings: Settings,
    specialization: S,
}

/// Functions associated with a particular user operation version that
/// specialize the `CallGasEstimatorImpl` to be able to handle that version.
/// Each user operation version will need an implementation of this trait to be
/// able to be used with `CallGasEstimatorImpl`
pub trait CallGasEstimatorSpecialization: Send + Sync + 'static {
    /// The user operation type estimated by this specialization
    type UO: UserOperation;

    /// Returns the input user operation, modified to have high verification gas
    /// limits but zero for the call gas limits. The intent is that the modified
    /// operation should run its validation but do nothing during execution
    fn get_op_with_verification_gas_but_no_call_gas(
        &self,
        op: Self::UO,
        settings: Settings,
    ) -> Self::UO;

    /// Returns the deployed bytecode of the entry point contract with
    /// simulation methods
    fn entry_point_simulations_code(&self) -> Bytes;
}

#[async_trait]
impl<UO, E, S> CallGasEstimator for CallGasEstimatorImpl<E, S>
where
    UO: UserOperation,
    E: EntryPoint + SimulationProvider<UO = UO>,
    S: CallGasEstimatorSpecialization<UO = UO>,
{
    type UO = UO;

    async fn estimate_call_gas(
        &self,
        op: Self::UO,
        block_hash: H256,
        mut state_override: spoof::State,
    ) -> Result<U128, GasEstimationError> {
        let timer = std::time::Instant::now();
        // For an explanation of what's going on here, see the comment at the
        // top of `CallGasEstimationProxy.sol`.

        // Use a random address for the moved entry point so that users can't
        // intentionally get bad estimates by interacting with the hardcoded
        // address.
        let moved_entry_point_address: Address = rand::thread_rng().gen();
        let estimation_proxy_bytecode =
            estimation_proxy_bytecode_with_target(moved_entry_point_address);
        state_override
            .account(moved_entry_point_address)
            .code(self.specialization.entry_point_simulations_code());
        state_override
            .account(self.entry_point.address())
            .code(estimation_proxy_bytecode);

        let callless_op = self
            .specialization
            .get_op_with_verification_gas_but_no_call_gas(op.clone(), self.settings);

        let mut min_gas = U256::zero();
        let mut max_gas = U256::from(self.settings.max_call_gas);
        let mut is_continuation = false;
        let mut num_rounds = U256::zero();
        loop {
            let target_call_data = eth::call_data_of(
                EstimateCallGasCall::selector(),
                (EstimateCallGasArgs {
                    sender: op.sender(),
                    call_data: Bytes::clone(op.call_data()),
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
                    &state_override,
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
                return Ok(result
                    .gas_estimate
                    .try_into()
                    .ok()
                    .context("gas estimate should fit in a 128-bit int")?);
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
}

impl<UO, E, S> CallGasEstimatorImpl<E, S>
where
    UO: UserOperation,
    E: EntryPoint + SimulationProvider<UO = UO>,
    S: CallGasEstimatorSpecialization<UO = UO>,
{
    /// Creates a new call gas estimator
    pub fn new(entry_point: E, settings: Settings, specialization: S) -> Self {
        Self {
            entry_point,
            settings,
            specialization,
        }
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
