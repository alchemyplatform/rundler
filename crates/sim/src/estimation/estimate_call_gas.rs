use anyhow::{anyhow, Context};
use async_trait::async_trait;
use ethers::{
    abi::AbiDecode,
    types::{spoof, Address, Bytes, H256, U128, U256},
};
use rundler_provider::{EntryPoint, SimulationProvider};
use rundler_types::{
    contracts::v0_7::call_gas_estimation_proxy::{
        // Errors are shared between v0.6 and v0.7 proxies
        EstimateCallGasContinuation,
        EstimateCallGasResult,
        EstimateCallGasRevertAtMax,
        TestCallGasResult,
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

/// Must match the constant in `CallGasEstimationProxyTypes.sol`.
#[allow(dead_code)]
pub(crate) const PROXY_IMPLEMENTATION_ADDRESS_MARKER: &str =
    "A13dB4eCfbce0586E57D1AeE224FbE64706E8cd3";

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

    /// Calls simulate_handle_op, but captures the execution result. Returning an
    /// error if the operation reverts or anyhow error on any other error
    async fn simulate_handle_op_with_result(
        &self,
        op: Self::UO,
        block_hash: H256,
        state_override: spoof::State,
    ) -> Result<(), GasEstimationError>;
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

    /// Add the required CallGasEstimation proxy to the overrides at the given entrypoint address
    fn add_proxy_to_overrides(&self, ep_to_override: Address, state_override: &mut spoof::State);

    /// Returns the input user operation, modified to have limits but zero for the call gas limits.
    /// The intent is that the modified operation should run its validation but do nothing during execution
    fn get_op_with_no_call_gas(&self, op: Self::UO) -> Self::UO;

    /// Returns the calldata for the `estimateCallGas` function of the proxy
    fn get_estimate_call_gas_calldata(
        &self,
        callless_op: Self::UO,
        min_gas: U256,
        max_gas: U256,
        rounding: U256,
        is_continuation: bool,
    ) -> Bytes;

    /// Returns the calldata for the `testCallGas` function of the proxy
    fn get_test_call_gas_calldata(&self, callless_op: Self::UO, call_gas_limit: U256) -> Bytes;
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
        self.specialization
            .add_proxy_to_overrides(self.entry_point.address(), &mut state_override);

        let callless_op = self.specialization.get_op_with_no_call_gas(op.clone());

        let mut min_gas = U256::zero();
        let mut max_gas = U256::from(self.settings.max_call_gas);
        let mut is_continuation = false;
        let mut num_rounds = U256::zero();
        loop {
            let target_call_data = self.specialization.get_estimate_call_gas_calldata(
                callless_op.clone(),
                min_gas,
                max_gas,
                GAS_ROUNDING.into(),
                is_continuation,
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
                .map_err(GasEstimationError::RevertInValidation)?
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

    async fn simulate_handle_op_with_result(
        &self,
        op: Self::UO,
        block_hash: H256,
        mut state_override: spoof::State,
    ) -> Result<(), GasEstimationError> {
        self.specialization
            .add_proxy_to_overrides(self.entry_point.address(), &mut state_override);

        let call_gas_limit = op.call_gas_limit();
        let callless_op = self.specialization.get_op_with_no_call_gas(op);
        let target_call_data = self
            .specialization
            .get_test_call_gas_calldata(callless_op.clone(), call_gas_limit);

        let target_revert_data = self
            .entry_point
            .call_spoofed_simulate_op(
                callless_op,
                self.entry_point.address(),
                target_call_data,
                block_hash,
                self.settings.max_simulate_handle_ops_gas.into(),
                &state_override,
            )
            .await?
            .map_err(GasEstimationError::RevertInValidation)?
            .target_result;
        if let Ok(result) = TestCallGasResult::decode(&target_revert_data) {
            if result.success {
                Ok(())
            } else {
                let error = if let Some(message) = eth::parse_revert_message(&result.revert_data) {
                    GasEstimationError::RevertInCallWithMessage(message)
                } else {
                    GasEstimationError::RevertInCallWithBytes(result.revert_data)
                };
                Err(error)
            }
        } else {
            Err(anyhow!("testCallGas revert should be a TestCallGasResult"))?
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
