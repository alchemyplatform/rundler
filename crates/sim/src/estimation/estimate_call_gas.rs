use alloy_primitives::{fixed_bytes, Address, Bytes, FixedBytes, B256};
use alloy_sol_types::{Revert, SolError, SolInterface};
use anyhow::{anyhow, Context};
use async_trait::async_trait;
use rundler_contracts::{
    v0_6::CallGasEstimationProxy::TestCallGasResult,
    v0_7::CallGasEstimationProxy::CallGasEstimationProxyErrors,
};
use rundler_provider::{AccountOverride, EntryPoint, SimulationProvider, StateOverride};
use rundler_types::UserOperation;

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
pub trait CallGasEstimator: Send + Sync {
    /// The user operation type estimated by this estimator
    type UO: UserOperation;

    /// Returns a gas estimate or a revert message, or an anyhow error on any
    /// other error
    async fn estimate_call_gas(
        &self,
        op: Self::UO,
        block_hash: B256,
        state_override: StateOverride,
    ) -> Result<u128, GasEstimationError>;

    /// Calls simulate_handle_op, but captures the execution result. Returning an
    /// error if the operation reverts or anyhow error on any other error
    async fn simulate_handle_op_with_result(
        &self,
        op: Self::UO,
        block_hash: B256,
        state_override: StateOverride,
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
pub trait CallGasEstimatorSpecialization: Send + Sync {
    /// The user operation type estimated by this specialization
    type UO: UserOperation;

    /// Add the required CallGasEstimation proxy to the overrides at the given entrypoint address
    fn add_proxy_to_overrides(&self, ep_to_override: Address, state_override: &mut StateOverride);

    /// Add the required EOA-upgrade to the overrides to simulate an upgrade;
    fn add_7702_overrides(
        &self,
        eoa_to_override: Address,
        sca_address: Address,
        state_override: &mut StateOverride,
    ) {
        let prefix: FixedBytes<3> = fixed_bytes!("ef0100");
        let code: FixedBytes<23> = prefix.concat_const(sca_address.into());
        tracing::debug!("state oveerride code: {}", code);
        // TODO(andy): if sca_address is 0x0, should remove code there.
        state_override.insert(
            eoa_to_override,
            AccountOverride {
                code: Some(code.into()),
                ..Default::default()
            },
        );
    }
    /// Returns the input user operation, modified to have limits but zero for the call gas limits.
    /// The intent is that the modified operation should run its validation but do nothing during execution
    fn get_op_with_no_call_gas(&self, op: Self::UO) -> Self::UO;

    /// Returns the calldata for the `estimateCallGas` function of the proxy
    fn get_estimate_call_gas_calldata(
        &self,
        callless_op: Self::UO,
        min_gas: u128,
        max_gas: u128,
        rounding: u128,
        is_continuation: bool,
    ) -> Bytes;

    /// Returns the calldata for the `testCallGas` function of the proxy
    fn get_test_call_gas_calldata(&self, callless_op: Self::UO, call_gas_limit: u128) -> Bytes;
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
        block_hash: B256,
        mut state_override: StateOverride,
    ) -> Result<u128, GasEstimationError> {
        let timer = std::time::Instant::now();
        self.specialization
            .add_proxy_to_overrides(*self.entry_point.address(), &mut state_override);

        let callless_op = self.specialization.get_op_with_no_call_gas(op.clone());

        if let Some(authrozation_tuple) = op.authorization_tuple().clone() {
            let contract_address = authrozation_tuple.address;
            self.specialization.add_7702_overrides(
                op.sender(),
                contract_address,
                &mut state_override,
            );
        }
        let mut min_gas = 0;
        let mut max_gas = self.settings.max_call_gas;
        let mut is_continuation = false;
        let mut num_rounds = 0_u32;
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
                .simulate_handle_op(
                    callless_op.clone(),
                    *self.entry_point.address(),
                    target_call_data,
                    block_hash.into(),
                    state_override.clone(),
                )
                .await?
                .map_err(GasEstimationError::RevertInValidation)?
                .target_result;

            let decoded = CallGasEstimationProxyErrors::abi_decode(&target_revert_data, false)
                .context("should decode revert data")?;
            match decoded {
                CallGasEstimationProxyErrors::EstimateCallGasResult(result) => {
                    let ret_num_rounds: u32 = result
                        .numRounds
                        .try_into()
                        .context("num rounds return overflow")?;

                    num_rounds += ret_num_rounds;
                    tracing::debug!(
                        "binary search for call gas took {num_rounds} rounds, {}ms",
                        timer.elapsed().as_millis()
                    );
                    return Ok(result
                        .gasEstimate
                        .try_into()
                        .ok()
                        .context("gasEstimate return overflow")?);
                }
                CallGasEstimationProxyErrors::EstimateCallGasRevertAtMax(revert) => {
                    let error = if let Ok(revert) = Revert::abi_decode(&revert.revertData, false) {
                        GasEstimationError::RevertInCallWithMessage(revert.reason)
                    } else {
                        GasEstimationError::RevertInCallWithBytes(revert.revertData)
                    };
                    return Err(error);
                }
                CallGasEstimationProxyErrors::EstimateCallGasContinuation(continuation) => {
                    let ret_min_gas = continuation
                        .minGas
                        .try_into()
                        .context("min gas return overflow")?;
                    let ret_max_gas = continuation
                        .maxGas
                        .try_into()
                        .context("max gas return overflow")?;
                    let ret_num_rounds: u32 = continuation
                        .numRounds
                        .try_into()
                        .context("num rounds return overflow")?;

                    if is_continuation && ret_min_gas <= min_gas && ret_max_gas >= max_gas {
                        // This should never happen, but if it does, bail so we
                        // don't end up in an infinite loop!
                        Err(anyhow!(
                            "estimateCallGas should make progress each time it is called"
                        ))?;
                    }
                    is_continuation = true;
                    min_gas = min_gas.max(ret_min_gas);
                    max_gas = max_gas.min(ret_max_gas);
                    num_rounds += ret_num_rounds;
                }
                CallGasEstimationProxyErrors::TestCallGasResult(_) => {
                    Err(anyhow!(
                        "estimateCallGas revert should be a Result or a Continuation"
                    ))?;
                }
            }
        }
    }

    async fn simulate_handle_op_with_result(
        &self,
        op: Self::UO,
        block_hash: B256,
        mut state_override: StateOverride,
    ) -> Result<(), GasEstimationError> {
        self.specialization
            .add_proxy_to_overrides(*self.entry_point.address(), &mut state_override);

        let call_gas_limit = op.call_gas_limit();
        let callless_op = self.specialization.get_op_with_no_call_gas(op);
        let target_call_data = self
            .specialization
            .get_test_call_gas_calldata(callless_op.clone(), call_gas_limit);

        let target_revert_data = self
            .entry_point
            .simulate_handle_op(
                callless_op,
                *self.entry_point.address(),
                target_call_data,
                block_hash.into(),
                state_override.clone(),
            )
            .await?
            .map_err(GasEstimationError::RevertInValidation)?
            .target_result;

        let result = TestCallGasResult::abi_decode(&target_revert_data, false)
            .context("should decode revert data as TestCallGasResult")?;

        if result.success {
            Ok(())
        } else {
            let error = if let Ok(revert) = Revert::abi_decode(&result.revertData, false) {
                GasEstimationError::RevertInCallWithMessage(revert.reason)
            } else {
                GasEstimationError::RevertInCallWithBytes(result.revertData)
            };
            Err(error)
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
