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

use std::{future::Future, pin::Pin};

use alloy_primitives::{Address, B256, Bytes};
use alloy_sol_types::{Revert, SolError};
use anyhow::Context;
use async_trait::async_trait;
use rundler_contracts::common::EstimationTypes;
use rundler_provider::{EntryPoint, SimulationProvider, StateOverride};
use rundler_types::UserOperation;
use rundler_utils::authorization_utils;
use tracing::instrument;

use super::Settings;
use crate::{GasEstimationError, estimation::BinarySearchResult};

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
#[derive(Debug, Clone)]
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

    /// Returns the input user operation, modified to have limits but zero for the call gas limits.
    /// The intent is that the modified operation should run its validation but do nothing during execution
    fn get_op_with_no_call_gas(&self, op: Self::UO) -> Self::UO;

    /// Returns the calldata for the `estimateCallGas` function of the proxy
    fn get_estimate_call_gas_calldata(
        &self,
        callless_op: Self::UO,
        min_gas: u128,
        max_gas: u128,
        allowed_error_pct: u128,
        is_continuation: bool,
    ) -> Bytes;

    /// Returns the calldata for the `testCallGas` function of the proxy
    fn get_test_call_gas_calldata(&self, callless_op: Self::UO, call_gas_limit: u128) -> Bytes;
}

#[async_trait]
impl<E, S> CallGasEstimator for CallGasEstimatorImpl<E, S>
where
    E: EntryPoint + SimulationProvider<UO = S::UO> + Clone + 'static,
    S: CallGasEstimatorSpecialization + Clone + 'static,
{
    type UO = S::UO;

    #[instrument(skip_all)]
    async fn estimate_call_gas(
        &self,
        op: Self::UO,
        block_hash: B256,
        mut state_override: StateOverride,
    ) -> Result<u128, GasEstimationError> {
        self.specialization
            .add_proxy_to_overrides(*self.entry_point.address(), &mut state_override);

        let callless_op = self.specialization.get_op_with_no_call_gas(op.clone());

        if let Some(authorization_tuple) = op.authorization_tuple() {
            let eip7702_auth_address = authorization_tuple.address;
            authorization_utils::apply_7702_overrides(
                &mut state_override,
                op.sender(),
                eip7702_auth_address,
            );
        }

        let round_fn = |min_gas: u128, max_gas: u128, is_continuation: bool| {
            Box::pin(self.clone().run_binary_search_round(
                callless_op.clone(),
                block_hash,
                state_override.clone(),
                min_gas,
                max_gas,
                is_continuation,
            ))
                as Pin<Box<dyn Future<Output = Result<Bytes, GasEstimationError>> + Send>>
        };

        let timer = std::time::Instant::now();
        let result = super::run_binary_search(
            round_fn,
            self.settings.max_bundle_execution_gas,
            self.settings.max_gas_estimation_rounds,
        )
        .await?;

        match result {
            BinarySearchResult::Success(estimate, num_rounds) => {
                tracing::debug!(
                    "call gas estimation took {} ms with {} rounds",
                    timer.elapsed().as_millis(),
                    num_rounds
                );
                Ok(estimate)
            }
            BinarySearchResult::Revert(revert_data) => {
                if let Ok(revert) = Revert::abi_decode(&revert_data) {
                    Err(GasEstimationError::RevertInCallWithMessage(revert.reason))
                } else {
                    Err(GasEstimationError::RevertInCallWithBytes(revert_data))
                }
            }
        }
    }

    #[instrument(skip_all)]
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
            .simulate_handle_op_estimate_gas(
                callless_op,
                *self.entry_point.address(),
                target_call_data,
                block_hash.into(),
                state_override.clone(),
            )
            .await?
            .map_err(GasEstimationError::RevertInValidation)?
            .target_result;

        let result = EstimationTypes::TestCallGasResult::abi_decode(&target_revert_data)
            .context("should decode revert data as TestCallGasResult")?;
        if result.success {
            Ok(())
        } else {
            let error = if let Ok(revert) = Revert::abi_decode(&result.revertData) {
                GasEstimationError::RevertInCallWithMessage(revert.reason)
            } else {
                GasEstimationError::RevertInCallWithBytes(result.revertData)
            };
            Err(error)
        }
    }
}

impl<E, S> CallGasEstimatorImpl<E, S>
where
    E: EntryPoint + SimulationProvider<UO = S::UO>,
    S: CallGasEstimatorSpecialization,
{
    /// Creates a new call gas estimator
    pub fn new(entry_point: E, settings: Settings, specialization: S) -> Self {
        Self {
            entry_point,
            settings,
            specialization,
        }
    }

    async fn run_binary_search_round(
        self,
        op: S::UO,
        block_hash: B256,
        state_overrides: StateOverride,
        min_gas: u128,
        max_gas: u128,
        is_continuation: bool,
    ) -> Result<Bytes, GasEstimationError> {
        let target_call_data = self.specialization.get_estimate_call_gas_calldata(
            op.clone(),
            min_gas,
            max_gas,
            self.settings.call_gas_allowed_error_pct,
            is_continuation,
        );
        Ok(self
            .entry_point
            .simulate_handle_op_estimate_gas(
                op,
                *self.entry_point.address(),
                target_call_data,
                block_hash.into(),
                state_overrides,
            )
            .await?
            .map_err(GasEstimationError::RevertInValidation)?
            .target_result)
    }
}
