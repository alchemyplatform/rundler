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

use alloy_primitives::{Address, Bytes};
use alloy_sol_types::{Revert, SolError, SolInterface};
use anyhow::{anyhow, Context};
use metrics::Histogram;
use metrics_derive::Metrics;
#[cfg(feature = "test-utils")]
use mockall::automock;
use rundler_contracts::common::EstimationTypes::EstimationTypesErrors;
use rundler_provider::{ProviderError, StateOverride};
use rundler_types::{GasEstimate, ValidationRevert};

use crate::precheck::MIN_CALL_GAS_LIMIT;

mod estimate_verification_gas;
pub use estimate_verification_gas::{VerificationGasEstimator, VerificationGasEstimatorImpl};
mod estimate_call_gas;
pub use estimate_call_gas::{
    CallGasEstimator, CallGasEstimatorImpl, CallGasEstimatorSpecialization,
};

/// Gas estimation module for Entry Point v0.6
mod v0_6;
pub use v0_6::GasEstimator as GasEstimatorV0_6;
mod v0_7;
pub use v0_7::GasEstimator as GasEstimatorV0_7;

/// Percentage by which to increase the verification gas limit after binary search
const VERIFICATION_GAS_BUFFER_PERCENT: u32 = 10;
/// Absolute value by which to increase the call gas limit after binary search
const CALL_GAS_BUFFER_VALUE: u128 = 3000;

/// Error type for gas estimation
#[derive(Debug, thiserror::Error)]
pub enum GasEstimationError {
    /// Validation reverted
    #[error("{0}")]
    RevertInValidation(ValidationRevert),
    /// Call reverted with a string message
    #[error("user operation's call reverted: {0}")]
    RevertInCallWithMessage(String),
    /// Call reverted with bytes
    #[error("user operation's call reverted: {0:#x}")]
    RevertInCallWithBytes(Bytes),
    /// Call used too much gas
    #[error("gas_used cannot be larger than a u64 integer")]
    GasUsedTooLarge,
    /// Supplied gas was too large
    #[error("{0} cannot be larger than {1}")]
    GasFieldTooLarge(&'static str, u128),
    /// The total amount of gas used by the UO is greater than allowed
    #[error("total gas used by the user operation {0} is greater than the allowed limit: {1}")]
    GasTotalTooLarge(u128, u128),
    /// Unsupported signature aggregator
    #[error("unsupported signature aggregator: {0:?}")]
    UnsupportedAggregator(Address),
    /// Error from provider
    #[error(transparent)]
    ProviderError(#[from] ProviderError),
    /// Other error
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Gas estimator trait
#[cfg_attr(feature = "test-utils", automock(type UserOperationOptionalGas = rundler_types::v0_6::UserOperationOptionalGas;))]
#[async_trait::async_trait]
pub trait GasEstimator: Send + Sync {
    /// The user operation type estimated by this gas estimator
    type UserOperationOptionalGas;

    /// Returns a gas estimate or a revert message, or an anyhow error on any
    /// other error.
    async fn estimate_op_gas(
        &self,
        op: Self::UserOperationOptionalGas,
        state_override: StateOverride,
    ) -> Result<GasEstimate, GasEstimationError>;
}

/// Settings for gas estimation
#[derive(Clone, Copy, Debug)]
pub struct Settings {
    /// The maximum amount of gas that can be used for the verification step of a user operation
    pub max_verification_gas: u128,
    /// The maximum amount of gas that can be used for the paymaster verification step of a user operation
    pub max_paymaster_verification_gas: u128,
    /// The maximum amount of gas that can be used for the paymaster post op step of a user operation
    pub max_paymaster_post_op_gas: u128,
    /// The maximum amount of execution gas in a bundle
    pub max_bundle_execution_gas: u128,
    /// The gas fee to use during verification gas estimation, required to be held by the fee-payer
    /// during estimation. If using a paymaster, the fee-payer must have 3x this value.
    /// As the gas limit is varied during estimation, the fee is held constant by varying the
    /// gas price.
    /// Clients can use state overrides to set the balance of the fee-payer to at least this value.
    pub verification_estimation_gas_fee: u128,
    /// The threshold for the verification gas limit efficiency reject
    pub verification_gas_limit_efficiency_reject_threshold: f64,
    /// The allowed error percentage for the verification gas estimation
    pub verification_gas_allowed_error_pct: u128,
    /// The allowed error percentage for the call gas estimation
    pub call_gas_allowed_error_pct: u128,
    /// The maximum number of rounds to run for gas estimation
    pub max_gas_estimation_rounds: u32,
}

impl Settings {
    /// Check if the settings are valid
    pub fn validate(&self) -> Option<String> {
        if self.max_bundle_execution_gas < MIN_CALL_GAS_LIMIT {
            return Some(
                "max_bundle_execution_gas field cannot be lower than MIN_CALL_GAS_LIMIT"
                    .to_string(),
            );
        }
        None
    }
}

#[derive(Metrics)]
#[metrics(scope = "gas_estimator")]
struct Metrics {
    #[metric(describe = "the distribution of total gas estimate time.")]
    total_gas_estimate_ms: Histogram,
    #[metric(describe = "the distribution of pvg estimate time.")]
    pvg_estimate_ms: Histogram,
    #[metric(describe = "the distribution of vgl estimate time.")]
    vgl_estimate_ms: Histogram,
    #[metric(describe = "the distribution of cgl estimate time.")]
    cgl_estimate_ms: Histogram,
    #[metric(describe = "the distribution of pvgl estimate time.")]
    pvgl_estimate_ms: Histogram,
}

async fn run_binary_search<F>(
    round_fn: F,
    max_gas: u128,
    max_rounds: u32,
) -> Result<(u128, u32), GasEstimationError>
where
    F: Fn(
        u128, // min gas
        u128, // max gas
        bool, // is continuation
    ) -> Pin<Box<dyn Future<Output = Result<Bytes, GasEstimationError>> + Send>>,
{
    let mut min_gas = 0;
    let mut max_gas = max_gas;
    let mut num_rounds = 0_u32;
    let mut is_continuation = false;

    for _ in 0..max_rounds {
        let revert_data = round_fn(min_gas, max_gas, is_continuation).await?;

        let decoded = EstimationTypesErrors::abi_decode(&revert_data, false)
            .context("should decode revert data")?;
        match decoded {
            EstimationTypesErrors::EstimateGasResult(result) => {
                let ret_num_rounds: u32 = result
                    .numRounds
                    .try_into()
                    .context("num rounds return overflow")?;

                num_rounds += ret_num_rounds;
                return Ok((
                    result
                        .gas
                        .try_into()
                        .map_err(|_| GasEstimationError::GasUsedTooLarge)?,
                    num_rounds,
                ));
            }
            EstimationTypesErrors::EstimateGasRevertAtMax(revert) => {
                let error = if let Ok(revert) = Revert::abi_decode(&revert.revertData, false) {
                    GasEstimationError::RevertInCallWithMessage(revert.reason)
                } else {
                    GasEstimationError::RevertInCallWithBytes(revert.revertData)
                };
                return Err(error);
            }
            EstimationTypesErrors::EstimateGasContinuation(continuation) => {
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
            EstimationTypesErrors::TestCallGasResult(_) => {
                Err(anyhow!(
                    "estimateCallGas revert should be a Result or a Continuation"
                ))?;
            }
        }
    }

    Err(anyhow!(
        "gas estimation failed to converge after {max_rounds} rounds"
    ))?
}
