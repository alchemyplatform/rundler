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

use std::{future::Future, pin::Pin, sync::Once};

use alloy_primitives::{Address, Bytes};
use alloy_sol_types::SolInterface;
use anyhow::{Context, anyhow};
use metrics::{Counter, Histogram};
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
    /// Call reverted with no data while consuming the entire supplied call gas limit,
    /// indicating it likely ran out of gas rather than hitting a genuine revert
    #[error(
        "call likely ran out of gas: consumed the entire callGasLimit ({0}) and reverted with no data"
    )]
    CallGasLimitTooLow(u128),
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

impl GasEstimationError {
    /// Returns a bounded label value for the error variant
    pub fn kind(&self) -> &'static str {
        match self {
            Self::RevertInValidation(_) => "revert_in_validation",
            Self::RevertInCallWithMessage(_) | Self::RevertInCallWithBytes(_) => "revert_in_call",
            Self::CallGasLimitTooLow(_) => "call_gas_limit_too_low",
            Self::GasUsedTooLarge => "gas_used_too_large",
            Self::GasFieldTooLarge(_, _) => "gas_field_too_large",
            Self::GasTotalTooLarge(_, _) => "gas_total_too_large",
            Self::UnsupportedAggregator(_) => "unsupported_aggregator",
            Self::ProviderError(_) => "provider",
            Self::Other(_) => "other",
        }
    }
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
    /// The maximum amount of gas that can be used during a round of binary search for gas estimation
    pub max_gas_estimation_gas: u64,
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

/// Names of the estimation eth_call histograms, without the global metrics prefix.
pub const ESTIMATION_ETH_CALL_HISTOGRAMS: &[&str] = &["gas_estimator.eth_calls"];

/// Histogram buckets for the number of eth_calls a binary search used.
pub const ESTIMATION_ETH_CALL_BUCKETS: &[f64] = &[1.0, 2.0, 3.0, 4.0, 5.0, 10.0];

// Separate structs because the metrics have different labels, and `new_with_labels`
// registers every field of a struct
#[derive(Metrics)]
#[metrics(scope = "gas_estimator")]
struct SearchCallMetrics {
    #[metric(
        describe = "the number of eth_calls a gas estimation binary search used, by entry point, field and outcome (success, revert, error, or not_converged when all max_gas_estimation_rounds were used), including the call that failed."
    )]
    eth_calls: Histogram,
}

#[derive(Metrics)]
#[metrics(scope = "gas_estimator")]
struct ClampMetrics {
    #[metric(
        describe = "the count of estimates where the buffered value was cut down to its maximum, by entry point and field."
    )]
    clamped_estimates: Counter,
}

#[derive(Metrics)]
#[metrics(scope = "gas_estimator")]
struct ErrorMetrics {
    #[metric(describe = "the count of gas estimation errors, by entry point and error kind.")]
    errors: Counter,
}

static DESCRIBE: Once = Once::new();

fn describe_metrics() {
    // `new_with_labels` does not register the metric descriptions
    DESCRIBE.call_once(|| {
        SearchCallMetrics::describe();
        ClampMetrics::describe();
        ErrorMetrics::describe();
    });
}

/// Records the eth_calls of one binary search, labelled by how it ended.
fn record_search(
    entry_point: Address,
    field: &'static str,
    eth_calls: u32,
    result: &Result<Option<BinarySearchResult>, GasEstimationError>,
) {
    describe_metrics();
    let outcome = match result {
        Ok(Some(BinarySearchResult::Success(..))) => "success",
        Ok(Some(BinarySearchResult::Revert(_))) => "revert",
        Ok(None) => "not_converged",
        Err(_) => "error",
    };
    SearchCallMetrics::new_with_labels(&[
        ("entry_point", entry_point.to_string()),
        ("field", field.to_string()),
        ("outcome", outcome.to_string()),
    ])
    .eth_calls
    .record(f64::from(eth_calls));
}

/// Counts one gas estimation error by its kind.
pub fn record_estimation_error(entry_point: Address, error: &GasEstimationError) {
    describe_metrics();
    ErrorMetrics::new_with_labels(&[
        ("entry_point", entry_point.to_string()),
        ("kind", error.kind().to_string()),
    ])
    .errors
    .increment(1);
}

/// Counts an estimate whose buffered value is above its cap, so the cap sets the returned limit.
pub(crate) fn record_clamped_estimate(
    entry_point: Address,
    field: &'static str,
    estimate: u128,
    cap: u128,
) {
    if estimate <= cap {
        return;
    }
    describe_metrics();
    ClampMetrics::new_with_labels(&[
        ("entry_point", entry_point.to_string()),
        ("field", field.to_string()),
    ])
    .clamped_estimates
    .increment(1);
}

enum BinarySearchResult {
    Success(u128, u32),
    Revert(Bytes),
}

async fn run_binary_search<F>(
    round_fn: F,
    max_gas: u128,
    max_rounds: u32,
    entry_point: Address,
    field: &'static str,
) -> Result<BinarySearchResult, GasEstimationError>
where
    F: Fn(
        u128, // min gas
        u128, // max gas
        bool, // is continuation
    ) -> Pin<Box<dyn Future<Output = Result<Bytes, GasEstimationError>> + Send>>,
{
    let mut eth_calls = 0_u32;
    let result = binary_search(round_fn, max_gas, max_rounds, &mut eth_calls).await;

    record_search(entry_point, field, eth_calls, &result);
    match result {
        Ok(Some(result)) => Ok(result),
        Ok(None) => Err(anyhow!(
            "gas estimation failed to converge after {max_rounds} rounds"
        ))?,
        Err(error) => Err(error),
    }
}

/// Runs the binary search, returning `None` if it did not converge within `max_rounds`.
///
/// `eth_calls` counts the rounds started, including one that fails.
async fn binary_search<F>(
    round_fn: F,
    max_gas: u128,
    max_rounds: u32,
    eth_calls: &mut u32,
) -> Result<Option<BinarySearchResult>, GasEstimationError>
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
        *eth_calls += 1;
        let revert_data = round_fn(min_gas, max_gas, is_continuation).await?;

        let decoded =
            EstimationTypesErrors::abi_decode(&revert_data).context("should decode revert data")?;
        match decoded {
            EstimationTypesErrors::EstimateGasResult(result) => {
                let ret_num_rounds: u32 = result
                    .numRounds
                    .try_into()
                    .context("num rounds return overflow")?;

                num_rounds += ret_num_rounds;
                return Ok(Some(BinarySearchResult::Success(
                    result
                        .gas
                        .try_into()
                        .map_err(|_| GasEstimationError::GasUsedTooLarge)?,
                    num_rounds,
                )));
            }
            EstimationTypesErrors::EstimateGasRevertAtMax(revert) => {
                return Ok(Some(BinarySearchResult::Revert(revert.revertData)));
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

    Ok(None)
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use alloy_primitives::{U256, address};
    use alloy_sol_types::SolError;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use rundler_contracts::common::EstimationTypes::{
        EstimateGasContinuation, EstimateGasResult, EstimateGasRevertAtMax,
    };

    use super::*;

    const ENTRY_POINT: Address = address!("0000000071727De22E5E9d8BAf0edAc6f37da032");

    fn counters(recorder: &DebuggingRecorder) -> Vec<(String, DebugValue)> {
        let mut counters = recorder
            .snapshotter()
            .snapshot()
            .into_vec()
            .into_iter()
            .map(|(key, _, _, value)| {
                let key = key.key();
                let mut labels = key
                    .labels()
                    .map(|label| format!("{}={}", label.key(), label.value()))
                    .collect::<Vec<_>>();
                labels.sort();
                (format!("{}{{{}}}", key.name(), labels.join(",")), value)
            })
            .collect::<Vec<_>>();
        counters.sort_by(|a, b| a.0.cmp(&b.0));
        counters
    }

    #[test]
    fn test_gas_estimation_error_kind() {
        let cases = [
            (
                GasEstimationError::RevertInValidation(ValidationRevert::EntryPoint(
                    "AA26 over verificationGasLimit".to_string(),
                )),
                "revert_in_validation",
            ),
            (
                GasEstimationError::RevertInCallWithMessage("reverted".to_string()),
                "revert_in_call",
            ),
            (
                GasEstimationError::RevertInCallWithBytes(Bytes::new()),
                "revert_in_call",
            ),
            (
                GasEstimationError::CallGasLimitTooLow(1),
                "call_gas_limit_too_low",
            ),
            (GasEstimationError::GasUsedTooLarge, "gas_used_too_large"),
            (
                GasEstimationError::GasFieldTooLarge("callGasLimit", 1),
                "gas_field_too_large",
            ),
            (
                GasEstimationError::GasTotalTooLarge(2, 1),
                "gas_total_too_large",
            ),
            (
                GasEstimationError::UnsupportedAggregator(Address::ZERO),
                "unsupported_aggregator",
            ),
            (
                GasEstimationError::ProviderError(ProviderError::Other(anyhow!("provider"))),
                "provider",
            ),
            (GasEstimationError::Other(anyhow!("other")), "other"),
        ];
        for (error, kind) in cases {
            assert_eq!(error.kind(), kind, "{error:?}");
        }
    }

    #[test]
    fn test_record_estimation_error() {
        let recorder = DebuggingRecorder::new();
        metrics::with_local_recorder(&recorder, || {
            record_estimation_error(ENTRY_POINT, &GasEstimationError::GasUsedTooLarge);
            record_estimation_error(ENTRY_POINT, &GasEstimationError::GasUsedTooLarge);
        });

        assert_eq!(
            counters(&recorder),
            vec![(
                format!(
                    "gas_estimator.errors{{entry_point={ENTRY_POINT},kind=gas_used_too_large}}"
                ),
                DebugValue::Counter(2)
            )]
        );
    }

    #[test]
    fn test_record_clamped_estimate() {
        let recorder = DebuggingRecorder::new();
        metrics::with_local_recorder(&recorder, || {
            // at or below the cap is not clamped
            record_clamped_estimate(ENTRY_POINT, "verification", 99, 100);
            record_clamped_estimate(ENTRY_POINT, "verification", 100, 100);
            record_clamped_estimate(ENTRY_POINT, "verification", 101, 100);
        });

        assert_eq!(
            counters(&recorder),
            vec![(
                format!(
                    "gas_estimator.clamped_estimates{{entry_point={ENTRY_POINT},field=verification}}"
                ),
                DebugValue::Counter(1)
            )]
        );
    }

    fn continuation(min_gas: u64, max_gas: u64) -> Option<Bytes> {
        Some(
            EstimateGasContinuation {
                minGas: U256::from(min_gas),
                maxGas: U256::from(max_gas),
                numRounds: U256::from(1),
            }
            .abi_encode()
            .into(),
        )
    }

    fn converged(gas: u64) -> Option<Bytes> {
        Some(
            EstimateGasResult {
                gas: U256::from(gas),
                numRounds: U256::from(1),
            }
            .abi_encode()
            .into(),
        )
    }

    /// Runs a search whose rounds return `responses` in order, `None` being a failed eth_call.
    async fn search(
        responses: Vec<Option<Bytes>>,
        max_rounds: u32,
    ) -> (
        Result<BinarySearchResult, GasEstimationError>,
        Vec<(String, DebugValue)>,
    ) {
        let responses = Arc::new(responses);
        let calls = Arc::new(AtomicUsize::new(0));
        let round_fn = move |_: u128, _: u128, _: bool| {
            let response = responses[calls.fetch_add(1, Ordering::SeqCst)].clone();
            Box::pin(async move {
                response.ok_or_else(|| GasEstimationError::Other(anyhow!("eth_call failed")))
            })
                as Pin<Box<dyn Future<Output = Result<Bytes, GasEstimationError>> + Send>>
        };

        let recorder = DebuggingRecorder::new();
        let _guard = metrics::set_default_local_recorder(&recorder);
        let result = run_binary_search(round_fn, 1_000_000, max_rounds, ENTRY_POINT, "call").await;
        (result, counters(&recorder))
    }

    fn eth_calls(outcome: &str, calls: f64) -> (String, DebugValue) {
        (
            format!(
                "gas_estimator.eth_calls{{entry_point={ENTRY_POINT},field=call,outcome={outcome}}}"
            ),
            DebugValue::Histogram(vec![calls.into()]),
        )
    }

    #[tokio::test]
    async fn test_binary_search_success() {
        let (result, metrics) = search(vec![continuation(100, 10_000), converged(5_000)], 3).await;

        assert!(matches!(result, Ok(BinarySearchResult::Success(5_000, 2))));
        assert_eq!(metrics, vec![eth_calls("success", 2.0)]);
    }

    #[tokio::test]
    async fn test_binary_search_revert() {
        let revert = EstimateGasRevertAtMax {
            revertData: Bytes::from_static(b"reverted"),
        };
        let (result, metrics) = search(
            vec![continuation(100, 10_000), Some(revert.abi_encode().into())],
            3,
        )
        .await;

        assert!(matches!(result, Ok(BinarySearchResult::Revert(_))));
        assert_eq!(metrics, vec![eth_calls("revert", 2.0)]);
    }

    #[tokio::test]
    async fn test_binary_search_not_converged() {
        let (result, metrics) = search(
            vec![
                continuation(100, 10_000),
                continuation(200, 9_000),
                continuation(300, 8_000),
            ],
            3,
        )
        .await;

        assert!(result.is_err());
        assert_eq!(metrics, vec![eth_calls("not_converged", 3.0)]);
    }

    #[tokio::test]
    async fn test_binary_search_failures_record_eth_calls() {
        let cases = [
            // no progress on the second continuation
            vec![continuation(100, 10_000), continuation(100, 10_000)],
            // the second eth_call fails
            vec![continuation(100, 10_000), None],
            // revert data that is not an estimation result
            vec![continuation(100, 10_000), Some(Bytes::from_static(b"bad"))],
        ];
        for responses in cases {
            let (result, metrics) = search(responses, 3).await;

            assert!(result.is_err());
            assert_eq!(metrics, vec![eth_calls("error", 2.0)]);
        }
    }
}
