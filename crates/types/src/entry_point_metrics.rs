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

//! Metrics for entry point errors, shared across the pool, builder and RPC crates.

use std::sync::Once;

use alloy_primitives::Address;
use metrics::Counter;
use metrics_derive::Metrics;

use crate::validation_results::AaErrorCode;

/// Where an entry point AA error was observed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AaErrorStage {
    /// Gas estimation (`eth_estimateUserOperationGas`)
    Estimation,
    /// Validation when an operation is added to the pool (`eth_sendUserOperation`)
    PoolAdmission,
    /// Re-simulation of a pool operation while building a bundle
    BundleRevalidation,
    /// Simulation of the full `handleOps` call while building a bundle
    BundleHandleOps,
    /// A mined bundle transaction that reverted
    Onchain,
}

impl AaErrorStage {
    /// Returns the value used for the `stage` label.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Estimation => "estimation",
            Self::PoolAdmission => "pool_admission",
            Self::BundleRevalidation => "bundle_revalidation",
            Self::BundleHandleOps => "bundle_handle_ops",
            Self::Onchain => "onchain",
        }
    }
}

#[derive(Metrics)]
#[metrics(scope = "entry_point")]
struct AaErrorMetrics {
    #[metric(
        describe = "the count of entry point AA errors, by entry point, stage and AA code (none when the error carries no AA code)."
    )]
    aa_errors: Counter,
}

static DESCRIBE: Once = Once::new();

/// Counts one entry point AA error.
///
/// `code` must come from [`AaErrorCode`] so the `aa_code` label stays bounded.
pub fn record_aa_error(stage: AaErrorStage, entry_point: Address, code: AaErrorCode<'_>) {
    // `new_with_labels` does not register the metric description
    DESCRIBE.call_once(AaErrorMetrics::describe);

    AaErrorMetrics::new_with_labels(&[
        ("stage", stage.as_str().to_string()),
        ("aa_code", code.as_label().to_string()),
        ("entry_point", entry_point.to_string()),
    ])
    .aa_errors
    .increment(1);
}

#[cfg(test)]
mod tests {
    use alloy_primitives::address;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};

    use super::*;

    #[test]
    fn test_record_aa_error() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let entry_point = address!("0000000071727De22E5E9d8BAf0edAc6f37da032");

        metrics::with_local_recorder(&recorder, || {
            record_aa_error(
                AaErrorStage::PoolAdmission,
                entry_point,
                AaErrorCode::Code("AA26"),
            );
            record_aa_error(
                AaErrorStage::PoolAdmission,
                entry_point,
                AaErrorCode::Code("AA26"),
            );
            record_aa_error(AaErrorStage::Onchain, entry_point, AaErrorCode::Uncoded);
        });

        let mut counters = snapshotter
            .snapshot()
            .into_vec()
            .into_iter()
            .map(|(key, _, _, value)| {
                let key = key.key();
                assert_eq!(key.name(), "entry_point.aa_errors");
                let mut labels = key
                    .labels()
                    .map(|label| format!("{}={}", label.key(), label.value()))
                    .collect::<Vec<_>>();
                labels.sort();
                (labels, value)
            })
            .collect::<Vec<_>>();
        counters.sort_by(|a, b| a.0.cmp(&b.0));

        let ep = entry_point.to_string();
        assert_eq!(
            counters,
            vec![
                (
                    vec![
                        "aa_code=AA26".to_string(),
                        format!("entry_point={ep}"),
                        "stage=pool_admission".to_string(),
                    ],
                    DebugValue::Counter(2),
                ),
                (
                    vec![
                        "aa_code=none".to_string(),
                        format!("entry_point={ep}"),
                        "stage=onchain".to_string(),
                    ],
                    DebugValue::Counter(1),
                ),
            ]
        );
    }
}
