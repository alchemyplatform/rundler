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

//! Metrics comparing what a mined bundle cost the bundler with what the entry point paid back.

use std::sync::Once;

use alloy_primitives::{Address, U256};
use metrics::{Counter, Histogram};
use metrics_derive::Metrics;

use crate::transaction_tracker::MinedUserOpEvent;

/// Names of the bundle compensation ratio histograms, without the global metrics prefix.
pub const BUNDLE_RATIO_HISTOGRAMS: &[&str] = &[
    "builder.bundle_gas_compensation_ratio",
    "builder.bundle_fee_compensation_ratio",
];

/// Histogram buckets for the compensation ratios. Values above 1 are expected for larger
/// bundles, since each op's pre-verification gas assumes a bundle of one.
pub const BUNDLE_RATIO_BUCKETS: &[f64] = &[
    0.0, 0.5, 0.8, 0.9, 0.95, 1.0, 1.05, 1.1, 1.25, 1.5, 2.0, 3.0, 5.0,
];

/// Names of the op count per bundle histograms, without the global metrics prefix.
pub const BUNDLE_OP_COUNT_HISTOGRAMS: &[&str] =
    &["builder.bundle_ops", "builder.bundle_bundler_sponsored_ops"];

/// Histogram buckets for the number of ops in a bundle.
pub const BUNDLE_OP_COUNT_BUCKETS: &[f64] =
    &[0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 10.0, 20.0, 50.0, 100.0, 128.0];

const WEI_PER_GWEI: U256 = U256::from_limbs([1_000_000_000, 0, 0, 0]);

#[derive(Metrics)]
#[metrics(scope = "builder")]
struct BundleCompensationCounters {
    #[metric(
        describe = "the fee paid for mined bundle transactions in gwei (gas used times effective gas price)."
    )]
    bundle_fee_paid_gwei: Counter,
    #[metric(
        describe = "the compensation paid to the bundler by the entry point for mined bundles in gwei (sum of actualGasCost)."
    )]
    bundle_compensation_gwei: Counter,
}

#[derive(Metrics)]
#[metrics(scope = "builder")]
struct BundleCompensationRatios {
    #[metric(
        describe = "the gas the entry point charged ops for divided by the gas the bundle transaction used, for successful bundles."
    )]
    bundle_gas_compensation_ratio: Histogram,
    #[metric(
        describe = "the compensation paid to the bundler divided by the bundle transaction fee, for successful bundles."
    )]
    bundle_fee_compensation_ratio: Histogram,
}

#[derive(Metrics)]
#[metrics(scope = "builder")]
struct BundleOpCounts {
    #[metric(describe = "the number of user operations in a successful mined bundle.")]
    bundle_ops: Histogram,
    #[metric(
        describe = "the number of bundler sponsored user operations (actualGasCost of 0) in a successful mined bundle."
    )]
    bundle_bundler_sponsored_ops: Histogram,
}

static DESCRIBE: Once = Once::new();

fn bundle_size_label(ops: usize) -> &'static str {
    match ops {
        0..=1 => "1",
        2..=4 => "2-4",
        5..=9 => "5-9",
        _ => "10+",
    }
}

fn wei_to_gwei(wei: U256) -> u64 {
    (wei / WEI_PER_GWEI).saturating_to()
}

fn ratio(numerator: U256, denominator: U256) -> Option<f64> {
    if denominator.is_zero() {
        return None;
    }
    Some(numerator.saturating_to::<u128>() as f64 / denominator.saturating_to::<u128>() as f64)
}

/// Records what a mined bundle cost the bundler and what the entry point paid back.
///
/// Only events emitted by `entry_point` are counted. Reverted bundles have no events, so they
/// only update the counters.
pub(crate) fn record_mined_bundle(
    entry_point: Address,
    sender: Address,
    is_success: bool,
    gas_used: Option<u64>,
    gas_price: Option<u128>,
    events: &[MinedUserOpEvent],
) {
    // `new_with_labels` does not register the metric descriptions
    DESCRIBE.call_once(|| {
        BundleCompensationCounters::describe();
        BundleCompensationRatios::describe();
        BundleOpCounts::describe();
    });

    let events = events
        .iter()
        .filter(|event| event.entry_point == entry_point)
        .collect::<Vec<_>>();
    let compensation = events.iter().fold(U256::ZERO, |sum, event| {
        sum.saturating_add(event.actual_gas_cost)
    });
    let fee = gas_used
        .zip(gas_price)
        .map(|(used, price)| U256::from(used) * U256::from(price));

    let counters = BundleCompensationCounters::new_with_labels(&[
        ("entry_point", entry_point.to_string()),
        ("sender", sender.to_string()),
        ("success", is_success.to_string()),
    ]);
    if let Some(fee) = fee {
        counters.bundle_fee_paid_gwei.increment(wei_to_gwei(fee));
    }
    counters
        .bundle_compensation_gwei
        .increment(wei_to_gwei(compensation));

    let Some(gas_used) = gas_used.filter(|used| *used > 0) else {
        return;
    };
    if !is_success || events.is_empty() {
        return;
    }

    let sponsored_ops = events
        .iter()
        .filter(|event| event.actual_gas_cost.is_zero())
        .count();
    let op_counts = BundleOpCounts::new_with_labels(&[("entry_point", entry_point.to_string())]);
    op_counts.bundle_ops.record(events.len() as f64);
    op_counts
        .bundle_bundler_sponsored_ops
        .record(sponsored_ops as f64);

    let ratios = BundleCompensationRatios::new_with_labels(&[
        ("entry_point", entry_point.to_string()),
        ("bundle_size", bundle_size_label(events.len()).to_string()),
        ("has_bundler_sponsored_op", (sponsored_ops > 0).to_string()),
    ]);
    let charged_gas = events.iter().fold(U256::ZERO, |sum, event| {
        sum.saturating_add(event.actual_gas_used)
    });
    if let Some(gas_ratio) = ratio(charged_gas, U256::from(gas_used)) {
        ratios.bundle_gas_compensation_ratio.record(gas_ratio);
    }
    if let Some(fee_ratio) = fee.and_then(|fee| ratio(compensation, fee)) {
        ratios.bundle_fee_compensation_ratio.record(fee_ratio);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use alloy_primitives::address;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};

    use super::*;

    const ENTRY_POINT: Address = address!("0000000071727De22E5E9d8BAf0edAc6f37da032");
    const SENDER: Address = address!("00000000000000000000000000000000000000aa");
    const OTHER: Address = address!("00000000000000000000000000000000000000bb");

    fn event(entry_point: Address, actual_gas_cost: u64, actual_gas_used: u64) -> MinedUserOpEvent {
        MinedUserOpEvent {
            entry_point,
            actual_gas_cost: U256::from(actual_gas_cost),
            actual_gas_used: U256::from(actual_gas_used),
        }
    }

    /// Records one bundle and returns `"name{sorted labels}" => value` for every metric touched.
    fn record(
        is_success: bool,
        gas_used: Option<u64>,
        gas_price: Option<u128>,
        events: &[MinedUserOpEvent],
    ) -> BTreeMap<String, DebugValue> {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            record_mined_bundle(ENTRY_POINT, SENDER, is_success, gas_used, gas_price, events);
        });

        snapshotter
            .snapshot()
            .into_vec()
            .into_iter()
            .map(|(key, _, _, value)| {
                let key = key.key();
                let mut labels = key
                    .labels()
                    .filter(|label| !matches!(label.key(), "entry_point" | "sender"))
                    .map(|label| format!("{}={}", label.key(), label.value()))
                    .collect::<Vec<_>>();
                labels.sort();
                (format!("{}{{{}}}", key.name(), labels.join(",")), value)
            })
            .collect()
    }

    #[test]
    fn test_bundle_size_label() {
        assert_eq!(bundle_size_label(1), "1");
        assert_eq!(bundle_size_label(2), "2-4");
        assert_eq!(bundle_size_label(4), "2-4");
        assert_eq!(bundle_size_label(5), "5-9");
        assert_eq!(bundle_size_label(9), "5-9");
        assert_eq!(bundle_size_label(10), "10+");
    }

    #[test]
    fn test_wei_to_gwei() {
        assert_eq!(wei_to_gwei(U256::from(1_999_999_999_u64)), 1);
        assert_eq!(wei_to_gwei(U256::MAX), u64::MAX);
    }

    #[test]
    fn test_successful_bundle() {
        let metrics = record(
            true,
            Some(300_000),
            Some(10_000_000_000),
            &[
                event(ENTRY_POINT, 1_500_000_000_000_000, 150_000),
                event(ENTRY_POINT, 1_800_000_000_000_000, 180_000),
                event(ENTRY_POINT, 0, 30_000),
                // not our entry point, e.g. an account emitting a look-alike event
                event(OTHER, 1_000_000_000_000_000_000, 1_000_000),
            ],
        );

        let ratio_labels = "{bundle_size=2-4,has_bundler_sponsored_op=true}";
        assert_eq!(
            metrics,
            BTreeMap::from([
                (
                    "builder.bundle_fee_paid_gwei{success=true}".to_string(),
                    // 300_000 gas * 10 gwei
                    DebugValue::Counter(3_000_000)
                ),
                (
                    "builder.bundle_compensation_gwei{success=true}".to_string(),
                    DebugValue::Counter(3_300_000)
                ),
                (
                    "builder.bundle_ops{}".to_string(),
                    DebugValue::Histogram(vec![3.0.into()])
                ),
                (
                    "builder.bundle_bundler_sponsored_ops{}".to_string(),
                    DebugValue::Histogram(vec![1.0.into()])
                ),
                (
                    format!("{}{ratio_labels}", BUNDLE_RATIO_HISTOGRAMS[0]),
                    // 360_000 charged / 300_000 used
                    DebugValue::Histogram(vec![1.2.into()])
                ),
                (
                    format!("{}{ratio_labels}", BUNDLE_RATIO_HISTOGRAMS[1]),
                    // 3_300_000 gwei paid back / 3_000_000 gwei fee
                    DebugValue::Histogram(vec![1.1.into()])
                ),
            ])
        );
        assert!(BUNDLE_OP_COUNT_HISTOGRAMS.iter().all(|name| {
            metrics
                .keys()
                .any(|key| key.starts_with(&format!("{name}{{")))
        }));
    }

    #[test]
    fn test_reverted_bundle_only_updates_counters() {
        let metrics = record(false, Some(100_000), Some(1_000_000_000), &[]);

        assert_eq!(
            metrics,
            BTreeMap::from([
                (
                    "builder.bundle_fee_paid_gwei{success=false}".to_string(),
                    DebugValue::Counter(100_000)
                ),
                (
                    "builder.bundle_compensation_gwei{success=false}".to_string(),
                    DebugValue::Counter(0)
                ),
            ])
        );
    }

    #[test]
    fn test_unknown_or_zero_fee_skips_fee_ratio() {
        for gas_price in [None, Some(0)] {
            let metrics = record(
                true,
                Some(100_000),
                gas_price,
                &[event(ENTRY_POINT, 0, 90_000)],
            );

            let ratio_labels = "{bundle_size=1,has_bundler_sponsored_op=true}";
            assert_eq!(
                metrics.get(&format!("{}{ratio_labels}", BUNDLE_RATIO_HISTOGRAMS[0])),
                Some(&DebugValue::Histogram(vec![0.9.into()]))
            );
            // registered alongside the gas ratio, but no fee ratio sample is recorded
            assert_eq!(
                metrics.get(&format!("{}{ratio_labels}", BUNDLE_RATIO_HISTOGRAMS[1])),
                Some(&DebugValue::Histogram(vec![]))
            );
            assert_eq!(
                metrics.get("builder.bundle_fee_paid_gwei{success=true}"),
                Some(&DebugValue::Counter(0))
            );
        }
    }
}
