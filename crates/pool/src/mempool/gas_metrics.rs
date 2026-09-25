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

//! Metrics comparing user operation gas limits with the gas actually used.

use std::sync::Once;

use alloy_primitives::{Address, U256};
use metrics::Histogram;
use metrics_derive::Metrics;
use rundler_types::{UserOperation, UserOperationVariant};

/// Names of the gas efficiency histograms, without the global metrics prefix.
pub const GAS_EFFICIENCY_HISTOGRAMS: &[&str] = &["op_pool.mined_op_gas_efficiency"];

/// Histogram buckets for the used / limit ratios, denser near 1.0 where limits are tight.
pub const GAS_EFFICIENCY_BUCKETS: &[f64] = &[
    0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.85, 0.9, 0.95, 0.98, 1.0, 1.05,
];

/// Bounded labels describing which parts of an operation may write new state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OpGasLabels {
    has_paymaster: bool,
    has_factory: bool,
    has_7702_auth: bool,
    fresh_nonce_slot: bool,
}

impl OpGasLabels {
    fn from_op(uo: &UserOperationVariant) -> Self {
        Self {
            has_paymaster: uo.paymaster().is_some(),
            has_factory: uo.factory().is_some(),
            has_7702_auth: uo.authorization_tuple().is_some(),
            // the low 64 bits are the sequence of the nonce key, 0 means its slot is still empty
            fresh_nonce_slot: (uo.nonce() & U256::from(u64::MAX)).is_zero(),
        }
    }

    fn to_labels(self, entry_point: Address) -> Vec<(&'static str, String)> {
        vec![
            ("entry_point", entry_point.to_string()),
            ("has_paymaster", self.has_paymaster.to_string()),
            ("has_factory", self.has_factory.to_string()),
            ("has_7702_auth", self.has_7702_auth.to_string()),
            ("fresh_nonce_slot", self.fresh_nonce_slot.to_string()),
        ]
    }
}

/// The gas the entry point budgets for an operation when computing its required prefund.
fn entry_point_gas_limit(uo: &UserOperationVariant) -> u128 {
    match uo {
        // v0.6 applies the verification gas limit to validation, paymaster validation and postOp
        UserOperationVariant::V0_6(op) => {
            let mul = if op.paymaster().is_some() { 3 } else { 1 };
            op.pre_verification_gas()
                .saturating_add(op.call_gas_limit())
                .saturating_add(op.verification_gas_limit().saturating_mul(mul))
        }
        UserOperationVariant::V0_7(op) => op.total_gas_limit(),
    }
}

fn efficiency(used: u128, limit: u128) -> Option<f64> {
    if limit == 0 {
        return None;
    }
    Some(used as f64 / limit as f64)
}

#[derive(Metrics)]
#[metrics(scope = "op_pool")]
struct MinedOpGasMetrics {
    #[metric(
        describe = "the fraction of the gas limit, including preVerificationGas, a mined op used according to its UserOperationEvent. has_7702_auth means the op carried an authorization, not necessarily a first delegation."
    )]
    mined_op_gas_efficiency: Histogram,
}

static DESCRIBE_MINED: Once = Once::new();

/// Records how much of its gas limit a mined operation used.
///
/// `uo` must be the operation that was mined, not a replacement with the same id.
pub(crate) fn record_mined_op_gas_efficiency(
    entry_point: Address,
    uo: &UserOperationVariant,
    success: bool,
    actual_gas_used: U256,
) {
    let Some(ratio) = efficiency(
        actual_gas_used.saturating_to::<u128>(),
        entry_point_gas_limit(uo),
    ) else {
        return;
    };

    // `new_with_labels` does not register the metric description
    DESCRIBE_MINED.call_once(MinedOpGasMetrics::describe);

    let mut labels = OpGasLabels::from_op(uo).to_labels(entry_point);
    labels.push(("success", success.to_string()));
    MinedOpGasMetrics::new_with_labels(&labels)
        .mined_op_gas_efficiency
        .record(ratio);
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Bytes, address};
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use rundler_types::{
        EntryPointVersion, authorization::Eip7702Auth, chain::ChainSpec, v0_6, v0_7,
    };

    use super::*;

    const ENTRY_POINT: Address = address!("0000000071727De22E5E9d8BAf0edAc6f37da032");
    const PAYMASTER: Address = address!("00000000000000000000000000000000000000aa");
    const FACTORY: Address = address!("00000000000000000000000000000000000000bb");

    fn v0_7_builder(chain_spec: &ChainSpec, nonce: U256) -> v0_7::UserOperationBuilder<'_> {
        v0_7::UserOperationBuilder::new(
            chain_spec,
            EntryPointVersion::V0_7,
            v0_7::UserOperationRequiredFields {
                sender: Address::ZERO,
                nonce,
                call_data: Bytes::new(),
                call_gas_limit: 100_000,
                verification_gas_limit: 200_000,
                pre_verification_gas: 50_000,
                max_priority_fee_per_gas: 1,
                max_fee_per_gas: 1,
                signature: Bytes::new(),
            },
        )
    }

    fn v0_6_op(paymaster: bool) -> UserOperationVariant {
        let chain_spec = ChainSpec::default();
        let paymaster_and_data = if paymaster {
            Bytes::copy_from_slice(PAYMASTER.as_slice())
        } else {
            Bytes::new()
        };
        v0_6::UserOperationBuilder::new(
            &chain_spec,
            v0_6::UserOperationRequiredFields {
                call_gas_limit: 100_000,
                verification_gas_limit: 200_000,
                pre_verification_gas: 50_000,
                paymaster_and_data,
                ..Default::default()
            },
        )
        .build()
        .into()
    }

    #[test]
    fn test_labels_from_op() {
        let chain_spec = ChainSpec::default();

        let plain: UserOperationVariant = v0_7_builder(&chain_spec, U256::from(1)).build().into();
        assert_eq!(
            OpGasLabels::from_op(&plain),
            OpGasLabels {
                has_paymaster: false,
                has_factory: false,
                has_7702_auth: false,
                fresh_nonce_slot: false,
            }
        );

        let full: UserOperationVariant = v0_7_builder(&chain_spec, U256::ZERO)
            .paymaster(PAYMASTER, 10_000, 10_000, Bytes::new())
            .factory(FACTORY, Bytes::new())
            .authorization_tuple(Eip7702Auth::default())
            .build()
            .into();
        assert_eq!(
            OpGasLabels::from_op(&full),
            OpGasLabels {
                has_paymaster: true,
                has_factory: true,
                has_7702_auth: true,
                fresh_nonce_slot: true,
            }
        );
    }

    #[test]
    fn test_fresh_nonce_slot() {
        let chain_spec = ChainSpec::default();
        let fresh = |nonce: U256| {
            let op: UserOperationVariant = v0_7_builder(&chain_spec, nonce).build().into();
            OpGasLabels::from_op(&op).fresh_nonce_slot
        };

        let key = U256::from(7) << 64;
        assert!(fresh(U256::ZERO));
        assert!(!fresh(U256::from(1)));
        assert!(fresh(key));
        assert!(!fresh(key + U256::from(1)));
    }

    #[test]
    fn test_entry_point_gas_limit() {
        // pvg + cgl + vgl
        assert_eq!(entry_point_gas_limit(&v0_6_op(false)), 350_000);
        // pvg + cgl + 3 * vgl
        assert_eq!(entry_point_gas_limit(&v0_6_op(true)), 750_000);

        let chain_spec = ChainSpec::default();
        let v0_7_op: UserOperationVariant = v0_7_builder(&chain_spec, U256::ZERO)
            .paymaster(PAYMASTER, 30_000, 20_000, Bytes::new())
            .build()
            .into();
        // pvg + vgl + pm vgl + cgl + pm postOp
        assert_eq!(entry_point_gas_limit(&v0_7_op), 400_000);
    }

    #[test]
    fn test_efficiency() {
        assert_eq!(efficiency(50, 100), Some(0.5));
        assert_eq!(efficiency(0, 0), None);
    }

    #[test]
    fn test_record_mined_op_gas_efficiency() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let chain_spec = ChainSpec::default();
        let op: UserOperationVariant = v0_7_builder(&chain_spec, U256::from(1)).build().into();

        metrics::with_local_recorder(&recorder, || {
            record_mined_op_gas_efficiency(ENTRY_POINT, &op, false, U256::from(175_000));
        });

        let snapshot = snapshotter.snapshot().into_vec();
        assert_eq!(snapshot.len(), 1);
        let (key, _, _, value) = &snapshot[0];
        let key = key.key();
        assert_eq!(key.name(), GAS_EFFICIENCY_HISTOGRAMS[0]);

        let mut labels = key
            .labels()
            .map(|label| format!("{}={}", label.key(), label.value()))
            .collect::<Vec<_>>();
        labels.sort();
        assert_eq!(
            labels,
            vec![
                format!("entry_point={ENTRY_POINT}"),
                "fresh_nonce_slot=false".to_string(),
                "has_7702_auth=false".to_string(),
                "has_factory=false".to_string(),
                "has_paymaster=false".to_string(),
                "success=false".to_string(),
            ]
        );
        // 175_000 used of 350_000
        assert_eq!(value, &DebugValue::Histogram(vec![0.5.into()]));
    }
}
