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

//! Helpers for reservoir-mode estimates: reading simulations of `simulateHandleOp`, and searching
//! for the least reservoir an op runs with.

use std::future::Future;

use alloy_primitives::Address;
use alloy_sol_types::SolEvent;
use futures_util::future::try_join_all;
use rundler_contracts::v0_7::IEntryPoint::UserOperationEvent;
use rundler_provider::SimulatedLog;

/// EIP-8037 state gas of one new storage slot
const NEW_SLOT_STATE_GAS: u128 = 97_920;

/// The least state gas a reservoir-mode estimate measures for an op to need a reservoir: one new
/// slot. The measurement is approximate (see `metered_gas`), so an op without state does not
/// measure as exactly 0.
pub(crate) const MIN_RESERVOIR_STATE_GAS: u128 = NEW_SLOT_STATE_GAS;

/// How far a reservoir-mode op's PVG surplus is kept above the reservoir threshold, so the op is
/// still classified as reservoir mode at admission if its threshold rises a little from the
/// estimate's: e.g. a shorter signature or paymaster data, or a lower limit lowers its
/// computation gas.
pub(crate) const RESERVOIR_THRESHOLD_MARGIN: u128 = NEW_SLOT_STATE_GAS;

/// The reservoir a reservoir-mode op's PVG pays for: its state gas, but at least
/// [`RESERVOIR_THRESHOLD_MARGIN`] above `threshold`, so admission classifies it as reservoir
/// mode. Any unused part of the reservoir is refunded to the bundler.
pub(crate) fn padded_reservoir(state_gas: u128, threshold: u128) -> u128 {
    state_gas.max(threshold + RESERVOIR_THRESHOLD_MARGIN)
}

/// The op's `UserOperationEvent`, if the entry point emitted it in a simulated call's logs.
pub(crate) fn user_operation_event(
    logs: &[SimulatedLog],
    entry_point: Address,
) -> Option<UserOperationEvent> {
    logs.iter()
        .filter(|log| log.address == entry_point)
        .find_map(|log| {
            if log.topics.first() != Some(&UserOperationEvent::SIGNATURE_HASH) {
                return None;
            }
            UserOperationEvent::decode_raw_log(log.topics.iter().copied(), &log.data).ok()
        })
}

/// `UserOperationEvent.success` of the op, if the entry point emitted the event in a simulated
/// call's logs.
pub(crate) fn user_operation_event_success(
    logs: &[SimulatedLog],
    entry_point: Address,
) -> Option<bool> {
    user_operation_event(logs, entry_point).map(|event| event.success)
}

/// The gas the entry point metered for an op from the `actualGasUsed` it reported, less the
/// penalty on unused execution gas, given the op's `preOpGas` and its call gas and postOp limits.
///
/// This is v0.7's penalty: 10% of the call gas and postOp limits' unused part together. v0.8+
/// charges it on each limit separately, and only above 40,000 unused, so this can be off by
/// about that, and 10% of the postOp limit.
pub(crate) fn metered_gas(
    actual_gas_used: u128,
    pre_op_gas: u128,
    execution_gas_limit: u128,
) -> u128 {
    let execution_charged = actual_gas_used.saturating_sub(pre_op_gas);
    if execution_charged >= execution_gas_limit {
        return actual_gas_used;
    }
    // charged = used + (limit - used) / 10
    let execution_used = (execution_charged * 10).saturating_sub(execution_gas_limit) / 9;
    pre_op_gas + execution_used.min(execution_charged)
}

/// Guesses tried in parallel per round of a [`least_passing`] search
const SEARCH_GUESSES: u128 = 4;

/// Rounds a [`least_passing`] search runs at most: each one narrows the range to a fifth.
const SEARCH_MAX_ROUNDS: usize = 6;

/// How close a [`least_passing`] search gets to the least passing value: 1% of it, but at least
/// one new slot's state gas.
fn search_tolerance(value: u128) -> u128 {
    (value / 100).max(NEW_SLOT_STATE_GAS)
}

/// A value in `(lo, hi]` that `passes`, at most about [`search_tolerance`] above the least one,
/// given that `lo` fails and `hi` passes. Tries [`SEARCH_GUESSES`] values per round in parallel.
pub(crate) async fn least_passing<F, Fut>(
    mut lo: u128,
    mut hi: u128,
    passes: F,
) -> anyhow::Result<u128>
where
    F: Fn(u128) -> Fut,
    Fut: Future<Output = anyhow::Result<bool>>,
{
    for _ in 0..SEARCH_MAX_ROUNDS {
        if hi.saturating_sub(lo) <= search_tolerance(hi) {
            break;
        }
        let guesses: Vec<u128> = (1..=SEARCH_GUESSES)
            .map(|i| lo + (hi - lo) * i / (SEARCH_GUESSES + 1))
            .collect();
        let results = try_join_all(guesses.iter().map(|&guess| passes(guess))).await?;
        match results.iter().position(|&passed| passed) {
            Some(i) => {
                hi = guesses[i];
                if i > 0 {
                    lo = guesses[i - 1];
                }
            }
            None => lo = guesses[guesses.len() - 1],
        }
    }
    Ok(hi)
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{B256, Bytes, U256, address};
    use alloy_sol_types::SolValue;

    use super::*;

    const EP: Address = address!("0000000071727De22E5E9d8BAf0edAc6f37da032");
    const SENDER: Address = address!("fd5d8F31bDd2A41Aca1866a51C6b11DC0C6fA545");

    #[test]
    fn reads_user_operation_event_from_logs() {
        let log = |address, success: bool| SimulatedLog {
            address,
            topics: vec![
                UserOperationEvent::SIGNATURE_HASH,
                B256::ZERO,
                B256::ZERO,
                B256::ZERO,
            ],
            data: Bytes::from(
                (U256::ZERO, success, U256::from(1), U256::from(2)).abi_encode_params(),
            ),
        };
        assert_eq!(
            user_operation_event_success(&[log(EP, true)], EP),
            Some(true)
        );
        assert_eq!(
            user_operation_event_success(&[log(EP, false)], EP),
            Some(false)
        );
        // not emitted by the entry point
        assert_eq!(user_operation_event_success(&[log(SENDER, true)], EP), None);
        assert_eq!(user_operation_event_success(&[], EP), None);
    }

    #[test]
    fn metered_gas_removes_the_unused_gas_penalty() {
        // 60,000 of validation, 500,000 of execution under a 15M limit: charged 1,450,000 more
        let pre_op_gas = 60_000;
        let limit = 15_000_000;
        let charged = pre_op_gas + 500_000 + (limit - 500_000) / 10;
        assert_eq!(
            metered_gas(charged, pre_op_gas, limit),
            pre_op_gas + 500_000
        );
        // all of the limit used: no penalty
        assert_eq!(
            metered_gas(pre_op_gas + limit, pre_op_gas, limit),
            pre_op_gas + limit
        );
        // nothing used
        assert_eq!(
            metered_gas(pre_op_gas + limit / 10, pre_op_gas, limit),
            pre_op_gas
        );
    }

    #[test]
    fn reservoir_keeps_a_margin_above_the_threshold() {
        // well above the threshold: the state gas itself
        assert_eq!(padded_reservoir(37_784_880, 1_000_000), 37_784_880);
        // below it, at it, or just above it: padded to the threshold plus the margin
        for state_gas in [500_000, 1_000_000, 1_000_001] {
            assert_eq!(
                padded_reservoir(state_gas, 1_000_000),
                1_000_000 + RESERVOIR_THRESHOLD_MARGIN
            );
        }
    }

    #[tokio::test]
    async fn least_passing_is_within_tolerance() {
        for least in [1_000_001u128, 25_000_000, 44_168_000, 74_999_999] {
            let found = least_passing(1_000_000, 75_000_000, |value| async move {
                anyhow::Ok(value >= least)
            })
            .await
            .unwrap();
            assert!(found >= least, "{found} < {least}");
            assert!(
                found <= least + search_tolerance(found),
                "{found} too far above {least}"
            );
        }
    }

    #[tokio::test]
    async fn least_passing_stops_at_errors() {
        let result = least_passing(0, 75_000_000, |_| async {
            Err::<bool, _>(anyhow::anyhow!("trace failed"))
        })
        .await;
        assert!(result.is_err());
    }
}
