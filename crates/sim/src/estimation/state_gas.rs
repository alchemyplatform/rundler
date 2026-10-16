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

//! Helpers for reservoir-mode estimates: reading traces and simulations of `simulateHandleOp`,
//! and searching for the least reservoir an op runs with.

use std::future::Future;

use alloy_primitives::Address;
use alloy_sol_types::SolEvent;
use futures_util::future::try_join_all;
use rundler_contracts::v0_7::IEntryPoint::UserOperationEvent;
use rundler_provider::{GethDebugTracerCallFrame as CallFrame, SimulatedLog};

/// EIP-8037 state gas of one new storage slot
const NEW_SLOT_STATE_GAS: u128 = 97_920;

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

/// `UserOperationEvent.success` of the op, if the entry point emitted the event in the trace.
pub(crate) fn user_operation_succeeded(frame: &CallFrame, entry_point: Address) -> Option<bool> {
    frame
        .logs
        .iter()
        .filter(|log| log.address == Some(entry_point))
        .find_map(|log| {
            let topics = log.topics.as_ref()?;
            if topics.first() != Some(&UserOperationEvent::SIGNATURE_HASH) {
                return None;
            }
            let data = log.data.as_ref()?;
            UserOperationEvent::decode_raw_log(topics.iter().copied(), data)
                .ok()
                .map(|event| event.success)
        })
        .or_else(|| {
            frame
                .calls
                .iter()
                .find_map(|call| user_operation_succeeded(call, entry_point))
        })
}

/// `UserOperationEvent.success` of the op, if the entry point emitted the event in a simulated
/// call's logs.
pub(crate) fn user_operation_event_success(
    logs: &[SimulatedLog],
    entry_point: Address,
) -> Option<bool> {
    logs.iter()
        .filter(|log| log.address == entry_point)
        .find_map(|log| {
            if log.topics.first() != Some(&UserOperationEvent::SIGNATURE_HASH) {
                return None;
            }
            UserOperationEvent::decode_raw_log(log.topics.iter().copied(), &log.data)
                .ok()
                .map(|event| event.success)
        })
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
    use rundler_provider::GethDebugTracerCallFrame;

    use super::*;

    const EP: Address = address!("0000000071727De22E5E9d8BAf0edAc6f37da032");
    const SENDER: Address = address!("fd5d8F31bDd2A41Aca1866a51C6b11DC0C6fA545");
    const CALLER: Address = address!("0643866dA50efE0b055Cd15aF95191968c8411b5");

    fn frame(from: Address, to: Address, gas_used: u64, calls: Vec<CallFrame>) -> CallFrame {
        GethDebugTracerCallFrame {
            from,
            to: Some(to),
            gas_used: U256::from(gas_used),
            calls,
            ..Default::default()
        }
    }

    fn user_operation_event(success: bool) -> CallFrame {
        let mut root = frame(CALLER, EP, 0, vec![]);
        root.logs
            .push(rundler_provider::GethDebugTracerCallLogFrame {
                address: Some(EP),
                topics: Some(vec![
                    UserOperationEvent::SIGNATURE_HASH,
                    B256::ZERO,
                    B256::ZERO,
                    B256::ZERO,
                ]),
                data: Some(Bytes::from(
                    (U256::ZERO, success, U256::from(1), U256::from(2)).abi_encode_params(),
                )),
                ..Default::default()
            });
        root
    }

    #[test]
    fn reads_user_operation_event() {
        assert_eq!(
            user_operation_succeeded(&user_operation_event(true), EP),
            Some(true)
        );
        assert_eq!(
            user_operation_succeeded(&user_operation_event(false), EP),
            Some(false)
        );
        // nested in a sub-call
        let nested = frame(CALLER, EP, 0, vec![user_operation_event(true)]);
        assert_eq!(user_operation_succeeded(&nested, EP), Some(true));
        assert_eq!(
            user_operation_succeeded(&frame(CALLER, EP, 0, vec![]), EP),
            None
        );
    }

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
