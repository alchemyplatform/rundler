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

//! Reading a reservoir-mode estimate out of state-gas traces of `simulateHandleOp`.

use std::future::Future;

use alloy_primitives::Address;
use alloy_sol_types::{SolCall, SolEvent};
use futures_util::future::try_join_all;
use rundler_contracts::v0_7::{
    IEntryPoint::UserOperationEvent, IEntryPointSimulations::simulateHandleOpCall,
    ReservoirProbe::probeCall,
};
use rundler_provider::GethDebugTracerCallFrame as CallFrame;

use super::CALL_GAS_BUFFER_VALUE;
use crate::MIN_CALL_GAS_LIMIT;

/// EIP-8037 state gas of one new storage slot. The least call gas headroom a reservoir-mode
/// estimate keeps, so one slot of state drift between estimation and inclusion does not run the
/// op out of gas.
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

/// Percentage of the execution gas a reservoir-mode call gas limit keeps as headroom, if more
/// than [`NEW_SLOT_STATE_GAS`].
const CALL_GAS_HEADROOM_PERCENT: u128 = 10;

/// The entry point's call into the sender during the op's execution phase: the sender call made
/// from `innerHandleOp` (the entry point calling itself).
pub(crate) fn find_execution_frame(
    frame: &CallFrame,
    entry_point: Address,
    sender: Address,
) -> Option<&CallFrame> {
    if frame.from == entry_point
        && frame.to == Some(entry_point)
        && let Some(call) = frame
            .calls
            .iter()
            .find(|call| call.from == entry_point && call.to == Some(sender))
    {
        return Some(call);
    }
    frame
        .calls
        .iter()
        .find_map(|call| find_execution_frame(call, entry_point, sender))
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

/// The call gas limit of a reservoir-mode op, which covers execution only.
///
/// `execution_frame_gas` is the gas the sender's execution call used in a simulation, and
/// `execution_state_gas` the part of it that was state: all of execution's state if calls get no
/// reservoir, none if they do. The frame's gas used, rather than a binary search, keeps the limit
/// tight: a search would also keep the 1/64 of the state gas withheld at each nested call.
pub(crate) fn reservoir_call_gas_limit(
    execution_frame_gas: u128,
    execution_state_gas: u128,
) -> u128 {
    let execution_gas = execution_frame_gas.saturating_sub(execution_state_gas);
    let headroom = (execution_gas * CALL_GAS_HEADROOM_PERCENT / 100).max(NEW_SLOT_STATE_GAS);
    (execution_gas * 64 / 63 + CALL_GAS_BUFFER_VALUE + headroom).max(MIN_CALL_GAS_LIMIT)
}

/// Whether the node gave the traced `simulateHandleOp` call a state-gas reservoir, read from the
/// result of its target, a `ReservoirProbe`. `None` if the call has no such result.
pub(crate) fn probe_found_reservoir(frame: &CallFrame) -> Option<bool> {
    let output = frame.output.as_ref()?;
    let result = simulateHandleOpCall::abi_decode_returns(output).ok()?;
    if !result.targetSuccess {
        return None;
    }
    probeCall::abi_decode_returns(&result.targetResult).ok()
}

/// The least gas `frame` needs to run as traced, from the gas used by it and its calls: a call
/// made with all but 1/64 of the caller's gas (EIP-150) needs 64/63 of the callee's own need at
/// the time of the call. Such a call also shows how much gas the caller had left then (64/63 of
/// the gas it gave), and so how much it had used before it.
///
/// Only meaningful where calls get no reservoir, so a frame's gas used includes its net state.
/// Before a call given less gas, the frame's own gas used is not known and is left out, so this
/// errs low.
pub(crate) fn frame_gas_need(frame: &CallFrame) -> u128 {
    let gas: u128 = frame.gas.saturating_to();
    let gas_used: u128 = frame.gas_used.saturating_to();
    // At a call, the frame had at least the gas it had left at its end.
    let gas_left = gas.saturating_sub(gas_used);
    let mut need = gas_used;
    let mut used_in_calls = 0u128;
    for call in &frame.calls {
        let call_need = frame_gas_need(call);
        let call_gas: u128 = call.gas.saturating_to();
        let gas_at_call = call_gas * 64 / 63;
        let need_at_call = if gas_at_call >= gas_left {
            // All but 1/64 forwarded: the frame had `gas_at_call` left.
            let used_before = gas.saturating_sub(gas_at_call).max(used_in_calls);
            used_before + (call_need * 64).div_ceil(63)
        } else {
            used_in_calls + call_need
        };
        need = need.max(need_at_call);
        used_in_calls += call.gas_used.saturating_to::<u128>();
    }
    need
}

/// Guesses tried in parallel per round of a [`least_passing`] search
const SEARCH_GUESSES: u128 = 3;

/// Rounds a [`least_passing`] search runs at most: each one narrows the range to a quarter.
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

    fn frame_with_gas(gas: u64, gas_used: u64, calls: Vec<CallFrame>) -> CallFrame {
        GethDebugTracerCallFrame {
            gas: U256::from(gas),
            ..frame(EP, SENDER, gas_used, calls)
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

    /// simulateHandleOp: validation calls the sender from the entry point directly; execution
    /// calls it from innerHandleOp.
    #[test]
    fn finds_execution_not_validation_call() {
        let validation = frame(EP, SENDER, 1_000, vec![]);
        let execution = frame(EP, SENDER, 6_469_508, vec![]);
        let inner = frame(EP, EP, 6_500_000, vec![execution]);
        let root = frame(CALLER, EP, 7_000_000, vec![validation, inner]);

        let found = find_execution_frame(&root, EP, SENDER).unwrap();
        assert_eq!(found.gas_used, U256::from(6_469_508));
    }

    #[test]
    fn no_execution_frame_without_inner_handle_op() {
        let root = frame(CALLER, EP, 1_000, vec![frame(EP, SENDER, 500, vec![])]);
        assert!(find_execution_frame(&root, EP, SENDER).is_none());
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

    /// Phase 0, 4 kB deploy: the execute frame used 6,469,508 with 6,450,480 of it state.
    #[test]
    fn call_gas_limit_covers_execution_only() {
        let cgl = reservoir_call_gas_limit(6_469_508, 6_450_480);
        // 19,028 of execution: ×64/63, the 3,000 buffer and one slot of headroom
        assert_eq!(cgl, 19_028 * 64 / 63 + 3_000 + 97_920);

        // above ~980k of execution, 10% headroom is larger than one slot
        let cgl = reservoir_call_gas_limit(3_000_000, 1_000_000);
        assert_eq!(cgl, 2_000_000 * 64 / 63 + 3_000 + 200_000);
    }

    /// Sepolia's 24 kB deploy from the sender: `execute` calls BlobDeployer, which builds the
    /// init code in memory (about 0.19M) before its CREATE2. Each call gets all but 1/64 of the
    /// caller's gas.
    #[test]
    fn frame_need_keeps_a_64th_per_call_and_the_gas_used_before() {
        let create = frame_with_gas(57_926_880, 37_609_349, vec![]);
        let deployer = frame_with_gas(59_042_482, 37_806_956, vec![create]);
        let execution = frame_with_gas(60_000_000, 37_827_456, vec![deployer]);

        let create_need = 37_609_349u128;
        let deployer_used_before = 59_042_482 - 57_926_880u128 * 64 / 63;
        assert!((180_000..200_000).contains(&deployer_used_before));
        let deployer_need = deployer_used_before + (create_need * 64).div_ceil(63);
        let execution_used_before = 60_000_000 - 59_042_482u128 * 64 / 63;
        assert_eq!(
            frame_gas_need(&execution),
            execution_used_before + (deployer_need * 64).div_ceil(63)
        );
        // more than the CREATE2's gas used, by the 1/64 kept at each call and the gas used
        // before them
        assert!(frame_gas_need(&execution) > 37_609_349 + 2 * 37_609_349 / 63 + 180_000);
    }

    /// A call given an explicit gas below all but 1/64 of the caller's gas needs no more than
    /// its own need; earlier calls' gas used counts before it.
    #[test]
    fn frame_need_of_explicit_gas_calls() {
        let first = frame_with_gas(73_000_000, 1_000_000, vec![]);
        let explicit = frame_with_gas(500_000, 400_000, vec![]);
        let execution = frame_with_gas(75_000_000, 1_500_000, vec![first, explicit]);
        let first_need =
            (75_000_000 - 73_000_000u128 * 64 / 63) + (1_000_000u128 * 64).div_ceil(63);
        assert_eq!(
            frame_gas_need(&execution),
            first_need.max(1_000_000 + 400_000).max(1_500_000)
        );
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

    #[test]
    fn reads_probe_result() {
        let mut root = frame(CALLER, EP, 0, vec![]);
        assert_eq!(probe_found_reservoir(&root), None);
        for reservoir in [false, true] {
            root.output = Some(Bytes::from(simulateHandleOpCall::abi_encode_returns(
                &rundler_contracts::v0_7::IEntryPointSimulations::ExecutionResult {
                    targetSuccess: true,
                    targetResult: reservoir.abi_encode().into(),
                    ..Default::default()
                },
            )));
            assert_eq!(probe_found_reservoir(&root), Some(reservoir));
        }
        // the target call failed
        root.output = Some(Bytes::from(simulateHandleOpCall::abi_encode_returns(
            &rundler_contracts::v0_7::IEntryPointSimulations::ExecutionResult::default(),
        )));
        assert_eq!(probe_found_reservoir(&root), None);
    }
}
