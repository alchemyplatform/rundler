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

use alloy_primitives::Address;
use alloy_sol_types::SolEvent;
use rundler_contracts::v0_7::IEntryPoint::UserOperationEvent;
use rundler_provider::GethDebugTracerCallFrame as CallFrame;

use super::CALL_GAS_BUFFER_VALUE;
use crate::MIN_CALL_GAS_LIMIT;

/// EIP-8037 state gas of one new storage slot. The least call gas headroom a reservoir-mode
/// estimate keeps, so one slot of state drift between estimation and inclusion does not run the
/// op out of gas.
const NEW_SLOT_STATE_GAS: u128 = 97_920;

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
/// `execution_frame_gas` is the gas the sender's execution call used in a simulation, where calls
/// have no reservoir, so it includes the state that execution created (`execution_state_gas`).
/// The frame's gas used, rather than a binary search, keeps the limit tight: a search would also
/// keep the 1/64 of the state gas withheld at each nested call.
pub(crate) fn reservoir_call_gas_limit(
    execution_frame_gas: u128,
    execution_state_gas: u128,
) -> u128 {
    let execution_gas = execution_frame_gas.saturating_sub(execution_state_gas);
    let headroom = (execution_gas * CALL_GAS_HEADROOM_PERCENT / 100).max(NEW_SLOT_STATE_GAS);
    (execution_gas * 64 / 63 + CALL_GAS_BUFFER_VALUE + headroom).max(MIN_CALL_GAS_LIMIT)
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
}
