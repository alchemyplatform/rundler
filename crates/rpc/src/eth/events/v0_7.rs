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

use alloy_primitives::{ruint::UintTryFrom, Address, Bytes, B256, U128};
use alloy_sol_types::SolEvent;
use rundler_contracts::v0_7::IEntryPoint::{
    BeforeExecution, UserOperationEvent, UserOperationRevertReason,
};
use rundler_provider::{Log, TransactionReceipt};
use rundler_types::{authorization::Eip7702Auth, chain::ChainSpec, v0_7::UserOperation};

use super::common::{EntryPointEvents, UserOperationEventProviderImpl};
use crate::types::{RpcUserOperationReceipt, UOStatusEnum};

pub(crate) type UserOperationEventProviderV0_7<P> =
    UserOperationEventProviderImpl<P, EntryPointFiltersV0_7>;

pub(crate) struct EntryPointFiltersV0_7;

impl EntryPointEvents for EntryPointFiltersV0_7 {
    type UO = UserOperation;
    type UserOperationEvent = UserOperationEvent;
    type UserOperationRevertReason = UserOperationRevertReason;

    fn construct_receipt(
        event: Self::UserOperationEvent,
        entry_point: Address,
        logs: Vec<Log>,
        tx_receipt: TransactionReceipt,
    ) -> RpcUserOperationReceipt {
        // get failure reason
        let reason: String = if event.success {
            "".to_owned()
        } else {
            let revert_reason_evt: Option<Self::UserOperationRevertReason> = logs
                .iter()
                .filter(|l| l.topics().len() > 1 && l.topics()[1] == event.userOpHash)
                .map_while(|l| {
                    l.log_decode::<Self::UserOperationRevertReason>()
                        .map(|l| l.inner.data)
                        .ok()
                })
                .next();

            revert_reason_evt
                .map(|r| r.revertReason.to_string())
                .unwrap_or_default()
        };

        RpcUserOperationReceipt {
            user_op_hash: event.userOpHash,
            entry_point: entry_point.into(),
            sender: event.sender.into(),
            nonce: event.nonce,
            paymaster: event.paymaster.into(),
            actual_gas_cost: event.actualGasCost,
            actual_gas_used: U128::uint_try_from(event.actualGasUsed).unwrap_or(U128::MAX),
            success: event.success,
            logs,
            receipt: tx_receipt,
            reason,
            status: UOStatusEnum::Mined,
        }
    }

    fn get_user_operations_from_tx_data(
        to_address: Address,
        tx_data: Bytes,
        tx_auth_list: &[Eip7702Auth],
        chain_spec: &ChainSpec,
    ) -> Vec<Self::UO> {
        let uos_per_agg = rundler_provider::decode_v0_7_ops_from_calldata(
            chain_spec,
            to_address,
            &tx_data,
            tx_auth_list,
        );

        uos_per_agg
            .into_iter()
            .flat_map(|uos_per_agg| uos_per_agg.user_ops)
            .collect()
    }

    fn before_execution_selector() -> B256 {
        BeforeExecution::SIGNATURE_HASH
    }
}
