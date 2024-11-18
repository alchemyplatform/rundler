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
use alloy_sol_types::SolInterface;
use rundler_contracts::v0_6::IEntryPoint::{
    IEntryPointCalls, UserOperationEvent, UserOperationRevertReason,
};
use rundler_provider::{Log, TransactionReceipt};
use rundler_types::{
    chain::ChainSpec,
    v0_6::{ExtendedUserOperation, UserOperation, UserOperationBuilder},
};

use super::common::{EntryPointEvents, UserOperationEventProviderImpl};
use crate::types::RpcUserOperationReceipt;

pub(crate) type UserOperationEventProviderV0_6<P> =
    UserOperationEventProviderImpl<P, EntryPointFiltersV0_6>;

pub(crate) struct EntryPointFiltersV0_6;

impl EntryPointEvents for EntryPointFiltersV0_6 {
    type UO = UserOperation;
    type UserOperationEvent = UserOperationEvent;
    type UserOperationRevertReason = UserOperationRevertReason;

    fn construct_receipt(
        event: Self::UserOperationEvent,
        hash: B256,
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
                .filter(|l| l.topics().len() > 1 && l.topics()[1] == hash)
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
            user_op_hash: hash,
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
        }
    }

    fn get_user_operations_from_tx_data(tx_data: Bytes, chain_spec: &ChainSpec) -> Vec<Self::UO> {
        let entry_point_calls = match IEntryPointCalls::abi_decode(&tx_data, false) {
            Ok(entry_point_calls) => entry_point_calls,
            Err(_) => return vec![],
        };

        match entry_point_calls {
            IEntryPointCalls::handleOps(handle_ops_call) => handle_ops_call
                .ops
                .into_iter()
                .filter_map(|op| {
                    UserOperationBuilder::from_contract(
                        chain_spec,
                        op,
                        ExtendedUserOperation {
                            authorization_tuple: None,
                        },
                    )
                    .ok()
                    .map(|b| b.build())
                })
                .collect(),
            IEntryPointCalls::handleAggregatedOps(handle_aggregated_ops_call) => {
                handle_aggregated_ops_call
                    .opsPerAggregator
                    .into_iter()
                    .flat_map(|ops| {
                        ops.userOps.into_iter().filter_map(|op| {
                            UserOperationBuilder::from_contract(
                                chain_spec,
                                op,
                                ExtendedUserOperation {
                                    authorization_tuple: None,
                                },
                            )
                            .ok()
                            .map(|b| b.build())
                        })
                    })
                    .collect()
            }
            _ => vec![],
        }
    }

    fn address(chain_spec: &ChainSpec) -> Address {
        chain_spec.entry_point_address_v0_6
    }
}
