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

use ethers::{
    abi::{AbiDecode, RawLog},
    prelude::EthEvent,
    types::{Address, Bytes, Log, TransactionReceipt, H256},
};
use rundler_types::{
    chain::ChainSpec,
    contracts::v0_6::i_entry_point::{
        IEntryPointCalls, UserOperationEventFilter, UserOperationRevertReasonFilter,
    },
    v0_6::UserOperation,
};

use super::common::{EntryPointFilters, UserOperationEventProviderImpl};
use crate::types::RpcUserOperationReceipt;

pub(crate) type UserOperationEventProviderV0_6<P> =
    UserOperationEventProviderImpl<P, EntryPointFiltersV0_6>;

pub(crate) struct EntryPointFiltersV0_6;

impl EntryPointFilters for EntryPointFiltersV0_6 {
    type UO = UserOperation;
    type UserOperationEventFilter = UserOperationEventFilter;
    type UserOperationRevertReasonFilter = UserOperationRevertReasonFilter;

    fn construct_receipt(
        event: Self::UserOperationEventFilter,
        hash: H256,
        entry_point: Address,
        logs: Vec<Log>,
        tx_receipt: TransactionReceipt,
    ) -> RpcUserOperationReceipt {
        // get failure reason
        let reason: String = if event.success {
            "".to_owned()
        } else {
            let revert_reason_evt: Option<Self::UserOperationRevertReasonFilter> = logs
                .iter()
                .filter(|l| l.topics.len() > 1 && l.topics[1] == hash)
                .map_while(|l| {
                    Self::UserOperationRevertReasonFilter::decode_log(&RawLog {
                        topics: l.topics.clone(),
                        data: l.data.to_vec(),
                    })
                    .ok()
                })
                .next();

            revert_reason_evt
                .map(|r| r.revert_reason.to_string())
                .unwrap_or_default()
        };

        RpcUserOperationReceipt {
            user_op_hash: hash,
            entry_point: entry_point.into(),
            sender: event.sender.into(),
            nonce: event.nonce,
            paymaster: event.paymaster.into(),
            actual_gas_cost: event.actual_gas_cost,
            actual_gas_used: event.actual_gas_used,
            success: event.success,
            logs,
            receipt: tx_receipt,
            reason,
        }
    }

    fn get_user_operations_from_tx_data(tx_data: Bytes, _chain_spec: &ChainSpec) -> Vec<Self::UO> {
        let entry_point_calls = match IEntryPointCalls::decode(tx_data) {
            Ok(entry_point_calls) => entry_point_calls,
            Err(_) => return vec![],
        };

        match entry_point_calls {
            IEntryPointCalls::HandleOps(handle_ops_call) => handle_ops_call.ops,
            IEntryPointCalls::HandleAggregatedOps(handle_aggregated_ops_call) => {
                handle_aggregated_ops_call
                    .ops_per_aggregator
                    .into_iter()
                    .flat_map(|ops| ops.user_ops)
                    .collect()
            }
            _ => vec![],
        }
    }

    fn address(chain_spec: &ChainSpec) -> Address {
        chain_spec.entry_point_address_v0_6
    }
}
