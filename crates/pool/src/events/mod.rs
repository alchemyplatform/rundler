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

//! Event provider for looking up mined user operations and receipts.
//!
//! Returns domain types (`MinedUserOperation`, `UserOperationReceiptData`)
//! instead of RPC types, so results can be used by both the pool gRPC server
//! and the RPC layer.

use alloy_primitives::{Address, B256};
use anyhow::bail;
use rundler_provider::{Log, TransactionReceipt};
use rundler_types::pool::{MinedUserOperation, UserOperationReceiptData};
use tracing::instrument;

mod common;

mod v0_6;
pub(crate) use v0_6::UserOperationEventProviderV0_6;
mod v0_7;
pub(crate) use v0_7::UserOperationEventProviderV0_7;

/// Trait for looking up mined user operations and receipts from on-chain events.
#[async_trait::async_trait]
pub(crate) trait UserOperationEventProvider: Send + Sync {
    /// Get a mined user operation by its hash, searching on-chain event logs.
    async fn get_mined_by_hash(&self, hash: B256) -> anyhow::Result<Option<MinedUserOperation>>;

    /// Get the receipt for a mined user operation by its hash.
    async fn get_receipt(&self, hash: B256) -> anyhow::Result<Option<UserOperationReceiptData>>;

    /// Get the receipt for a mined user operation from a specific bundle transaction hash.
    async fn get_receipt_from_tx_hash(
        &self,
        hash: B256,
        bundle_transaction: B256,
    ) -> anyhow::Result<Option<UserOperationReceiptData>>;

    /// Get a receipt from a transaction receipt.
    async fn get_receipt_from_tx_receipt(
        &self,
        uo_hash: B256,
        tx_receipt: TransactionReceipt,
    ) -> anyhow::Result<Option<UserOperationReceiptData>>;
}

// This method takes a user operation event and a transaction receipt and filters out all the logs
// relevant to the user operation. Since there are potentially many user operations in a transaction,
// we want to find all the logs (including the user operation event itself) that are sandwiched between
// ours and the one before it that wasn't ours.
#[instrument(skip_all)]
fn filter_receipt_logs_matching_user_op(
    entry_point: Address,
    before_execution_topic: B256,
    reference_log: &Log,
    tx_receipt: &TransactionReceipt,
) -> anyhow::Result<Vec<Log>> {
    let logs = tx_receipt.inner.inner.logs();

    let is_ref_user_op = |log: &Log| {
        log.topics().len() >= 2
            && log.topics()[0] == reference_log.topics()[0]
            && log.topics()[1] == reference_log.topics()[1]
            && log.address() == reference_log.address()
    };

    let is_user_op_event =
        |log: &Log| !log.topics().is_empty() && log.topics()[0] == reference_log.topics()[0];

    let is_before_execution_log = |log: &Log| {
        !log.topics().is_empty()
            && log.topics()[0] == before_execution_topic
            && log.address() == entry_point
    };

    let mut i = 0;
    let mut start_idx = None;
    while i < logs.len() {
        if is_before_execution_log(&logs[i])
            || (is_user_op_event(&logs[i]) && !is_ref_user_op(&logs[i]))
        {
            start_idx = Some(i + 1);
        } else if is_ref_user_op(&logs[i]) {
            let Some(start_idx) = start_idx else {
                bail!("invalid sequence of logs. found ref user op before BeforeExecution event");
            };
            return Ok(logs[start_idx..=i].to_vec());
        }

        i += 1;
    }

    bail!("no matching user op found in tx receipt");
}
