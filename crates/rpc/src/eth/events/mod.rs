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

use alloy_primitives::B256;
use anyhow::bail;
use rundler_provider::{Log, TransactionReceipt};

use crate::types::{RpcUserOperationByHash, RpcUserOperationReceipt};

mod common;

mod v0_6;
pub(crate) use v0_6::UserOperationEventProviderV0_6;
mod v0_7;
pub(crate) use v0_7::UserOperationEventProviderV0_7;

#[async_trait::async_trait]
pub(crate) trait UserOperationEventProvider: Send + Sync {
    async fn get_mined_by_hash(&self, hash: B256)
        -> anyhow::Result<Option<RpcUserOperationByHash>>;

    async fn get_receipt(&self, hash: B256) -> anyhow::Result<Option<RpcUserOperationReceipt>>;
}

// This method takes a user operation event and a transaction receipt and filters out all the logs
// relevant to the user operation. Since there are potentially many user operations in a transaction,
// we want to find all the logs (including the user operation event itself) that are sandwiched between
// ours and the one before it that wasn't ours.
// eg. reference_log: UserOp(hash_moldy) logs: \[...OtherLogs, UserOp(hash1), ...OtherLogs, UserOp(hash_moldy), ...OtherLogs\]
// -> logs: logs\[(idx_of_UserOp(hash1) + 1)..=idx_of_UserOp(hash_moldy)\]
//
// topic\[0\] == event name
// topic\[1\] == user operation hash
//
// NOTE: we can't convert just decode all the logs as user operations and filter because we still want all the other log types
//
fn filter_receipt_logs_matching_user_op(
    reference_log: &Log,
    tx_receipt: &TransactionReceipt,
) -> anyhow::Result<Vec<Log>> {
    let logs = tx_receipt.inner.logs();

    let mut start_idx = 0;
    let mut end_idx = logs.len() - 1;

    // TODO protect against topic of zero size

    let is_ref_user_op = |log: &Log| {
        log.topics()[0] == reference_log.topics()[0]
            && log.topics()[1] == reference_log.topics()[1]
            && log.address() == reference_log.address()
    };

    let is_user_op_event = |log: &Log| log.topics()[0] == reference_log.topics()[0];

    let mut i = 0;
    while i < logs.len() {
        if i < end_idx && is_user_op_event(&logs[i]) && !is_ref_user_op(&logs[i]) {
            start_idx = i;
        } else if is_ref_user_op(&logs[i]) {
            end_idx = i;
        }

        i += 1;
    }

    if !is_ref_user_op(&logs[end_idx]) {
        bail!("fatal: no user ops found in tx receipt ({start_idx},{end_idx})");
    }

    let start_idx = if start_idx == 0 { 0 } else { start_idx + 1 };
    Ok(logs[start_idx..=end_idx].to_vec())
}

#[cfg(test)]
mod tests {

    use alloy_primitives::{address, utils::keccak256, Address, Log as PrimitiveLog, LogData};
    use rundler_provider::{TransactionReceiptEnvelope, TransactionReceiptWithBloom};

    use super::*;

    const UO_OP_TOPIC: &str = "user-op-event-topic";

    #[test]
    fn test_filter_receipt_logs_when_at_beginning_of_list() {
        let reference_log = given_log(UO_OP_TOPIC, "moldy-hash");
        let receipt = given_receipt(vec![
            given_log("other-topic", "some-hash"),
            reference_log.clone(),
            given_log(UO_OP_TOPIC, "other-hash"),
            given_log(UO_OP_TOPIC, "another-hash"),
        ]);

        let result = filter_receipt_logs_matching_user_op(&reference_log, &receipt);

        assert!(result.is_ok(), "{}", result.unwrap_err());
        let result = result.unwrap();
        assert_eq!(result, receipt.inner.logs()[0..=1]);
    }

    #[test]
    fn test_filter_receipt_logs_when_in_middle_of_list() {
        let reference_log = given_log(UO_OP_TOPIC, "moldy-hash");
        let receipt = given_receipt(vec![
            given_log("other-topic", "some-hash"),
            given_log(UO_OP_TOPIC, "other-hash"),
            given_log("another-topic", "some-hash"),
            given_log("another-topic-2", "some-hash"),
            reference_log.clone(),
            given_log(UO_OP_TOPIC, "another-hash"),
        ]);

        let result = filter_receipt_logs_matching_user_op(&reference_log, &receipt);

        assert!(result.is_ok(), "{}", result.unwrap_err());
        let result = result.unwrap();
        assert_eq!(result, receipt.inner.logs()[2..=4]);
    }

    #[test]
    fn test_filter_receipt_logs_when_at_end_of_list() {
        let reference_log = given_log(UO_OP_TOPIC, "moldy-hash");
        let receipt = given_receipt(vec![
            given_log("other-topic", "some-hash"),
            given_log(UO_OP_TOPIC, "other-hash"),
            given_log(UO_OP_TOPIC, "another-hash"),
            given_log("another-topic", "some-hash"),
            given_log("another-topic-2", "some-hash"),
            reference_log.clone(),
        ]);

        let result = filter_receipt_logs_matching_user_op(&reference_log, &receipt);

        assert!(result.is_ok(), "{}", result.unwrap_err());
        let result = result.unwrap();
        assert_eq!(result, receipt.inner.logs()[3..=5]);
    }

    #[test]
    fn test_filter_receipt_logs_skips_event_from_different_address() {
        let reference_log = given_log(UO_OP_TOPIC, "moldy-hash");
        let mut reference_log_w_different_address = reference_log.clone();
        reference_log_w_different_address.inner.address =
            address!("0000000000000000000000000000000000001234");

        let receipt = given_receipt(vec![
            given_log("other-topic", "some-hash"),
            given_log(UO_OP_TOPIC, "other-hash"),
            given_log(UO_OP_TOPIC, "another-hash"),
            reference_log_w_different_address,
            given_log("another-topic", "some-hash"),
            given_log("another-topic-2", "some-hash"),
            reference_log.clone(),
        ]);

        let result = filter_receipt_logs_matching_user_op(&reference_log, &receipt);

        assert!(result.is_ok(), "{}", result.unwrap_err());
        let result = result.unwrap();
        assert_eq!(result, receipt.inner.logs()[4..=6]);
    }

    #[test]
    fn test_filter_receipt_logs_includes_multiple_sets_of_ref_uo() {
        let reference_log = given_log(UO_OP_TOPIC, "moldy-hash");

        let receipt = given_receipt(vec![
            given_log("other-topic", "some-hash"),
            given_log(UO_OP_TOPIC, "other-hash"),
            given_log("other-topic-2", "another-hash"),
            reference_log.clone(),
            given_log("another-topic", "some-hash"),
            given_log("another-topic-2", "some-hash"),
            reference_log.clone(),
            given_log(UO_OP_TOPIC, "other-hash"),
        ]);

        let result = filter_receipt_logs_matching_user_op(&reference_log, &receipt);

        assert!(result.is_ok(), "{}", result.unwrap_err());
        let result = result.unwrap();
        assert_eq!(result, receipt.inner.logs()[2..=6]);
    }

    #[test]
    fn test_filter_receipt_logs_when_not_found() {
        let reference_log = given_log(UO_OP_TOPIC, "moldy-hash");
        let receipt = given_receipt(vec![
            given_log("other-topic", "some-hash"),
            given_log(UO_OP_TOPIC, "other-hash"),
            given_log(UO_OP_TOPIC, "another-hash"),
            given_log("another-topic", "some-hash"),
            given_log("another-topic-2", "some-hash"),
        ]);

        let result = filter_receipt_logs_matching_user_op(&reference_log, &receipt);

        assert!(result.is_err(), "{:?}", result.unwrap());
    }

    fn given_log(topic_0: &str, topic_1: &str) -> Log {
        let mut log_data = LogData::default();
        log_data.set_topics_unchecked(vec![
            keccak256(topic_0.as_bytes()),
            keccak256(topic_1.as_bytes()),
        ]);

        Log {
            inner: PrimitiveLog {
                address: Address::ZERO,
                data: log_data,
            },
            ..Default::default()
        }
    }

    fn given_receipt(logs: Vec<Log>) -> TransactionReceipt {
        let receipt = alloy_consensus::Receipt {
            logs,
            ..Default::default()
        };
        TransactionReceipt {
            inner: TransactionReceiptEnvelope::Legacy(TransactionReceiptWithBloom {
                receipt,
                ..Default::default()
            }),
            transaction_hash: B256::ZERO,
            transaction_index: None,
            block_hash: None,
            block_number: None,
            gas_used: 0,
            effective_gas_price: 0,
            blob_gas_used: None,
            blob_gas_price: None,
            from: Address::ZERO,
            to: None,
            contract_address: None,
            authorization_list: None,
        }
    }
}
