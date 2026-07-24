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

use alloy_eips::{BlockId, BlockNumberOrTag};
use alloy_primitives::{Address, B256};
use rundler_provider::{EvmProvider, FilterBlockOption, Log, ProviderError, TransactionReceipt};
use thiserror::Error;
use tracing::instrument;

use crate::types::{RpcUserOperationByHash, RpcUserOperationReceipt};

mod common;

mod v0_6;
pub(crate) use v0_6::UserOperationEventProviderV0_6;
mod v0_7;
pub(crate) use v0_7::UserOperationEventProviderV0_7;

/// Unresolved block scoping options as received from the JSON-RPC API. The block option
/// may contain tags; `max_block_range` is a per-request override of the configured maximum
/// event block distance.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct EventBlockOptions {
    /// Caller-supplied block range or hash to search. When set, the fallback retry is
    /// disabled and the option is used as-is (after tag resolution and validation).
    pub(crate) block_option: Option<FilterBlockOption>,
    /// Per-request override of the maximum event block distance.
    pub(crate) max_block_range: Option<u64>,
}

/// Block scoping options after resolution: the search window is a concrete block-number
/// range (tags resolved, one-sided ranges expanded, width validated), ready to hand to the
/// event query layer as-is.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ResolvedEventBlockOptions {
    /// Concrete range (or block hash) to search.
    pub(crate) block_option: FilterBlockOption,
    /// Whether the caller supplied an explicit block option. When false, the fallback
    /// retry is enabled.
    pub(crate) caller_supplied: bool,
    /// Per-request max override, retained so the fallback retry can be capped by it.
    pub(crate) max_block_range: Option<u64>,
}

impl EventBlockOptions {
    /// Resolve into a concrete search window ready for the event query layer.
    ///
    /// The per-request `max_block_range` override takes precedence over the statically
    /// configured `event_block_distance`; the resulting effective max bounds the window,
    /// expands a one-sided range, and defines the default window when no option is supplied.
    ///
    /// RPC handlers call this once per request, before fanning out to entry point routes,
    /// so tags are resolved a single time and every route receives concrete block numbers.
    pub(crate) async fn resolve<P: EvmProvider>(
        self,
        provider: &P,
        event_block_distance: Option<u64>,
    ) -> EventProviderResult<ResolvedEventBlockOptions> {
        let max_distance = self.max_block_range.or(event_block_distance);

        // An empty range `{}` carries no information: treat it exactly like an omitted
        // parameter (default window + fallback retry) instead of delegating both bounds to
        // the node's getLogs defaults (typically latest..latest).
        let supplied = self.block_option.filter(|bo| {
            !matches!(
                bo,
                FilterBlockOption::Range {
                    from_block: None,
                    to_block: None,
                }
            )
        });

        let block_option = match supplied {
            // Resolve tags, validate the window against the effective max, and expand a
            // one-sided range to a bounded window.
            Some(bo) => resolve_block_option(provider, bo, max_distance).await?,
            // No option supplied: search the default trailing window ending at the head.
            None => {
                let to_block = provider.get_block_number().await?;
                let from_block = match max_distance {
                    Some(distance) => to_block.saturating_sub(distance),
                    None => 0,
                };
                FilterBlockOption::Range {
                    from_block: Some(from_block.into()),
                    to_block: Some(to_block.into()),
                }
            }
        };

        Ok(ResolvedEventBlockOptions {
            block_option,
            caller_supplied: supplied.is_some(),
            max_block_range: self.max_block_range,
        })
    }
}

#[async_trait::async_trait]
pub(crate) trait UserOperationEventProvider: Send + Sync {
    async fn get_mined_by_hash(
        &self,
        hash: B256,
        block_options: ResolvedEventBlockOptions,
    ) -> EventProviderResult<Option<RpcUserOperationByHash>>;

    async fn get_mined_from_tx_receipt(
        &self,
        uo_hash: B256,
        tx_receipt: TransactionReceipt,
    ) -> EventProviderResult<Option<RpcUserOperationByHash>>;

    async fn get_receipt(
        &self,
        hash: B256,
        block_options: ResolvedEventBlockOptions,
    ) -> EventProviderResult<Option<RpcUserOperationReceipt>>;

    async fn get_receipt_from_tx_hash(
        &self,
        hash: B256,
        bundle_transaction: B256,
    ) -> EventProviderResult<Option<RpcUserOperationReceipt>>;

    async fn get_receipt_from_tx_receipt(
        &self,
        uo_hash: B256,
        tx_receipt: TransactionReceipt,
    ) -> EventProviderResult<Option<RpcUserOperationReceipt>>;

    /// Get both the mined user operation and receipt in a single call,
    /// sharing the logs RPC call between both operations.
    async fn get_mined_and_receipt(
        &self,
        hash: B256,
        bundle_transaction: Option<B256>,
        block_options: ResolvedEventBlockOptions,
    ) -> EventProviderResult<Option<(RpcUserOperationByHash, RpcUserOperationReceipt)>>;
}

/// Errors that can occur while querying user operation events from the blockchain
#[derive(Debug, Error)]
pub enum EventProviderError {
    /// Provider RPC call failed (includes event queries, traces, missing 'to' field, etc.)
    #[error("provider error: {0}")]
    Provider(#[from] ProviderError),

    /// Transaction not found (includes missing tx hash, tx not found)
    #[error("transaction {0} not found")]
    TransactionNotFound(B256),

    /// Transaction receipt not found
    #[error("transaction receipt for {0} not found")]
    ReceiptNotFound(B256),

    /// User operation not found in receipt logs
    #[error("user operation {uo_hash} not found in transaction {tx_hash}")]
    UserOpNotInReceipt { uo_hash: B256, tx_hash: B256 },

    /// User operation not found in transaction data
    #[error("user operation {uo_hash} not found in transaction data for {tx_hash}")]
    UserOpNotInTransaction { uo_hash: B256, tx_hash: B256 },

    /// User operation not found in transaction trace
    #[error("user operation {uo_hash} not found in trace for transaction {tx_hash}")]
    UserOpNotInTrace { uo_hash: B256, tx_hash: B256 },

    /// Error processing logs (includes invalid sequence, no matching logs, decode failures)
    #[error("log processing error: {0}")]
    LogProcessingError(String),

    /// Invalid request
    #[error("invalid event request: {0}")]
    InvalidRequest(String),
}

/// Type alias for results from event provider operations
pub(crate) type EventProviderResult<T> = Result<T, EventProviderError>;

/// Resolve a filter block option into a concrete range: resolve any block tags to block
/// numbers and, when a maximum block distance is enforced, validate and bound the window.
///
/// RPC handlers call this once with `max_distance = None` so tags are resolved a single
/// time before fanning out; each entry point route then re-invokes it with its effective
/// max to validate the window and expand a one-sided range.
///
/// A one-sided range is expanded to a `max_distance`-wide window anchored at the supplied
/// bound. For `{ fromBlock }` the synthesized `toBlock` is capped at the chain head so we
/// never emit a `toBlock` past the tip (`eth_getLogs` clamping of an out-of-range
/// `toBlock` is not guaranteed by the JSON-RPC spec).
pub(crate) async fn resolve_block_option<P: EvmProvider>(
    provider: &P,
    block_option: FilterBlockOption,
    max_distance: Option<u64>,
) -> EventProviderResult<FilterBlockOption> {
    let FilterBlockOption::Range {
        from_block,
        to_block,
    } = block_option
    else {
        // AtBlockHash: nothing to resolve or bound.
        return Ok(block_option);
    };

    // Resolve any tags to concrete block numbers.
    let (from_block, to_block) = match (from_block, to_block) {
        // both bounds are the same tag: resolve once
        (Some(from), Some(to)) if from == to => {
            let number = resolve_block_number(provider, from).await?;
            (Some(number), Some(number))
        }
        (from, to) => {
            let from = match from {
                Some(block) => Some(resolve_block_number(provider, block).await?),
                None => None,
            };
            let to = match to {
                Some(block) => Some(resolve_block_number(provider, block).await?),
                None => None,
            };
            (from, to)
        }
    };

    if let (Some(from), Some(to)) = (from_block, to_block)
        && from > to
    {
        return Err(EventProviderError::InvalidRequest(format!(
            "fromBlock: {from} is greater than toBlock: {to}"
        )));
    }

    let (from_block, to_block) = match (max_distance, from_block, to_block) {
        // No max enforced: leave a missing bound to the node's getLogs default.
        (None, from, to) => (from, to),
        // Both bounds supplied: enforce the max width.
        (Some(max_distance), Some(from), Some(to)) => {
            if to - from > max_distance {
                return Err(EventProviderError::InvalidRequest(format!(
                    "fromBlock: {from}, toBlock: {to} larger than max block distance {max_distance}, reduce block range"
                )));
            }
            (Some(from), Some(to))
        }
        // One-sided fromBlock: expand toBlock to a max-wide window, capped at the head.
        (Some(max_distance), Some(from), None) => {
            let head = provider.get_block_number().await?;
            let to = from.saturating_add(max_distance).min(head);
            if from > to {
                return Err(EventProviderError::InvalidRequest(format!(
                    "fromBlock: {from} is greater than the current head block: {head}"
                )));
            }
            (Some(from), Some(to))
        }
        // One-sided toBlock: expand fromBlock to a max-wide window. toBlock is caller-
        // supplied, so it is left as-is.
        (Some(max_distance), None, Some(to)) => (Some(to.saturating_sub(max_distance)), Some(to)),
        // Both omitted: nothing to bound; leave to the node default.
        (Some(_), None, None) => (None, None),
    };

    Ok(FilterBlockOption::Range {
        from_block: from_block.map(Into::into),
        to_block: to_block.map(Into::into),
    })
}

/// Resolve a block number or tag to a concrete block number.
pub(crate) async fn resolve_block_number<P: EvmProvider>(
    provider: &P,
    block: BlockNumberOrTag,
) -> EventProviderResult<u64> {
    match block {
        BlockNumberOrTag::Number(block) => Ok(block),
        tag => {
            // The tag is caller-supplied, so an unresolvable tag (e.g. "pending" on a
            // chain whose node returns no pending block) is an invalid request, not an
            // internal error.
            let Some(block) = provider.get_block(BlockId::Number(tag)).await? else {
                return Err(EventProviderError::InvalidRequest(format!(
                    "block \"{tag}\" not found"
                )));
            };
            Ok(block.number())
        }
    }
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
#[instrument(skip_all)]
fn filter_receipt_logs_matching_user_op(
    entry_point: Address,
    before_execution_topic: B256,
    reference_log: &Log,
    tx_receipt: &TransactionReceipt,
) -> EventProviderResult<Vec<Log>> {
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
                return Err(EventProviderError::LogProcessingError(
                    "invalid log sequence: found user operation event before BeforeExecution event"
                        .into(),
                ));
            };
            return Ok(logs[start_idx..=i].to_vec());
        }

        i += 1;
    }

    let uo_hash = reference_log.topics().get(1).copied().unwrap_or_default();
    Err(EventProviderError::LogProcessingError(format!(
        "no matching user operation {uo_hash:?} found in transaction receipt"
    )))
}

#[cfg(test)]
mod tests {

    use alloy_primitives::{Address, Log as PrimitiveLog, LogData, address, utils::keccak256};
    use alloy_rpc_types_eth::TransactionReceipt as AlloyTransactionReceipt;
    use rundler_provider::{
        AnyReceiptEnvelope, ReceiptWithBloom, TransactionReceipt, WithOtherFields,
    };

    use super::*;

    const LOG_ADDRESS: Address = Address::ZERO;
    const UO_OP_TOPIC: &str = "user-op-event-topic";
    const BEFORE_EXECUTION_TOPIC: &str = "before-execution-topic";

    #[test]
    fn test_filter_receipt_logs_when_at_beginning_of_list() {
        let reference_log = given_log(UO_OP_TOPIC, "moldy-hash");
        let receipt = given_receipt(vec![
            given_log(BEFORE_EXECUTION_TOPIC, "some-hash"),
            given_log("other-topic", "some-hash"),
            reference_log.clone(),
            given_log(UO_OP_TOPIC, "other-hash"),
            given_log(UO_OP_TOPIC, "another-hash"),
        ]);

        let result = filter_receipt_logs_matching_user_op(
            LOG_ADDRESS,
            before_execution_selector(),
            &reference_log,
            &receipt,
        );

        assert!(result.is_ok(), "{}", result.unwrap_err());
        let result = result.unwrap();
        assert_eq!(result, receipt.inner.inner.logs()[1..=2]);
    }

    #[test]
    fn test_filter_receipt_logs_when_in_middle_of_list() {
        let reference_log = given_log(UO_OP_TOPIC, "moldy-hash");
        let receipt = given_receipt(vec![
            given_log(BEFORE_EXECUTION_TOPIC, "some-hash"),
            given_log("other-topic", "some-hash"),
            given_log(UO_OP_TOPIC, "other-hash"),
            given_log("another-topic", "some-hash"),
            given_log("another-topic-2", "some-hash"),
            reference_log.clone(),
            given_log(UO_OP_TOPIC, "another-hash"),
        ]);

        let result = filter_receipt_logs_matching_user_op(
            LOG_ADDRESS,
            before_execution_selector(),
            &reference_log,
            &receipt,
        );

        assert!(result.is_ok(), "{}", result.unwrap_err());
        let result = result.unwrap();
        assert_eq!(result, receipt.inner.inner.logs()[3..=5]);
    }

    #[test]
    fn test_filter_receipt_logs_when_at_end_of_list() {
        let reference_log = given_log(UO_OP_TOPIC, "moldy-hash");
        let receipt = given_receipt(vec![
            given_log(BEFORE_EXECUTION_TOPIC, "some-hash"),
            given_log("other-topic", "some-hash"),
            given_log(UO_OP_TOPIC, "other-hash"),
            given_log(UO_OP_TOPIC, "another-hash"),
            given_log("another-topic", "some-hash"),
            given_log("another-topic-2", "some-hash"),
            reference_log.clone(),
        ]);

        let result = filter_receipt_logs_matching_user_op(
            LOG_ADDRESS,
            before_execution_selector(),
            &reference_log,
            &receipt,
        );

        assert!(result.is_ok(), "{}", result.unwrap_err());
        let result = result.unwrap();
        assert_eq!(result, receipt.inner.inner.logs()[4..=6]);
    }

    #[test]
    fn test_filter_receipt_logs_skips_event_from_different_address() {
        let reference_log = given_log(UO_OP_TOPIC, "moldy-hash");
        let mut reference_log_w_different_address = reference_log.clone();
        reference_log_w_different_address.inner.address =
            address!("0000000000000000000000000000000000001234");

        let receipt = given_receipt(vec![
            given_log(BEFORE_EXECUTION_TOPIC, "some-hash"),
            given_log("other-topic", "some-hash"),
            given_log(UO_OP_TOPIC, "other-hash"),
            given_log(UO_OP_TOPIC, "another-hash"),
            reference_log_w_different_address,
            given_log("another-topic", "some-hash"),
            given_log("another-topic-2", "some-hash"),
            reference_log.clone(),
        ]);

        let result = filter_receipt_logs_matching_user_op(
            LOG_ADDRESS,
            before_execution_selector(),
            &reference_log,
            &receipt,
        );

        assert!(result.is_ok(), "{}", result.unwrap_err());
        let result = result.unwrap();
        assert_eq!(result, receipt.inner.inner.logs()[5..=7]);
    }

    #[test]
    fn test_filter_receipt_logs_includes_multiple_sets_of_ref_uo() {
        let reference_log = given_log(UO_OP_TOPIC, "moldy-hash");

        // This isn't possible as the same UO cannot be executed twice,
        // make sure it returns the first instance of the UO and doesn't crash
        let receipt = given_receipt(vec![
            given_log(BEFORE_EXECUTION_TOPIC, "some-hash"),
            given_log("other-topic", "some-hash"),
            given_log(UO_OP_TOPIC, "other-hash"),
            given_log("other-topic-2", "another-hash"),
            reference_log.clone(),
            given_log("another-topic", "some-hash"),
            given_log("another-topic-2", "some-hash"),
            reference_log.clone(),
            given_log(UO_OP_TOPIC, "other-hash"),
        ]);

        let result = filter_receipt_logs_matching_user_op(
            LOG_ADDRESS,
            before_execution_selector(),
            &reference_log,
            &receipt,
        );

        assert!(result.is_ok(), "{}", result.unwrap_err());
        let result = result.unwrap();
        assert_eq!(result, receipt.inner.inner.logs()[3..=4]);
    }

    #[test]
    fn test_filter_receipt_logs_when_not_found() {
        let reference_log = given_log(UO_OP_TOPIC, "moldy-hash");
        let receipt = given_receipt(vec![
            given_log(BEFORE_EXECUTION_TOPIC, "some-hash"),
            given_log("other-topic", "some-hash"),
            given_log(UO_OP_TOPIC, "other-hash"),
            given_log(UO_OP_TOPIC, "another-hash"),
            given_log("another-topic", "some-hash"),
            given_log("another-topic-2", "some-hash"),
        ]);

        let result = filter_receipt_logs_matching_user_op(
            LOG_ADDRESS,
            before_execution_selector(),
            &reference_log,
            &receipt,
        );

        assert!(result.is_err(), "{:?}", result.unwrap());
    }

    #[test]
    fn test_filter_anon_logs() {
        let reference_log = given_log(UO_OP_TOPIC, "moldy-hash");
        let receipt = given_receipt(vec![
            given_log(BEFORE_EXECUTION_TOPIC, "some-hash"),
            anon_log(),
            anon_log(),
            reference_log.clone(),
            anon_log(),
        ]);

        let result = filter_receipt_logs_matching_user_op(
            LOG_ADDRESS,
            before_execution_selector(),
            &reference_log,
            &receipt,
        );

        assert!(result.is_ok(), "{}", result.unwrap_err());
        let result = result.unwrap();
        assert_eq!(result, receipt.inner.inner.logs()[1..=3]);
    }

    fn given_log(topic_0: &str, topic_1: &str) -> Log {
        let mut log_data = LogData::default();
        log_data.set_topics_unchecked(vec![
            keccak256(topic_0.as_bytes()),
            keccak256(topic_1.as_bytes()),
        ]);

        Log {
            inner: PrimitiveLog {
                address: LOG_ADDRESS,
                data: log_data,
            },
            ..Default::default()
        }
    }

    #[test]
    fn test_start_after_before_execution_log_single() {
        let reference_log = given_log(UO_OP_TOPIC, "moldy-hash");
        let receipt = given_receipt(vec![
            given_log(BEFORE_EXECUTION_TOPIC, "some-hash"),
            reference_log.clone(),
        ]);

        let result = filter_receipt_logs_matching_user_op(
            LOG_ADDRESS,
            before_execution_selector(),
            &reference_log,
            &receipt,
        );

        assert!(result.is_ok(), "{}", result.unwrap_err());
        let result = result.unwrap();
        assert_eq!(result, receipt.inner.inner.logs()[1..=1]);
    }

    #[test]
    fn test_start_after_before_execution_log_multiple() {
        let reference_log = given_log(UO_OP_TOPIC, "moldy-hash");
        let receipt = given_receipt(vec![
            given_log(BEFORE_EXECUTION_TOPIC, "some-hash"),
            anon_log(),
            reference_log.clone(),
        ]);

        let result = filter_receipt_logs_matching_user_op(
            LOG_ADDRESS,
            before_execution_selector(),
            &reference_log,
            &receipt,
        );

        assert!(result.is_ok(), "{}", result.unwrap_err());
        let result = result.unwrap();
        assert_eq!(result, receipt.inner.inner.logs()[1..=2]);
    }

    #[test]
    fn test_multiple_entry_point_calls_single_txn() {
        let reference_log = given_log(UO_OP_TOPIC, "moldy-hash");
        let receipt = given_receipt(vec![
            given_log(BEFORE_EXECUTION_TOPIC, "some-hash"),
            anon_log(),
            given_log(UO_OP_TOPIC, "other-hash"),
            given_log(BEFORE_EXECUTION_TOPIC, "some-hash"),
            anon_log(),
            reference_log.clone(),
        ]);

        let result = filter_receipt_logs_matching_user_op(
            LOG_ADDRESS,
            before_execution_selector(),
            &reference_log,
            &receipt,
        );

        assert!(result.is_ok(), "{}", result.unwrap_err());
        let result = result.unwrap();
        assert_eq!(result, receipt.inner.inner.logs()[4..=5]);
    }

    #[test]
    fn test_invalid_sequence_of_logs() {
        let reference_log = given_log(UO_OP_TOPIC, "moldy-hash");
        let receipt = given_receipt(vec![
            reference_log.clone(),
            given_log(BEFORE_EXECUTION_TOPIC, "some-hash"),
        ]);

        let result = filter_receipt_logs_matching_user_op(
            LOG_ADDRESS,
            before_execution_selector(),
            &reference_log,
            &receipt,
        );

        assert!(result.is_err(), "{}", result.unwrap_err());
    }

    fn anon_log() -> Log {
        let mut log_data = LogData::default();
        log_data.set_topics_unchecked(vec![]);

        Log {
            inner: PrimitiveLog {
                address: LOG_ADDRESS,
                data: log_data,
            },
            ..Default::default()
        }
    }

    fn before_execution_selector() -> B256 {
        keccak256(BEFORE_EXECUTION_TOPIC.as_bytes())
    }

    fn given_receipt(logs: Vec<Log>) -> TransactionReceipt {
        let receipt = alloy_consensus::Receipt {
            logs,
            ..Default::default()
        };

        WithOtherFields::new(AlloyTransactionReceipt {
            inner: AnyReceiptEnvelope {
                inner: ReceiptWithBloom {
                    receipt,
                    ..Default::default()
                },
                r#type: 0,
            },
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
        })
    }
}
