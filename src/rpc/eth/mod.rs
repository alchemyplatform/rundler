mod error;

use crate::common::{
    contracts::entry_point::{
        EntryPointCalls, UserOperationEventFilter, UserOperationRevertReasonFilter,
    },
    eth::log_to_raw_log,
    types::UserOperation,
};
use anyhow::{bail, Context};
use ethers::{
    abi::{AbiDecode, RawLog},
    prelude::EthEvent,
    providers::{Http, Middleware, Provider},
    types::{Address, Bytes, Filter, Log, TransactionReceipt, H256, U256},
};
use jsonrpsee::core::{Error as RpcError, RpcResult};
use jsonrpsee::proc_macros::rpc;
use std::sync::Arc;
use tonic::async_trait;

use self::error::EthRpcError;

use super::{GasEstimate, RichUserOperation, UserOperationOptionalGas, UserOperationReceipt};

/// Eth API
#[rpc(server, namespace = "eth")]
pub trait EthApi {
    #[method(name = "sendUserOperation")]
    async fn send_user_operation(&self, op: UserOperation, entry_point: Address)
        -> RpcResult<H256>;

    #[method(name = "estimateUserOperationGas")]
    async fn estimate_user_operation_gas(
        &self,
        op: UserOperationOptionalGas,
        entry_point: Address,
    ) -> RpcResult<GasEstimate>;

    #[method(name = "getUserOperationByHash")]
    async fn get_user_operation_by_hash(&self, hash: H256) -> RpcResult<Option<RichUserOperation>>;

    #[method(name = "getUserOperationReceipt")]
    async fn get_user_operation_receipt(
        &self,
        hash: H256,
    ) -> RpcResult<Option<UserOperationReceipt>>;

    #[method(name = "supportedEntryPoints")]
    async fn supported_entry_points(&self) -> RpcResult<Vec<Address>>;

    #[method(name = "chainId")]
    async fn chain_id(&self) -> RpcResult<U256>;
}

pub struct EthApi {
    entry_points: Vec<Address>,
    provider: Arc<Provider<Http>>,
    chain_id: U256,
}

impl EthApi {
    pub fn new(provider: Arc<Provider<Http>>, entry_points: Vec<Address>, chain_id: U256) -> Self {
        Self {
            entry_points,
            provider,
            chain_id,
        }
    }

    async fn get_user_operation_event_by_hash(&self, hash: H256) -> anyhow::Result<Option<Log>> {
        let filter = Filter::new()
            .address(self.entry_points.clone())
            .topic1(hash);

        // we don't do .query().await here because we still need the raw logs for the TX
        // hash later. But hopefully this is a bit clearer than using .abi_signature()
        let filter = UserOperationEventFilter::new(filter, &self.provider).filter;

        let logs = self.provider.get_logs(&filter).await?;

        Ok(logs.into_iter().next())
    }

    fn get_user_operations_from_tx_data(
        &self,
        tx_data: Bytes,
    ) -> anyhow::Result<Vec<UserOperation>> {
        let entry_point_calls = EntryPointCalls::decode(tx_data)
            .context("should parse tx data as calls to the entry point")?;

        match entry_point_calls {
            EntryPointCalls::HandleOps(handle_ops_call) => Ok(handle_ops_call.ops),
            EntryPointCalls::HandleAggregatedOps(handle_aggregated_ops_call) => {
                Ok(handle_aggregated_ops_call
                    .ops_per_aggregator
                    .into_iter()
                    .flat_map(|ops| ops.user_ops)
                    .collect())
            }
            _ => bail!("tx should contain a user operations"),
        }
    }

    fn decode_user_operation_event(&self, log: Log) -> anyhow::Result<UserOperationEventFilter> {
        UserOperationEventFilter::decode_log(&log_to_raw_log(log))
            .context("log should be a user operation event")
    }

    /// This method takes a user operation event and a transaction receipt and filters out all the logs
    /// relevant to the user operation. Since there are potentially many user operations in a transaction,
    /// we want to find all the logs (including the user operation event itself) that are sandwiched between
    /// ours and the one before it that wasn't ours.
    /// eg. reference_log: UserOp(hash_moldy) logs: \[...OtherLogs, UserOp(hash1), ...OtherLogs, UserOp(hash_moldy), ...OtherLogs\]
    /// -> logs: logs\[(idx_of_UserOp(hash1) + 1)..=idx_of_UserOp(hash_moldy)\]
    ///
    /// topic\[0\] == event name
    /// topic\[1\] == user operation hash
    ///
    /// NOTE: we can't convert just decode all the logs as user operations and filter because we still want all the other log types
    ///
    fn filter_receipt_logs_matching_user_op(
        reference_log: &Log,
        tx_receipt: &TransactionReceipt,
    ) -> Result<Vec<Log>, anyhow::Error> {
        let mut start_idx = 0;
        let mut end_idx = tx_receipt.logs.len() - 1;
        let logs = &tx_receipt.logs;

        let is_ref_user_op = |log: &Log| {
            log.topics[0] == reference_log.topics[0]
                && log.topics[1] == reference_log.topics[1]
                && log.address == reference_log.address
        };

        let is_user_op_event = |log: &Log| log.topics[0] == reference_log.topics[0];

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
            bail!("fatal: no user ops found in tx receipt ({start_idx},{end_idx})")
        }

        let start_idx = if start_idx == 0 { 0 } else { start_idx + 1 };
        Ok(logs[start_idx..=end_idx].to_vec())
    }

    fn get_user_operation_failure_reason(
        logs: &[Log],
        user_op_hash: H256,
    ) -> Result<Option<String>, anyhow::Error> {
        let revert_reason_evt: Option<UserOperationRevertReasonFilter> = logs
            .iter()
            .filter(|l| l.topics[1] == user_op_hash)
            .map_while(|l| {
                UserOperationRevertReasonFilter::decode_log(&RawLog {
                    topics: l.topics.clone(),
                    data: l.data.to_vec(),
                })
                .ok()
            })
            .next();

        revert_reason_evt.map_or(Ok(None), |revert_reason_evt| {
            String::from_utf8(revert_reason_evt.revert_reason.to_vec())
                .map(Some)
                .context("should have parsed revert reason as string")
        })
    }
}

#[async_trait]
impl EthApiServer for EthApi {
    async fn send_user_operation(
        &self,
        _op: UserOperation,
        _entry_point: Address,
    ) -> RpcResult<H256> {
        Err(RpcError::HttpNotImplemented)
    }

    async fn estimate_user_operation_gas(
        &self,
        _op: UserOperationOptionalGas,
        _entry_point: Address,
    ) -> RpcResult<GasEstimate> {
        Err(RpcError::HttpNotImplemented)
    }

    async fn get_user_operation_by_hash(&self, hash: H256) -> RpcResult<Option<RichUserOperation>> {
        if hash == H256::zero() {
            return Err(EthRpcError::InvalidParams(
                "hash cannot be zero".to_string(),
            ))?;
        }

        // 1. Get event associated with hash (need to check all entry point addresses associated with this API)
        let event = self
            .get_user_operation_event_by_hash(hash)
            .await
            .context("should have successfully queried for user op events by hash")?;

        let Some(event) = event else {
            return Ok(None)
        };

        // 2. If the event is found, get the TX
        let transaction_hash = event
            .transaction_hash
            .context("tx_hash should be present")?;

        let tx = self
            .provider
            .get_transaction(transaction_hash)
            .await
            .context("should have fetched tx from provider")?
            .context("should have found tx")?;

        // We should return null if the tx isn't included in the block yet
        if tx.block_hash.is_none() && tx.block_number.is_none() {
            return Ok(None);
        }

        let to = tx
            .to
            .filter(|to| self.entry_points.contains(to))
            .context("Failed to parse tx or tx doesn't belong to entry point")?;

        // 3. parse the tx data using the EntryPoint interface and extract UserOperation[] from it
        let user_ops = self
            .get_user_operations_from_tx_data(tx.input)
            .context("should have parsed tx data as user operations")?;

        // 4. find first op matching sender + nonce with the event
        let event = self
            .decode_user_operation_event(event)
            .context("should have decoded log event as user operation event")?;

        let user_operation = user_ops
            .into_iter()
            .find(|op| op.sender == event.sender && op.nonce == event.nonce)
            .context("matching user operation should be found in tx data")?;

        // 5. return the result
        Ok(Some(RichUserOperation {
            user_operation,
            entry_point: to,
            block_number: tx
                .block_number
                .map(|n| U256::from(n.as_u64()))
                .unwrap_or_default(),
            block_hash: tx.block_hash.unwrap_or_default(),
            transaction_hash,
        }))
    }

    async fn get_user_operation_receipt(
        &self,
        hash: H256,
    ) -> RpcResult<Option<UserOperationReceipt>> {
        if hash == H256::zero() {
            return Err(EthRpcError::InvalidParams(
                "hash cannot be zero".to_string(),
            ))?;
        }

        // 1. Get event associated with hash (need to check all entry point addresses associated with this API)
        let log = self
            .get_user_operation_event_by_hash(hash)
            .await
            .context("should have fetched user ops by hash")?;

        let Some(log) = log else {
            return Ok(None)
        };

        // 2. If the event is found, get the TX receipt
        let tx_hash = log.transaction_hash.context("tx_hash should be present")?;

        let tx_receipt = self
            .provider
            .get_transaction_receipt(tx_hash)
            .await
            .context("should have fetched tx receipt")?
            .context("Failed to fetch tx receipt")?;

        // We should return null if the tx isn't included in the block yet
        if tx_receipt.block_hash.is_none() && tx_receipt.block_number.is_none() {
            return Ok(None);
        }

        let to = tx_receipt
            .to
            .filter(|to| self.entry_points.contains(to))
            .context("Failed to parse tx or tx doesn't belong to entry point")?;

        // 3. filter receipt logs to match just those belonging to the user op
        let filtered_logs = EthApi::filter_receipt_logs_matching_user_op(&log, &tx_receipt)
            .context("should have found receipt logs matching user op")?;

        // 4. decode log and find failure reason if not success
        let log = self
            .decode_user_operation_event(log)
            .context("should have decoded user operation event")?;

        let reason: Option<String> = if log.success {
            None
        } else {
            EthApi::get_user_operation_failure_reason(&tx_receipt.logs, hash)
                .context("should have found revert reason if tx wasn't successful")?
        };

        // 5. Return the result
        Ok(Some(UserOperationReceipt {
            user_op_hash: hash,
            entry_point: to,
            sender: log.sender,
            nonce: log.nonce,
            paymaster: log.paymaster,
            actual_gas_cost: log.actual_gas_cost,
            acutal_gas_used: log.actual_gas_used,
            success: log.success,
            logs: filtered_logs,
            receipt: tx_receipt,
            reason,
        }))
    }

    async fn supported_entry_points(&self) -> RpcResult<Vec<Address>> {
        Ok(self.entry_points.clone())
    }

    async fn chain_id(&self) -> RpcResult<U256> {
        Ok(self.chain_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::{
        types::{Log, TransactionReceipt},
        utils::keccak256,
    };

    const UO_OP_TOPIC: &str = "user-op-event-topic";

    #[test]
    fn test_filter_receipt_logs_when_at_begining_of_list() {
        let reference_log = given_log(UO_OP_TOPIC, "moldy-hash");
        let receipt = given_receipt(vec![
            given_log("other-topic", "some-hash"),
            reference_log.clone(),
            given_log(UO_OP_TOPIC, "other-hash"),
            given_log(UO_OP_TOPIC, "another-hash"),
        ]);

        let result = EthApi::filter_receipt_logs_matching_user_op(&reference_log, &receipt);

        assert!(result.is_ok(), "{}", result.unwrap_err());
        let result = result.unwrap();
        assert_eq!(result, receipt.logs[0..=1]);
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

        let result = EthApi::filter_receipt_logs_matching_user_op(&reference_log, &receipt);

        assert!(result.is_ok(), "{}", result.unwrap_err());
        let result = result.unwrap();
        assert_eq!(result, receipt.logs[2..=4]);
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

        let result = EthApi::filter_receipt_logs_matching_user_op(&reference_log, &receipt);

        assert!(result.is_ok(), "{}", result.unwrap_err());
        let result = result.unwrap();
        assert_eq!(result, receipt.logs[3..=5]);
    }

    #[test]
    fn test_filter_receipt_logs_skips_event_from_different_address() {
        let reference_log = given_log(UO_OP_TOPIC, "moldy-hash");
        let mut reference_log_w_different_address = reference_log.clone();
        reference_log_w_different_address.address = Address::from_low_u64_be(0x1234);

        let receipt = given_receipt(vec![
            given_log("other-topic", "some-hash"),
            given_log(UO_OP_TOPIC, "other-hash"),
            given_log(UO_OP_TOPIC, "another-hash"),
            reference_log_w_different_address,
            given_log("another-topic", "some-hash"),
            given_log("another-topic-2", "some-hash"),
            reference_log.clone(),
        ]);

        let result = EthApi::filter_receipt_logs_matching_user_op(&reference_log, &receipt);

        assert!(result.is_ok(), "{}", result.unwrap_err());
        let result = result.unwrap();
        assert_eq!(result, receipt.logs[4..=6]);
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

        let result = EthApi::filter_receipt_logs_matching_user_op(&reference_log, &receipt);

        assert!(result.is_ok(), "{}", result.unwrap_err());
        let result = result.unwrap();
        assert_eq!(result, receipt.logs[2..=6]);
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

        let result = EthApi::filter_receipt_logs_matching_user_op(&reference_log, &receipt);

        assert!(result.is_err(), "{:?}", result.unwrap());
    }

    fn given_log(topic_0: &str, topic_1: &str) -> Log {
        Log {
            topics: vec![
                keccak256(topic_0.as_bytes()).into(),
                keccak256(topic_1.as_bytes()).into(),
            ],
            ..Default::default()
        }
    }

    fn given_receipt(logs: Vec<Log>) -> TransactionReceipt {
        TransactionReceipt {
            logs,
            ..Default::default()
        }
    }
}
