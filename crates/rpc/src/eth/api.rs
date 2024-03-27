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

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};

use anyhow::Context;
use ethers::{
    abi::{AbiDecode, RawLog},
    prelude::EthEvent,
    types::{
        spoof, Address, Bytes, Filter, GethDebugBuiltInTracerType, GethDebugTracerType,
        GethDebugTracingOptions, GethTrace, GethTraceFrame, Log, TransactionReceipt, H256, U256,
        U64,
    },
    utils::to_checksum,
};
use rundler_pool::PoolServer;
use rundler_provider::{EntryPoint, Provider};
use rundler_sim::{
    EstimationSettings, FeeEstimator, GasEstimate, GasEstimationError, GasEstimator,
    GasEstimatorImpl, PrecheckSettings, UserOperationOptionalGas,
};
use rundler_types::{
    chain::ChainSpec,
    contracts::i_entry_point::{
        IEntryPointCalls, UserOperationEventFilter, UserOperationRevertReasonFilter,
    },
    UserOperation,
};
use rundler_utils::{eth::log_to_raw_log, log::LogOnError};
use tracing::Level;

use super::error::{EthResult, EthRpcError, ExecutionRevertedWithBytesData};
use crate::types::{RichUserOperation, RpcUserOperation, UserOperationReceipt};

/// Settings for the `eth_` API
#[derive(Copy, Clone, Debug)]
pub struct Settings {
    /// The number of blocks to look back for user operation events
    pub user_operation_event_block_distance: Option<u64>,
}

impl Settings {
    /// Create new settings for the `eth_` API
    pub fn new(block_distance: Option<u64>) -> Self {
        Self {
            user_operation_event_block_distance: block_distance,
        }
    }
}

#[derive(Debug)]
struct EntryPointContext<P, E> {
    gas_estimator: GasEstimatorImpl<P, E>,
}

impl<P, E> EntryPointContext<P, E>
where
    P: Provider,
    E: EntryPoint,
{
    fn new(
        chain_spec: ChainSpec,
        provider: Arc<P>,
        entry_point: E,
        estimation_settings: EstimationSettings,
        fee_estimator: FeeEstimator<P>,
    ) -> Self {
        let gas_estimator = GasEstimatorImpl::new(
            chain_spec,
            provider,
            entry_point,
            estimation_settings,
            fee_estimator,
        );
        Self { gas_estimator }
    }
}

#[derive(Debug)]
pub(crate) struct EthApi<P, E, PS> {
    contexts_by_entry_point: HashMap<Address, EntryPointContext<P, E>>,
    provider: Arc<P>,
    chain_spec: ChainSpec,
    pool: PS,
    settings: Settings,
}

impl<P, E, PS> EthApi<P, E, PS>
where
    P: Provider,
    E: EntryPoint,
    PS: PoolServer,
{
    pub(crate) fn new(
        chain_spec: ChainSpec,
        provider: Arc<P>,
        entry_points: Vec<E>,
        pool: PS,
        settings: Settings,
        estimation_settings: EstimationSettings,
        precheck_settings: PrecheckSettings,
    ) -> Self
    where
        E: Clone,
    {
        let contexts_by_entry_point = entry_points
            .into_iter()
            .map(|entry_point| {
                (
                    entry_point.address(),
                    EntryPointContext::new(
                        chain_spec.clone(),
                        Arc::clone(&provider),
                        entry_point,
                        estimation_settings,
                        FeeEstimator::new(
                            &chain_spec,
                            Arc::clone(&provider),
                            precheck_settings.priority_fee_mode,
                            precheck_settings.bundle_priority_fee_overhead_percent,
                        ),
                    ),
                )
            })
            .collect();

        Self {
            settings,
            contexts_by_entry_point,
            provider,
            chain_spec,
            pool,
        }
    }

    pub(crate) async fn send_user_operation(
        &self,
        op: RpcUserOperation,
        entry_point: Address,
    ) -> EthResult<H256> {
        if !self.contexts_by_entry_point.contains_key(&entry_point) {
            return Err(EthRpcError::InvalidParams(
                "supplied entry point addr is not a known entry point".to_string(),
            ));
        }
        self.pool
            .add_op(entry_point, op.into())
            .await
            .map_err(EthRpcError::from)
            .log_on_error_level(Level::DEBUG, "failed to add op to the mempool")
    }

    pub(crate) async fn estimate_user_operation_gas(
        &self,
        op: UserOperationOptionalGas,
        entry_point: Address,
        state_override: Option<spoof::State>,
    ) -> EthResult<GasEstimate> {
        let context = self
            .contexts_by_entry_point
            .get(&entry_point)
            .ok_or_else(|| {
                EthRpcError::InvalidParams(
                    "supplied entry_point address is not a known entry point".to_string(),
                )
            })?;

        let result = context
            .gas_estimator
            .estimate_op_gas(op, state_override.unwrap_or_default())
            .await;
        match result {
            Ok(estimate) => Ok(estimate),
            Err(GasEstimationError::RevertInValidation(message)) => {
                Err(EthRpcError::EntryPointValidationRejected(message))?
            }
            Err(GasEstimationError::RevertInCallWithMessage(message)) => {
                Err(EthRpcError::ExecutionReverted(message))?
            }
            Err(GasEstimationError::RevertInCallWithBytes(b)) => {
                Err(EthRpcError::ExecutionRevertedWithBytes(
                    ExecutionRevertedWithBytesData { revert_data: b },
                ))?
            }
            Err(GasEstimationError::Other(error)) => Err(error)?,
        }
    }

    pub(crate) async fn get_user_operation_by_hash(
        &self,
        hash: H256,
    ) -> EthResult<Option<RichUserOperation>> {
        if hash == H256::zero() {
            return Err(EthRpcError::InvalidParams(
                "Missing/invalid userOpHash".to_string(),
            ));
        }

        // check for the user operation both in the pool and mined on chain
        let mined_fut = self.get_mined_user_operation_by_hash(hash);
        let pending_fut = self.get_pending_user_operation_by_hash(hash);
        let (mined, pending) = tokio::join!(mined_fut, pending_fut);

        // mined takes precedence over pending
        if let Ok(Some(mined)) = mined {
            Ok(Some(mined))
        } else if let Ok(Some(pending)) = pending {
            Ok(Some(pending))
        } else if mined.is_err() || pending.is_err() {
            // if either futures errored, and the UO was not found, return the errors
            Err(EthRpcError::Internal(anyhow::anyhow!(
                "error fetching user operation by hash: mined: {:?}, pending: {:?}",
                mined.err().map(|e| e.to_string()).unwrap_or_default(),
                pending.err().map(|e| e.to_string()).unwrap_or_default(),
            )))
        } else {
            // not found in either pool or mined
            Ok(None)
        }
    }

    pub(crate) async fn get_user_operation_receipt(
        &self,
        hash: H256,
    ) -> EthResult<Option<UserOperationReceipt>> {
        if hash == H256::zero() {
            return Err(EthRpcError::InvalidParams(
                "Missing/invalid userOpHash".to_string(),
            ));
        }

        // Get event associated with hash (need to check all entry point addresses associated with this API)
        let log = self
            .get_user_operation_event_by_hash(hash)
            .await
            .context("should have fetched user ops by hash")?;

        let Some(log) = log else { return Ok(None) };
        let entry_point = log.address;

        // If the event is found, get the TX receipt
        let tx_hash = log.transaction_hash.context("tx_hash should be present")?;
        let tx_receipt = self
            .provider
            .get_transaction_receipt(tx_hash)
            .await
            .context("should have fetched tx receipt")?
            .context("Failed to fetch tx receipt")?;

        // Return null if the tx isn't included in the block yet
        if tx_receipt.block_hash.is_none() && tx_receipt.block_number.is_none() {
            return Ok(None);
        }

        // Filter receipt logs to match just those belonging to the user op
        let filtered_logs =
            EthApi::<P, E, PS>::filter_receipt_logs_matching_user_op(&log, &tx_receipt)
                .context("should have found receipt logs matching user op")?;

        // Decode log and find failure reason if not success
        let uo_event = self
            .decode_user_operation_event(log)
            .context("should have decoded user operation event")?;
        let reason: String = if uo_event.success {
            "".to_owned()
        } else {
            EthApi::<P, E, PS>::get_user_operation_failure_reason(&tx_receipt.logs, hash)
                .context("should have found revert reason if tx wasn't successful")?
                .unwrap_or_default()
        };

        Ok(Some(UserOperationReceipt {
            user_op_hash: hash,
            entry_point: entry_point.into(),
            sender: uo_event.sender.into(),
            nonce: uo_event.nonce,
            paymaster: uo_event.paymaster.into(),
            actual_gas_cost: uo_event.actual_gas_cost,
            actual_gas_used: uo_event.actual_gas_used,
            success: uo_event.success,
            logs: filtered_logs,
            receipt: tx_receipt,
            reason,
        }))
    }

    pub(crate) async fn supported_entry_points(&self) -> EthResult<Vec<String>> {
        Ok(self
            .contexts_by_entry_point
            .keys()
            .map(|ep| to_checksum(ep, None))
            .collect())
    }

    pub(crate) async fn chain_id(&self) -> EthResult<U64> {
        Ok(self.chain_spec.id.into())
    }

    async fn get_mined_user_operation_by_hash(
        &self,
        hash: H256,
    ) -> EthResult<Option<RichUserOperation>> {
        // Get event associated with hash (need to check all entry point addresses associated with this API)
        let event = self
            .get_user_operation_event_by_hash(hash)
            .await
            .log_on_error("should have successfully queried for user op events by hash")?;

        let Some(event) = event else { return Ok(None) };

        // If the event is found, get the TX and entry point
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
            .context("tx.to should be present on transaction containing user operation event")?;

        // Find first op matching the hash
        let user_operation = if self.contexts_by_entry_point.contains_key(&to) {
            self.get_user_operations_from_tx_data(tx.input)
                .into_iter()
                .find(|op| op.op_hash(to, self.chain_spec.id) == hash)
                .context("matching user operation should be found in tx data")?
        } else {
            self.trace_find_user_operation(transaction_hash, hash)
                .await
                .context("error running trace")?
                .context("should have found user operation in trace")?
        };

        Ok(Some(RichUserOperation {
            user_operation: user_operation.into(),
            entry_point: event.address.into(),
            block_number: Some(
                tx.block_number
                    .map(|n| U256::from(n.as_u64()))
                    .unwrap_or_default(),
            ),
            block_hash: Some(tx.block_hash.unwrap_or_default()),
            transaction_hash: Some(transaction_hash),
        }))
    }

    async fn get_pending_user_operation_by_hash(
        &self,
        hash: H256,
    ) -> EthResult<Option<RichUserOperation>> {
        let res = self
            .pool
            .get_op_by_hash(hash)
            .await
            .map_err(EthRpcError::from)?;
        Ok(res.map(|op| RichUserOperation {
            user_operation: op.uo.into(),
            entry_point: op.entry_point.into(),
            block_number: None,
            block_hash: None,
            transaction_hash: None,
        }))
    }

    async fn get_user_operation_event_by_hash(&self, hash: H256) -> EthResult<Option<Log>> {
        let to_block = self.provider.get_block_number().await?;

        let from_block = match self.settings.user_operation_event_block_distance {
            Some(distance) => to_block.saturating_sub(distance),
            None => 0,
        };

        let filter = Filter::new()
            .address::<Vec<Address>>(
                self.contexts_by_entry_point
                    .iter()
                    .map(|ep| *ep.0)
                    .collect(),
            )
            .event(&UserOperationEventFilter::abi_signature())
            .from_block(from_block)
            .to_block(to_block)
            .topic1(hash);

        let logs = self.provider.get_logs(&filter).await?;
        Ok(logs.into_iter().next())
    }

    fn get_user_operations_from_tx_data(&self, tx_data: Bytes) -> Vec<UserOperation> {
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

    fn decode_user_operation_event(&self, log: Log) -> EthResult<UserOperationEventFilter> {
        Ok(UserOperationEventFilter::decode_log(&log_to_raw_log(log))
            .context("log should be a user operation event")?)
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
    ) -> EthResult<Vec<Log>> {
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
            return Err(EthRpcError::Internal(anyhow::anyhow!(
                "fatal: no user ops found in tx receipt ({start_idx},{end_idx})"
            )));
        }

        let start_idx = if start_idx == 0 { 0 } else { start_idx + 1 };
        Ok(logs[start_idx..=end_idx].to_vec())
    }

    fn get_user_operation_failure_reason(
        logs: &[Log],
        user_op_hash: H256,
    ) -> EthResult<Option<String>> {
        let revert_reason_evt: Option<UserOperationRevertReasonFilter> = logs
            .iter()
            .filter(|l| l.topics.len() > 1 && l.topics[1] == user_op_hash)
            .map_while(|l| {
                UserOperationRevertReasonFilter::decode_log(&RawLog {
                    topics: l.topics.clone(),
                    data: l.data.to_vec(),
                })
                .ok()
            })
            .next();

        Ok(revert_reason_evt.map(|r| r.revert_reason.to_string()))
    }

    /// This method takes a transaction hash and a user operation hash and returns the full user operation if it exists.
    /// This is meant to be used when a user operation event is found in the logs of a transaction, but the top level call
    /// wasn't to an entrypoint, so we need to trace the transaction to find the user operation by inspecting each call frame
    /// and returning the user operation that matches the hash.
    async fn trace_find_user_operation(
        &self,
        tx_hash: H256,
        user_op_hash: H256,
    ) -> EthResult<Option<UserOperation>> {
        // initial call wasn't to an entrypoint, so we need to trace the transaction to find the user operation
        let trace_options = GethDebugTracingOptions {
            tracer: Some(GethDebugTracerType::BuiltInTracer(
                GethDebugBuiltInTracerType::CallTracer,
            )),
            ..Default::default()
        };
        let trace = self
            .provider
            .debug_trace_transaction(tx_hash, trace_options)
            .await
            .context("should have fetched trace from provider")?;

        // breadth first search for the user operation in the trace
        let mut frame_queue = VecDeque::new();

        if let GethTrace::Known(GethTraceFrame::CallTracer(call_frame)) = trace {
            frame_queue.push_back(call_frame);
        }

        while let Some(call_frame) = frame_queue.pop_front() {
            // check if the call is to an entrypoint, if not enqueue the child calls if any
            if let Some(to) = call_frame
                .to
                .as_ref()
                .and_then(|to| to.as_address())
                .filter(|to| self.contexts_by_entry_point.contains_key(to))
            {
                // check if the user operation is in the call frame
                if let Some(uo) = self
                    .get_user_operations_from_tx_data(call_frame.input)
                    .into_iter()
                    .find(|op| op.op_hash(*to, self.chain_spec.id) == user_op_hash)
                {
                    return Ok(Some(uo));
                }
            } else if let Some(calls) = call_frame.calls {
                frame_queue.extend(calls)
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use ethers::{
        abi::AbiEncode,
        types::{Log, Transaction, TransactionReceipt},
        utils::keccak256,
    };
    use mockall::predicate::eq;
    use rundler_pool::{MockPoolServer, PoolOperation};
    use rundler_provider::{MockEntryPoint, MockProvider};
    use rundler_sim::PriorityFeeMode;
    use rundler_types::contracts::i_entry_point::HandleOpsCall;

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

        let result =
            EthApi::<MockProvider, MockEntryPoint, MockPoolServer>::filter_receipt_logs_matching_user_op(
                &reference_log,
                &receipt,
            );

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

        let result =
            EthApi::<MockProvider, MockEntryPoint, MockPoolServer>::filter_receipt_logs_matching_user_op(
                &reference_log,
                &receipt,
            );

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

        let result =
            EthApi::<MockProvider, MockEntryPoint, MockPoolServer>::filter_receipt_logs_matching_user_op(
                &reference_log,
                &receipt,
            );

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

        let result =
            EthApi::<MockProvider, MockEntryPoint, MockPoolServer>::filter_receipt_logs_matching_user_op(
                &reference_log,
                &receipt,
            );

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

        let result =
            EthApi::<MockProvider, MockEntryPoint, MockPoolServer>::filter_receipt_logs_matching_user_op(
                &reference_log,
                &receipt,
            );

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

        let result =
            EthApi::<MockProvider, MockEntryPoint, MockPoolServer>::filter_receipt_logs_matching_user_op(
                &reference_log,
                &receipt,
            );

        assert!(result.is_err(), "{:?}", result.unwrap());
    }

    #[tokio::test]
    async fn test_get_user_op_by_hash_pending() {
        let ep = Address::random();
        let uo = UserOperation::default();
        let hash = uo.op_hash(ep, 1);

        let po = PoolOperation {
            uo: uo.clone(),
            entry_point: ep,
            ..Default::default()
        };

        let mut pool = MockPoolServer::default();
        pool.expect_get_op_by_hash()
            .with(eq(hash))
            .times(1)
            .returning(move |_| Ok(Some(po.clone())));

        let mut provider = MockProvider::default();
        provider.expect_get_logs().returning(move |_| Ok(vec![]));
        provider.expect_get_block_number().returning(|| Ok(1000));

        let mut entry_point = MockEntryPoint::default();
        entry_point.expect_address().returning(move || ep);

        let api = create_api(provider, entry_point, pool);
        let res = api.get_user_operation_by_hash(hash).await.unwrap();
        let ro = RichUserOperation {
            user_operation: uo.into(),
            entry_point: ep.into(),
            block_number: None,
            block_hash: None,
            transaction_hash: None,
        };
        assert_eq!(res, Some(ro));
    }

    #[tokio::test]
    async fn test_get_user_op_by_hash_mined() {
        let ep = Address::random();
        let uo = UserOperation::default();
        let hash = uo.op_hash(ep, 1);
        let block_number = 1000;
        let block_hash = H256::random();

        let mut pool = MockPoolServer::default();
        pool.expect_get_op_by_hash()
            .with(eq(hash))
            .returning(move |_| Ok(None));

        let mut provider = MockProvider::default();
        provider.expect_get_block_number().returning(|| Ok(1000));

        let tx_data: Bytes = IEntryPointCalls::HandleOps(HandleOpsCall {
            beneficiary: Address::zero(),
            ops: vec![uo.clone()],
        })
        .encode()
        .into();
        let tx = Transaction {
            to: Some(ep),
            input: tx_data,
            block_number: Some(block_number.into()),
            block_hash: Some(block_hash),
            ..Default::default()
        };
        let tx_hash = tx.hash();
        let log = Log {
            address: ep,
            transaction_hash: Some(tx_hash),
            ..Default::default()
        };

        provider
            .expect_get_logs()
            .returning(move |_| Ok(vec![log.clone()]));
        provider
            .expect_get_transaction()
            .with(eq(tx_hash))
            .returning(move |_| Ok(Some(tx.clone())));

        let mut entry_point = MockEntryPoint::default();
        entry_point.expect_address().returning(move || ep);

        let api = create_api(provider, entry_point, pool);
        let res = api.get_user_operation_by_hash(hash).await.unwrap();
        let ro = RichUserOperation {
            user_operation: uo.into(),
            entry_point: ep.into(),
            block_number: Some(block_number.into()),
            block_hash: Some(block_hash),
            transaction_hash: Some(tx_hash),
        };
        assert_eq!(res, Some(ro));
    }

    #[tokio::test]
    async fn test_get_user_op_by_hash_not_found() {
        let ep = Address::random();
        let uo = UserOperation::default();
        let hash = uo.op_hash(ep, 1);

        let mut pool = MockPoolServer::default();
        pool.expect_get_op_by_hash()
            .with(eq(hash))
            .times(1)
            .returning(move |_| Ok(None));

        let mut provider = MockProvider::default();
        provider.expect_get_logs().returning(move |_| Ok(vec![]));
        provider.expect_get_block_number().returning(|| Ok(1000));

        let mut entry_point = MockEntryPoint::default();
        entry_point.expect_address().returning(move || ep);

        let api = create_api(provider, entry_point, pool);
        let res = api.get_user_operation_by_hash(hash).await.unwrap();
        assert_eq!(res, None);
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

    fn create_api(
        provider: MockProvider,
        ep: MockEntryPoint,
        pool: MockPoolServer,
    ) -> EthApi<MockProvider, MockEntryPoint, MockPoolServer> {
        let mut contexts_by_entry_point = HashMap::new();
        let provider = Arc::new(provider);
        let chain_spec = ChainSpec {
            id: 1,
            ..Default::default()
        };
        contexts_by_entry_point.insert(
            ep.address(),
            EntryPointContext::new(
                chain_spec.clone(),
                Arc::clone(&provider),
                ep,
                EstimationSettings {
                    max_verification_gas: 1_000_000,
                    max_call_gas: 1_000_000,
                    max_simulate_handle_ops_gas: 1_000_000,
                    verification_estimation_gas_fee: 1_000_000_000_000,
                },
                FeeEstimator::new(
                    &chain_spec,
                    Arc::clone(&provider),
                    PriorityFeeMode::BaseFeePercent(0),
                    0,
                ),
            ),
        );
        EthApi {
            contexts_by_entry_point,
            provider,
            chain_spec,
            pool,
            settings: Settings::new(None),
        }
    }
}
