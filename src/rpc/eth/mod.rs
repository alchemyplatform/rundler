mod error;
pub mod estimation;
use std::{
    collections::{HashMap, VecDeque},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use anyhow::{anyhow, bail, Context};
use ethers::{
    abi::{AbiDecode, RawLog},
    prelude::EthEvent,
    types::{
        Address, Bytes, Filter, GethDebugBuiltInTracerType, GethDebugTracerType,
        GethDebugTracingOptions, GethTrace, GethTraceFrame, Log, Opcode, TransactionReceipt, H256,
        U256, U64,
    },
    utils::to_checksum,
};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use prost::Message;
use tonic::{async_trait, transport::Channel, Status};
use tracing::{debug, Level};

use self::{
    error::{
        EthRpcError, OutOfTimeRangeData, PaymasterValidationRejectedData,
        ReplacementUnderpricedData, StakeTooLowData, UnsupportedAggregatorData,
    },
    estimation::GasEstimator,
};
use crate::{
    common::{
        context::LogOnError,
        contracts::i_entry_point::{
            IEntryPointCalls, UserOperationEventFilter, UserOperationRevertReasonFilter,
        },
        eth::{log_to_raw_log, Settings},
        mempool::MempoolConfig,
        precheck::{self, PrecheckError, Prechecker, PrecheckerImpl},
        protos::op_pool::{
            op_pool_client::OpPoolClient, AddOpRequest, EntityType as ProtoEntityType, ErrorInfo,
            ErrorMetadataKey, ErrorReason, MempoolOp,
        },
        simulation::{
            self, SimulationError, SimulationSuccess, SimulationViolation, Simulator, SimulatorImpl,
        },
        types::{Entity, EntityType, EntryPointLike, ProviderLike, Timestamp, UserOperation},
    },
    rpc::{
        estimation::{GasEstimationError, GasEstimatorImpl},
        GasEstimate, RichUserOperation, RpcUserOperation, UserOperationOptionalGas,
        UserOperationReceipt,
    },
};

/// Eth API
#[rpc(client, server, namespace = "eth")]
#[cfg_attr(test, automock)]
pub trait EthApi {
    #[method(name = "sendUserOperation")]
    async fn send_user_operation(
        &self,
        op: RpcUserOperation,
        entry_point: Address,
    ) -> RpcResult<H256>;

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
    async fn supported_entry_points(&self) -> RpcResult<Vec<String>>;

    #[method(name = "chainId")]
    async fn chain_id(&self) -> RpcResult<U64>;
}

#[derive(Debug)]
struct EntryPointContext<P: ProviderLike, E: EntryPointLike> {
    entry_point: E,
    prechecker: PrecheckerImpl<P, E>,
    simulator: SimulatorImpl<P, E>,
    gas_estimator: GasEstimatorImpl<P, E>,
}

impl<P, E> EntryPointContext<P, E>
where
    P: ProviderLike,
    E: EntryPointLike,
{
    pub fn new(
        chain_id: u64,
        provider: Arc<P>,
        entry_point: E,
        precheck_settings: precheck::Settings,
        sim_settings: simulation::Settings,
        estimator_settings: estimation::Settings,
        mempool_configs: HashMap<H256, MempoolConfig>,
    ) -> Self
    where
        E: Clone, // Add Clone trait bound for E
    {
        let prechecker = PrecheckerImpl::new(
            Arc::clone(&provider),
            chain_id,
            entry_point.clone(),
            precheck_settings,
        );
        let simulator = SimulatorImpl::new(
            Arc::clone(&provider),
            entry_point.clone(),
            sim_settings,
            mempool_configs,
        );
        let gas_estimator =
            GasEstimatorImpl::new(chain_id, provider, entry_point.clone(), estimator_settings);
        Self {
            entry_point,
            prechecker,
            simulator,
            gas_estimator,
        }
    }
}

#[derive(Debug)]
pub struct EthApi<P: ProviderLike, E: EntryPointLike> {
    contexts_by_entry_point: HashMap<Address, EntryPointContext<P, E>>,
    provider: Arc<P>,
    chain_id: u64,
    op_pool_client: OpPoolClient<Channel>,
    settings: Settings,
}

impl<P, E> EthApi<P, E>
where
    P: ProviderLike,
    E: EntryPointLike,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider: Arc<P>,
        entry_points: Vec<E>,
        chain_id: u64,
        op_pool_client: OpPoolClient<Channel>,
        precheck_settings: precheck::Settings,
        settings: Settings,
        sim_settings: simulation::Settings,
        estimation_settings: estimation::Settings,
        mempool_configs: HashMap<H256, MempoolConfig>,
    ) -> Self
    where
        E: Clone,
    {
        let contexts_by_entry_point = entry_points
            .into_iter()
            .map(|entry| {
                (
                    entry.address(),
                    EntryPointContext::new(
                        chain_id,
                        Arc::clone(&provider),
                        entry,
                        precheck_settings,
                        sim_settings,
                        estimation_settings,
                        mempool_configs.clone(),
                    ),
                )
            })
            .collect();

        Self {
            settings,
            contexts_by_entry_point,
            provider,
            chain_id,
            op_pool_client,
        }
    }

    async fn get_user_operation_event_by_hash(&self, hash: H256) -> anyhow::Result<Option<Log>> {
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
    ) -> Result<Option<UserOperation>, anyhow::Error> {
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
                    .find(|op| op.op_hash(*to, self.chain_id) == user_op_hash)
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

const EXPIRATION_BUFFER: Duration = Duration::from_secs(30);

#[async_trait]
impl<P, E> EthApiServer for EthApi<P, E>
where
    P: ProviderLike,
    E: EntryPointLike,
{
    async fn send_user_operation(
        &self,
        op: RpcUserOperation,
        entry_point: Address,
    ) -> RpcResult<H256> {
        if !self.contexts_by_entry_point.contains_key(&entry_point) {
            return Err(EthRpcError::InvalidParams(
                "supplied entry point addr is not a known entry point".to_string(),
            ))?;
        }

        let op: UserOperation = op.into();

        let EntryPointContext {
            entry_point,
            prechecker,
            simulator,
            ..
        } = self
            .contexts_by_entry_point
            .get(&entry_point)
            .context("entry point should exist in the map")?;

        // 1. Validate op with simple prechecks
        prechecker.check(&op).await.map_err(EthRpcError::from)?;

        // 2. Validate op with simulation
        let SimulationSuccess {
            valid_time_range,
            code_hash,
            aggregator,
            entities_needing_stake,
            block_hash,
            account_is_staked,
            ..
        } = simulator
            .simulate_validation(op.clone(), None, None)
            .await
            .map_err(EthRpcError::from)?;

        if let Some(agg) = &aggregator {
            // TODO(danc): all aggregators are currently unsupported
            Err(EthRpcError::UnsupportedAggregator(
                UnsupportedAggregatorData {
                    aggregator: agg.address,
                },
            ))?
        }

        let now = Timestamp::now();
        let valid_after = valid_time_range.valid_after;
        let valid_until = valid_time_range.valid_until;
        if !valid_time_range.contains(now, EXPIRATION_BUFFER) {
            Err(EthRpcError::OutOfTimeRange(OutOfTimeRangeData {
                valid_after,
                valid_until,
                paymaster: op.paymaster(),
            }))?
        }

        // 3. send op the mempool
        let add_op_result = self
            .op_pool_client
            .clone()
            .add_op(AddOpRequest {
                entry_point: entry_point.address().as_bytes().to_vec(),
                op: Some(MempoolOp {
                    uo: Some((&op).into()),
                    aggregator: aggregator.unwrap_or_default().address.as_bytes().to_vec(),
                    valid_after: valid_after.seconds_since_epoch(),
                    valid_until: valid_until.seconds_since_epoch(),
                    expected_code_hash: code_hash.as_bytes().to_vec(),
                    sim_block_hash: block_hash.as_bytes().to_vec(),
                    entities_needing_stake: entities_needing_stake
                        .iter()
                        .map(|&e| ProtoEntityType::from(e).into())
                        .collect(),
                    account_is_staked,
                }),
            })
            .await
            .map_err(EthRpcError::from)
            .log_on_error_level(Level::DEBUG, "failed to add op to the mempool")?;

        // 4. return the op hash
        Ok(H256::from_slice(&add_op_result.into_inner().hash))
    }

    async fn estimate_user_operation_gas(
        &self,
        op: UserOperationOptionalGas,
        entry_point: Address,
    ) -> RpcResult<GasEstimate> {
        let context = self
            .contexts_by_entry_point
            .get(&entry_point)
            .ok_or_else(|| {
                EthRpcError::InvalidParams(
                    "supplied entry_point address is not a known entry point".to_string(),
                )
            })?;

        let result = context.gas_estimator.estimate_op_gas(op).await;
        match result {
            Ok(estimate) => Ok(estimate),
            Err(GasEstimationError::RevertInValidation(message)) => {
                Err(EthRpcError::EntryPointValidationRejected(message))?
            }
            Err(GasEstimationError::RevertInCallWithMessage(message)) => {
                Err(EthRpcError::ExecutionReverted(message))?
            }
            Err(error @ GasEstimationError::RevertInCallWithBytes(_)) => {
                Err(EthRpcError::ExecutionReverted(error.to_string()))?
            }
            Err(GasEstimationError::Other(error)) => Err(error)?,
        }
    }

    async fn get_user_operation_by_hash(&self, hash: H256) -> RpcResult<Option<RichUserOperation>> {
        if hash == H256::zero() {
            return Err(EthRpcError::InvalidParams(
                "Missing/invalid userOpHash".to_string(),
            ))?;
        }

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
                .find(|op| op.op_hash(to, self.chain_id) == hash)
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
                "Missing/invalid userOpHash".to_string(),
            ))?;
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
        let filtered_logs = EthApi::<P, E>::filter_receipt_logs_matching_user_op(&log, &tx_receipt)
            .context("should have found receipt logs matching user op")?;

        // Decode log and find failure reason if not success
        let uo_event = self
            .decode_user_operation_event(log)
            .context("should have decoded user operation event")?;
        let reason: String = if uo_event.success {
            "".to_owned()
        } else {
            EthApi::<P, E>::get_user_operation_failure_reason(&tx_receipt.logs, hash)
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

    async fn supported_entry_points(&self) -> RpcResult<Vec<String>> {
        Ok(self
            .contexts_by_entry_point
            .keys()
            .map(|ep| to_checksum(ep, None))
            .collect())
    }

    async fn chain_id(&self) -> RpcResult<U64> {
        Ok(self.chain_id.into())
    }
}

impl From<PrecheckError> for EthRpcError {
    fn from(value: PrecheckError) -> Self {
        match &value {
            PrecheckError::Violations(_) => Self::PrecheckFailed(value),
            PrecheckError::Other(_) => Self::Internal(value.into()),
        }
    }
}

impl From<SimulationError> for EthRpcError {
    fn from(mut value: SimulationError) -> Self {
        debug!("Simulation error: {value:?}");

        let SimulationError::Violations(violations) = &mut value else {
            return Self::Internal(value.into());
        };

        let Some(violation) = violations.iter().min() else {
            return Self::Internal(value.into());
        };

        match violation {
            SimulationViolation::InvalidSignature => Self::SignatureCheckFailed,
            SimulationViolation::UnintendedRevertWithMessage(
                EntityType::Paymaster,
                reason,
                Some(paymaster),
            ) => Self::PaymasterValidationRejected(PaymasterValidationRejectedData {
                paymaster: *paymaster,
                reason: reason.to_string(),
            }),
            SimulationViolation::UnintendedRevertWithMessage(_, reason, _) => {
                Self::EntryPointValidationRejected(reason.clone())
            }
            SimulationViolation::UsedForbiddenOpcode(entity, _, op) => {
                Self::OpcodeViolation(entity.kind, op.clone().0)
            }
            SimulationViolation::UsedForbiddenPrecompile(entity, _, precompile) => {
                Self::PrecompileViolation(entity.kind, *precompile)
            }
            SimulationViolation::FactoryCalledCreate2Twice(_) => {
                Self::OpcodeViolation(EntityType::Factory, Opcode::CREATE2)
            }
            SimulationViolation::InvalidStorageAccess(entity, slot) => {
                Self::InvalidStorageAccess(entity.kind, slot.address, slot.slot)
            }
            SimulationViolation::NotStaked(entity, min_stake, min_unstake_delay) => {
                Self::StakeTooLow(StakeTooLowData::new(
                    *entity,
                    *min_stake,
                    *min_unstake_delay,
                ))
            }
            SimulationViolation::AggregatorValidationFailed => Self::SignatureCheckFailed,
            _ => Self::SimulationFailed(value),
        }
    }
}

impl TryFrom<Status> for ErrorInfo {
    type Error = anyhow::Error;

    fn try_from(value: Status) -> Result<Self, Self::Error> {
        let decoded_status =
            tonic_types::Status::decode(value.details()).context("should have decoded status")?;

        // This could actually contain more error details, but we only use the first right now
        let any = decoded_status
            .details
            .first()
            .context("should have details")?;

        if any.type_url == "type.alchemy.com/op_pool.ErrorInfo" {
            ErrorInfo::decode(&any.value[..])
                .context("should have decoded successfully into ErrorInfo")
        } else {
            bail!("Unknown type_url: {}", any.type_url);
        }
    }
}

impl From<ErrorInfo> for EthRpcError {
    fn from(value: ErrorInfo) -> Self {
        let ErrorInfo { reason, metadata } = value;

        if reason == ErrorReason::EntityThrottled.as_str_name() {
            let (entity, address) = metadata.iter().next().unwrap();
            let Some(address) = Address::from_str(address).ok() else {
                return anyhow!("should have valid address in ErrorInfo metadata").into();
            };
            let Some(entity) = EntityType::from_str(entity).ok() else {
                return anyhow!("should be a valid Entity type in ErrorInfo metadata").into();
            };
            return EthRpcError::ThrottledOrBanned(Entity::new(entity, address));
        } else if reason == ErrorReason::ReplacementUnderpriced.as_str_name() {
            let prio_fee = metadata
                .get(ErrorMetadataKey::CurrentMaxPriorityFeePerGas.as_str_name())
                .and_then(|fee| fee.parse::<U256>().ok())
                .unwrap_or_default();
            let fee = metadata
                .get(ErrorMetadataKey::CurrentMaxFeePerGas.as_str_name())
                .and_then(|fee| fee.parse::<U256>().ok())
                .unwrap_or_default();
            return EthRpcError::ReplacementUnderpriced(ReplacementUnderpricedData::new(
                prio_fee, fee,
            ));
        } else if reason == ErrorReason::OperationDiscardedOnInsert.as_str_name() {
            return anyhow!("operation rejected: mempool full try again with higher gas price")
                .into();
        }

        anyhow!("operation rejected").into()
    }
}

impl From<Status> for EthRpcError {
    fn from(status: Status) -> Self {
        let status_details: anyhow::Result<ErrorInfo> = status.try_into();
        let Ok(error_info) = status_details else {
            return EthRpcError::Internal(status_details.unwrap_err());
        };

        EthRpcError::from(error_info)
    }
}

#[cfg(test)]
mod tests {
    use ethers::{
        types::{Log, TransactionReceipt},
        utils::{hex::ToHex, keccak256},
    };

    use super::*;
    use crate::common::{
        protos::op_pool::ErrorReason,
        types::{MockEntryPointLike, MockProviderLike},
    };

    const UO_OP_TOPIC: &str = "user-op-event-topic";

    // NOTE: Will use base config and mockall once new grpc mocking is enabled

    // fn base_config() -> EthApi {
    //     let provider = MockProviderLike::new();
    //     let entrypoints = vec![MockEntryPointLike::new()];

    //     let precheck_settings = precheck::Settings {
    //         max_verification_gas: U256::from(100000),
    //         use_bundle_priority_fee: Some(true),
    //         bundle_priority_fee_overhead_percent: 5,
    //         priority_fee_mode: PriorityFeeMode::BaseFeePercent(5),
    //     };

    //     let eth_api = EthApi::new(provider, entrypoints, 0, precheck_settings);
    // }

    #[test]
    fn test_throttled_or_banned_decode() {
        let error_info = ErrorInfo {
            reason: ErrorReason::EntityThrottled.as_str_name().to_string(),
            metadata: HashMap::from([(
                EntityType::Paymaster.to_string(),
                Address::default().encode_hex(),
            )]),
        };

        let details = tonic_types::Status {
            code: 0,
            message: "".to_string(),
            details: vec![prost_types::Any {
                type_url: "type.alchemy.com/op_pool.ErrorInfo".to_string(),
                value: error_info.encode_to_vec(),
            }],
        };

        let status = Status::with_details(
            tonic::Code::Internal,
            "error_message".to_string(),
            details.encode_to_vec().into(),
        );

        let rpc_error: EthRpcError = status.into();

        assert!(
            matches!(
                rpc_error,
                EthRpcError::ThrottledOrBanned(ref data) if *data == Entity::paymaster(Address::default())
            ),
            "{:?}",
            rpc_error
        );
    }

    #[test]
    fn test_filter_receipt_logs_when_at_begining_of_list() {
        let reference_log = given_log(UO_OP_TOPIC, "moldy-hash");
        let receipt = given_receipt(vec![
            given_log("other-topic", "some-hash"),
            reference_log.clone(),
            given_log(UO_OP_TOPIC, "other-hash"),
            given_log(UO_OP_TOPIC, "another-hash"),
        ]);

        let result =
            EthApi::<MockProviderLike, MockEntryPointLike>::filter_receipt_logs_matching_user_op(
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
            EthApi::<MockProviderLike, MockEntryPointLike>::filter_receipt_logs_matching_user_op(
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
            EthApi::<MockProviderLike, MockEntryPointLike>::filter_receipt_logs_matching_user_op(
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
            EthApi::<MockProviderLike, MockEntryPointLike>::filter_receipt_logs_matching_user_op(
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
            EthApi::<MockProviderLike, MockEntryPointLike>::filter_receipt_logs_matching_user_op(
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
            EthApi::<MockProviderLike, MockEntryPointLike>::filter_receipt_logs_matching_user_op(
                &reference_log,
                &receipt,
            );

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
