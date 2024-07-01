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

use std::{collections::VecDeque, marker::PhantomData, sync::Arc};

use anyhow::Context;
use ethers::{
    prelude::EthEvent,
    types::{
        Address, Bytes, Filter, GethDebugBuiltInTracerType, GethDebugTracerType,
        GethDebugTracingOptions, GethTrace, GethTraceFrame, Log, TransactionReceipt, H256, U256,
    },
};
use rundler_provider::Provider;
use rundler_types::{chain::ChainSpec, UserOperation, UserOperationVariant};
use rundler_utils::{eth, log::LogOnError};

use super::UserOperationEventProvider;
use crate::types::{RpcUserOperationByHash, RpcUserOperationReceipt};

#[derive(Debug)]
pub(crate) struct UserOperationEventProviderImpl<P, F> {
    chain_spec: ChainSpec,
    provider: Arc<P>,
    event_block_distance: Option<u64>,
    _f_type: PhantomData<F>,
}

pub(crate) trait EntryPointFilters: Send + Sync + 'static {
    type UO: UserOperation + Into<UserOperationVariant>;
    type UserOperationEventFilter: EthEvent;
    type UserOperationRevertReasonFilter: EthEvent;

    fn construct_receipt(
        event: Self::UserOperationEventFilter,
        hash: H256,
        entry_point: Address,
        logs: Vec<Log>,
        tx_receipt: TransactionReceipt,
    ) -> RpcUserOperationReceipt;

    fn get_user_operations_from_tx_data(tx_data: Bytes, chain_spec: &ChainSpec) -> Vec<Self::UO>;

    fn address(chain_spec: &ChainSpec) -> Address;
}

#[async_trait::async_trait]
impl<P, F> UserOperationEventProvider for UserOperationEventProviderImpl<P, F>
where
    P: Provider,
    F: EntryPointFilters,
{
    async fn get_mined_by_hash(
        &self,
        hash: H256,
    ) -> anyhow::Result<Option<RpcUserOperationByHash>> {
        // Get event associated with hash (need to check all entry point addresses associated with this API)
        let event = self
            .get_event_by_hash(hash)
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
        let user_operation = if F::address(&self.chain_spec) == to {
            F::get_user_operations_from_tx_data(tx.input, &self.chain_spec)
                .into_iter()
                .find(|op| op.hash(to, self.chain_spec.id) == hash)
                .context("matching user operation should be found in tx data")?
        } else {
            self.trace_find_user_operation(transaction_hash, hash)
                .await
                .context("error running trace")?
                .context("should have found user operation in trace")?
        };

        Ok(Some(RpcUserOperationByHash {
            user_operation: user_operation.into().into(),
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

    async fn get_receipt(&self, hash: H256) -> anyhow::Result<Option<RpcUserOperationReceipt>> {
        let event = self
            .get_event_by_hash(hash)
            .await
            .log_on_error("should have successfully queried for user op events by hash")?;
        let Some(event) = event else { return Ok(None) };

        let entry_point = event.address;

        let tx_hash = event
            .transaction_hash
            .context("tx_hash should be present")?;

        // get transaction receipt
        let tx_receipt = self
            .provider
            .get_transaction_receipt(tx_hash)
            .await
            .context("should have fetched tx receipt")?
            .context("Failed to fetch tx receipt")?;

        // filter receipt logs
        let filtered_logs = super::filter_receipt_logs_matching_user_op(&event, &tx_receipt)
            .context("should have found receipt logs matching user op")?;

        // decode uo event
        let uo_event = self
            .decode_user_operation_event(event)
            .context("should have decoded user operation event")?;

        Ok(Some(F::construct_receipt(
            uo_event,
            hash,
            entry_point,
            filtered_logs,
            tx_receipt,
        )))
    }
}

impl<P, F> UserOperationEventProviderImpl<P, F>
where
    P: Provider,
    F: EntryPointFilters,
{
    pub(crate) fn new(
        chain_spec: ChainSpec,
        provider: Arc<P>,
        event_block_distance: Option<u64>,
    ) -> Self {
        Self {
            chain_spec,
            provider,
            event_block_distance,
            _f_type: PhantomData,
        }
    }

    async fn get_event_by_hash(&self, hash: H256) -> anyhow::Result<Option<Log>> {
        let to_block = self.provider.get_block_number().await?;

        let from_block = match self.event_block_distance {
            Some(distance) => to_block.saturating_sub(distance),
            None => 0,
        };

        let filter = Filter::new()
            .address(F::address(&self.chain_spec))
            .event(&F::UserOperationEventFilter::abi_signature())
            .from_block(from_block)
            .to_block(to_block)
            .topic1(hash);

        let logs = self.provider.get_logs(&filter).await?;
        Ok(logs.into_iter().next())
    }

    fn decode_user_operation_event(&self, log: Log) -> anyhow::Result<F::UserOperationEventFilter> {
        F::UserOperationEventFilter::decode_log(&eth::log_to_raw_log(log))
            .context("log should be a user operation event")
    }

    /// This method takes a transaction hash and a user operation hash and returns the full user operation if it exists.
    /// This is meant to be used when a user operation event is found in the logs of a transaction, but the top level call
    /// wasn't to an entrypoint, so we need to trace the transaction to find the user operation by inspecting each call frame
    /// and returning the user operation that matches the hash.
    async fn trace_find_user_operation(
        &self,
        tx_hash: H256,
        user_op_hash: H256,
    ) -> anyhow::Result<Option<F::UO>> {
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
                .filter(|to| **to == F::address(&self.chain_spec))
            {
                // check if the user operation is in the call frame
                if let Some(uo) =
                    F::get_user_operations_from_tx_data(call_frame.input, &self.chain_spec)
                        .into_iter()
                        .find(|op| op.hash(*to, self.chain_spec.id) == user_op_hash)
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
