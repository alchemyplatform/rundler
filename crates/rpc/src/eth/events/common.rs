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

use std::{collections::VecDeque, marker::PhantomData};

use alloy_consensus::Transaction;
use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_sol_types::SolEvent;
use anyhow::Context;
use itertools::Itertools;
use rundler_provider::{
    EvmProvider, Filter, GethDebugBuiltInTracerType, GethDebugTracerType, GethDebugTracingOptions,
    GethTrace, Log, TransactionReceipt,
};
use rundler_types::{chain::ChainSpec, UserOperation, UserOperationVariant};
use rundler_utils::log::LogOnError;
use tracing::instrument;

use super::UserOperationEventProvider;
use crate::types::{RpcUserOperationByHash, RpcUserOperationReceipt, UOStatusEnum};

#[derive(Debug)]
pub(crate) struct UserOperationEventProviderImpl<P, F> {
    chain_spec: ChainSpec,
    provider: P,
    event_block_distance: Option<u64>,
    event_block_distance_fallback: Option<u64>,
    _f_type: PhantomData<F>,
}

pub(crate) trait EntryPointEvents: Send + Sync {
    type UO: UserOperation + Into<UserOperationVariant>;
    type UserOperationEvent: SolEvent;
    type UserOperationRevertReason: SolEvent;

    fn construct_receipt(
        event: Self::UserOperationEvent,
        entry_point: Address,
        logs: Vec<Log>,
        tx_receipt: TransactionReceipt,
    ) -> RpcUserOperationReceipt;

    fn get_user_operations_from_tx_data(tx_data: Bytes, chain_spec: &ChainSpec) -> Vec<Self::UO>;

    fn address(chain_spec: &ChainSpec) -> Address;

    fn before_execution_selector() -> B256;
}

#[async_trait::async_trait]
impl<P, E> UserOperationEventProvider for UserOperationEventProviderImpl<P, E>
where
    P: EvmProvider,
    E: EntryPointEvents,
{
    #[instrument(skip_all)]
    async fn get_mined_by_hash(
        &self,
        hash: B256,
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

        self.get_user_operation(hash, transaction_hash, &event)
            .await
            .log_on_error("should have successfully found user operation")
    }

    #[instrument(skip_all)]
    async fn get_mined_from_tx_receipt(
        &self,
        uo_hash: B256,
        tx_receipt: TransactionReceipt,
    ) -> anyhow::Result<Option<RpcUserOperationByHash>> {
        let Some(event) = self.get_event_from_tx_receipt(uo_hash, &tx_receipt) else {
            return Ok(None);
        };

        self.get_user_operation(uo_hash, tx_receipt.transaction_hash, event)
            .await
            .log_on_error("should have successfully found user operation")
    }

    #[instrument(skip_all)]
    async fn get_receipt(&self, hash: B256) -> anyhow::Result<Option<RpcUserOperationReceipt>> {
        let event = self
            .get_event_by_hash(hash)
            .await
            .log_on_error("should have successfully queried for user op events by hash")?;
        let Some(event) = event else { return Ok(None) };

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

        self.construct_receipt(event, tx_receipt).map(Some)
    }

    #[instrument(skip_all)]
    async fn get_receipt_from_tx_receipt(
        &self,
        uo_hash: B256,
        tx_receipt: TransactionReceipt,
    ) -> anyhow::Result<Option<RpcUserOperationReceipt>> {
        let Some(event) = self.get_event_from_tx_receipt(uo_hash, &tx_receipt) else {
            return Ok(None);
        };

        if event.address() != E::address(&self.chain_spec) {
            return Ok(None);
        }

        self.construct_receipt(event.clone(), tx_receipt).map(Some)
    }

    #[instrument(skip_all)]
    async fn get_receipt_from_tx_hash(
        &self,
        uo_hash: B256,
        bundle_transaction: B256,
    ) -> anyhow::Result<Option<RpcUserOperationReceipt>> {
        let txn_receipt = self
            .provider
            .get_transaction_receipt(bundle_transaction)
            .await
            .context("should have fetched tx receipt")?
            .context("Failed to fetch tx receipt")?;

        let receipt = self
            .get_receipt_from_tx_receipt(uo_hash, txn_receipt)
            .await?;
        if let Some(inner_receipt) = receipt {
            return Ok(Some(RpcUserOperationReceipt {
                status: UOStatusEnum::Preconfirmed,
                ..inner_receipt
            }));
        }
        return Ok(None);
    }
}

impl<P, E> UserOperationEventProviderImpl<P, E>
where
    P: EvmProvider,
    E: EntryPointEvents,
{
    pub(crate) fn new(
        chain_spec: ChainSpec,
        provider: P,
        event_block_distance: Option<u64>,
        event_block_distance_fallback: Option<u64>,
    ) -> Self {
        Self {
            chain_spec,
            provider,
            event_block_distance,
            event_block_distance_fallback,
            _f_type: PhantomData,
        }
    }

    #[instrument(skip_all)]
    async fn get_event_by_hash(&self, hash: B256) -> anyhow::Result<Option<Log>> {
        let to_block = self.provider.get_block_number().await?;

        let from_block = match self.event_block_distance {
            Some(distance) => to_block.saturating_sub(distance),
            None => 0,
        };

        match self.get_event_by_hash_at(hash, from_block, to_block).await {
            Ok(logs) => Ok(logs),
            Err(e) => {
                if let Some(fallback_distance) = self.event_block_distance_fallback {
                    tracing::warn!("Error querying for event at from block {from_block:?} to block {to_block:?} falling back to a distance of {fallback_distance:?}. Error {e:?}");
                    self.get_event_by_hash_at(
                        hash,
                        to_block.saturating_sub(fallback_distance),
                        to_block,
                    )
                    .await
                } else {
                    Err(e)
                }
            }
        }
    }

    #[instrument(skip_all)]
    async fn get_event_by_hash_at(
        &self,
        hash: B256,
        from_block: u64,
        to_block: u64,
    ) -> anyhow::Result<Option<Log>> {
        let filter = Filter::new()
            .address(E::address(&self.chain_spec))
            .event_signature(E::UserOperationEvent::SIGNATURE_HASH)
            .from_block(from_block)
            .to_block(to_block)
            .topic1(hash);

        Ok(self.provider.get_logs(&filter).await?.into_iter().next())
    }

    #[instrument(skip(self))]
    async fn get_user_operation(
        &self,
        uo_hash: B256,
        tx_hash: B256,
        event: &Log,
    ) -> anyhow::Result<Option<RpcUserOperationByHash>> {
        let tx = self
            .provider
            .get_transaction_by_hash(tx_hash)
            .await
            .context("should have fetched tx from provider")?
            .context("should have found tx")?;

        // We should return null if the tx isn't included in the block yet
        if tx.block_hash.is_none() && tx.block_number.is_none() {
            return Ok(None);
        }
        let to = tx
            .inner
            .to()
            .expect("tx.to should be present on transaction containing user operation event");

        let input = tx.input();

        let ep_address = E::address(&self.chain_spec);
        let user_operation =
            if ep_address == to || self.chain_spec.known_proxy_addresses().contains(&to) {
                E::get_user_operations_from_tx_data(input.clone(), &self.chain_spec)
                    .into_iter()
                    .find(|op| op.hash() == uo_hash)
                    .context("matching user operation should be found in tx data")?
            } else {
                tracing::debug!("Unknown entrypoint {to:?}, falling back to trace");
                self.trace_find_user_operation(tx_hash, uo_hash)
                    .await
                    .context("error running trace")?
                    .context("should have found user operation in trace")?
            };

        Ok(Some(RpcUserOperationByHash {
            user_operation: user_operation.into().into(),
            entry_point: event.address().into(),
            block_number: Some(tx.block_number.map(|n| U256::from(n)).unwrap_or_default()),
            block_hash: Some(tx.block_hash.unwrap_or_default()),
            transaction_hash: Some(tx_hash),
        }))
    }

    fn get_event_from_tx_receipt<'a>(
        &self,
        uo_hash: B256,
        tx_receipt: &'a TransactionReceipt,
    ) -> Option<&'a Log> {
        tx_receipt.inner.inner.logs().iter().find(|l| {
            l.topics().len() >= 2
                && l.topics()[0] == E::UserOperationEvent::SIGNATURE_HASH
                && l.topics()[1] == uo_hash
        })
    }

    fn construct_receipt(
        &self,
        event: Log,
        tx_receipt: TransactionReceipt,
    ) -> anyhow::Result<RpcUserOperationReceipt> {
        // filter receipt logs
        let filtered_logs = super::filter_receipt_logs_matching_user_op(
            E::address(&self.chain_spec),
            E::before_execution_selector(),
            &event,
            &tx_receipt,
        )
        .context("should have found receipt logs matching user op")?;

        // decode uo event
        let uo_event = self
            .decode_user_operation_event(event)
            .context("should have decoded user operation event")?;

        Ok(E::construct_receipt(
            uo_event,
            E::address(&self.chain_spec),
            filtered_logs,
            tx_receipt,
        ))
    }

    fn decode_user_operation_event(&self, log: Log) -> anyhow::Result<E::UserOperationEvent> {
        log.log_decode::<E::UserOperationEvent>()
            .map(|l| l.inner.data)
            .context("log should be a user operation event")
    }

    /// This method takes a transaction hash and a user operation hash and returns the full user operation if it exists.
    /// This is meant to be used when a user operation event is found in the logs of a transaction, but the top level call
    /// wasn't to an entrypoint, so we need to trace the transaction to find the user operation by inspecting each call frame
    /// and returning the user operation that matches the hash.
    #[instrument(skip_all)]
    async fn trace_find_user_operation(
        &self,
        tx_hash: B256,
        user_op_hash: B256,
    ) -> anyhow::Result<Option<E::UO>> {
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

        if let GethTrace::CallTracer(call_frame) = trace {
            frame_queue.push_back(call_frame);
        } else {
            tracing::warn!(
                "should have found user operation {user_op_hash:?} in trace for tx {tx_hash:?}"
            );
            return Err(anyhow::anyhow!(
                "should have found user operation {user_op_hash:?} in trace"
            ));
        }

        while let Some(call_frame) = frame_queue.pop_front() {
            // check if the call is to an entrypoint, if not enqueue the child calls if any
            if call_frame
                .to
                .is_some_and(|to| to == E::address(&self.chain_spec))
            {
                // check if the user operation is in the call frame
                if let Some(uo) =
                    E::get_user_operations_from_tx_data(call_frame.input, &self.chain_spec)
                        .into_iter()
                        .find(|op| op.hash() == user_op_hash)
                {
                    return Ok(Some(uo));
                }
            } else {
                frame_queue.extend(call_frame.calls)
            }
        }

        Ok(None)
    }
}
