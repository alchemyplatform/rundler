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

use std::{collections::HashMap, sync::Arc};

use alloy_primitives::{Address, Bytes, TxHash};
use async_trait::async_trait;
use rundler_provider::{
    EvmProvider, GethDebugTracingOptions, GethTrace, HandleOpsOut, ProviderResult, Transaction,
    decode_v0_6_handle_ops_revert, decode_v0_6_ops_from_calldata, decode_v0_7_handle_ops_revert,
    decode_v0_7_ops_from_calldata,
};
use rundler_types::{
    UserOperationVariant, UserOpsPerAggregator, authorization::Eip7702Auth, chain::ChainSpec,
    proxy::SubmissionProxy,
};

use crate::bundle_proposer::BundleProposerT;

/// Object-safe EVM provider trait for revert processing
///
/// This trait wraps the subset of `EvmProvider` methods needed for processing
/// transaction reverts, making it object-safe (unlike `EvmProvider` which has
/// a generic `request` method).
#[async_trait]
#[cfg_attr(test, mockall::automock)]
pub(crate) trait EvmProviderLike: Send + Sync {
    /// Get transaction by hash
    async fn get_transaction_by_hash(&self, tx: TxHash) -> ProviderResult<Option<Transaction>>;

    /// Debug trace a transaction
    async fn debug_trace_transaction(
        &self,
        tx_hash: TxHash,
        trace_options: GethDebugTracingOptions,
    ) -> ProviderResult<GethTrace>;
}

/// Wrapper to adapt any EvmProvider to EvmProviderLike
pub(crate) struct EvmProviderAdapter<E> {
    inner: E,
}

impl<E> EvmProviderAdapter<E> {
    pub(crate) fn new(inner: E) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl<E: EvmProvider> EvmProviderLike for EvmProviderAdapter<E> {
    async fn get_transaction_by_hash(&self, tx: TxHash) -> ProviderResult<Option<Transaction>> {
        self.inner.get_transaction_by_hash(tx).await
    }

    async fn debug_trace_transaction(
        &self,
        tx_hash: TxHash,
        trace_options: GethDebugTracingOptions,
    ) -> ProviderResult<GethTrace> {
        self.inner
            .debug_trace_transaction(tx_hash, trace_options)
            .await
    }
}

/// Type-erased revert handler for processing onchain reverts
pub(crate) trait RevertHandler: Send + Sync {
    /// Decode user operations from handleOps calldata
    fn decode_ops_from_calldata(
        &self,
        chain_spec: &ChainSpec,
        address: Address,
        calldata: &Bytes,
        auth_list: &[Eip7702Auth],
    ) -> Vec<UserOpsPerAggregator<UserOperationVariant>>;

    /// Decode the revert data from a failed handleOps call
    fn decode_handle_ops_revert(
        &self,
        message: &str,
        revert_data: &Option<Bytes>,
    ) -> Option<HandleOpsOut>;
}

/// Revert handler for v0.6 entrypoints
pub(crate) struct RevertHandlerV0_6;

impl RevertHandler for RevertHandlerV0_6 {
    fn decode_ops_from_calldata(
        &self,
        chain_spec: &ChainSpec,
        address: Address,
        calldata: &Bytes,
        _auth_list: &[Eip7702Auth],
    ) -> Vec<UserOpsPerAggregator<UserOperationVariant>> {
        decode_v0_6_ops_from_calldata(chain_spec, address, calldata)
            .into_iter()
            .map(|ops| ops.into_uo_variants())
            .collect()
    }

    fn decode_handle_ops_revert(
        &self,
        message: &str,
        revert_data: &Option<Bytes>,
    ) -> Option<HandleOpsOut> {
        decode_v0_6_handle_ops_revert(message, revert_data)
    }
}

/// Revert handler for v0.7+ entrypoints (works for v0.7, v0.8, v0.9)
pub(crate) struct RevertHandlerV0_7;

impl RevertHandler for RevertHandlerV0_7 {
    fn decode_ops_from_calldata(
        &self,
        chain_spec: &ChainSpec,
        address: Address,
        calldata: &Bytes,
        auth_list: &[Eip7702Auth],
    ) -> Vec<UserOpsPerAggregator<UserOperationVariant>> {
        decode_v0_7_ops_from_calldata(chain_spec, address, calldata, auth_list)
            .into_iter()
            .map(|ops| ops.into_uo_variants())
            .collect()
    }

    fn decode_handle_ops_revert(
        &self,
        _message: &str,
        revert_data: &Option<Bytes>,
    ) -> Option<HandleOpsOut> {
        decode_v0_7_handle_ops_revert(revert_data)
    }
}

/// Registry key: (entrypoint address, filter_id)
/// This allows multiple configurations per entrypoint address (virtual entrypoints)
pub(crate) type RegistryKey = (Address, Option<String>);

/// Single registry holding all entrypoint-specific resources, keyed by (address, filter_id)
pub(crate) struct EntrypointRegistry {
    entries: HashMap<RegistryKey, EntrypointEntry>,
}

/// All resources for a single entrypoint configuration
pub(crate) struct EntrypointEntry {
    /// Bundle proposer for this entrypoint
    pub proposer: Box<dyn BundleProposerT>,
    /// Revert handler for this entrypoint version
    pub revert_handler: Box<dyn RevertHandler>,
    /// Optional submission proxy for this configuration
    pub submission_proxy: Option<Arc<dyn SubmissionProxy>>,
}

impl EntrypointEntry {
    /// Create a new entrypoint entry
    pub(crate) fn new(
        proposer: Box<dyn BundleProposerT>,
        revert_handler: Box<dyn RevertHandler>,
        submission_proxy: Option<Arc<dyn SubmissionProxy>>,
    ) -> Self {
        Self {
            proposer,
            revert_handler,
            submission_proxy,
        }
    }
}

impl EntrypointRegistry {
    /// Create a new empty registry
    pub(crate) fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Insert an entry for an entrypoint configuration
    pub(crate) fn insert(&mut self, key: RegistryKey, entry: EntrypointEntry) {
        self.entries.insert(key, entry);
    }

    /// Get the entry for an entrypoint by (address, filter_id)
    pub(crate) fn get(&self, key: &RegistryKey) -> Option<&EntrypointEntry> {
        self.entries.get(key)
    }
}
