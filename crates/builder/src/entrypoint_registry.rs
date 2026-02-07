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

use std::collections::HashMap;

use alloy_primitives::{Address, TxHash};
use async_trait::async_trait;
use rundler_provider::{
    EvmProvider, GethDebugTracingOptions, GethTrace, ProviderResult, Transaction,
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
}

impl EntrypointEntry {
    /// Create a new entrypoint entry
    pub(crate) fn new(proposer: Box<dyn BundleProposerT>) -> Self {
        Self { proposer }
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
