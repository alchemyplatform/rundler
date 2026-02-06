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

use jsonrpsee::{Extensions, core::RpcResult, types::ErrorObjectOwned};

use super::{
    chain::ChainBackend,
    error::{CHAIN_NOT_FOUND_CODE, GatewayError},
    middleware::ChainId,
};
use crate::chain_resolver::{ChainResolver, ResolvedChain};

/// Router for directing requests to the appropriate chain backend.
///
/// Implements [`ChainResolver`] directly:
/// - If a [`ChainId`] is present in the request extensions (gateway mode),
///   looks up that chain.
/// - Otherwise, if there is exactly one chain (node mode), returns it.
/// - Otherwise, returns an error.
pub struct ChainRouter {
    chains: HashMap<u64, Arc<ChainBackend>>,
}

impl ChainRouter {
    /// Creates a new chain router.
    pub fn new() -> Self {
        Self {
            chains: HashMap::new(),
        }
    }

    /// Adds a chain backend to the router.
    pub fn add_chain(&mut self, backend: Arc<ChainBackend>) {
        let chain_id = backend.chain_id();
        self.chains.insert(chain_id, backend);
    }

    /// Gets a chain backend by chain ID.
    pub fn get_chain(&self, chain_id: u64) -> Result<&Arc<ChainBackend>, GatewayError> {
        self.chains
            .get(&chain_id)
            .ok_or(GatewayError::ChainNotFound(chain_id))
    }

    /// Returns an iterator over all chain IDs.
    pub fn chain_ids(&self) -> impl Iterator<Item = u64> + '_ {
        self.chains.keys().copied()
    }

    /// Returns an iterator over all chain backends.
    pub fn chains(&self) -> impl Iterator<Item = &Arc<ChainBackend>> {
        self.chains.values()
    }

    /// Returns true if the router has no chains.
    pub fn is_empty(&self) -> bool {
        self.chains.is_empty()
    }
}

impl Default for ChainRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl ChainResolver for ChainRouter {
    fn resolve(&self, ext: &Extensions) -> RpcResult<ResolvedChain<'_>> {
        // Gateway mode: chain ID in extensions
        if let Some(chain_id) = ext.get::<ChainId>() {
            let backend = self.get_chain(chain_id.0).map_err(|e| {
                let err: ErrorObjectOwned = e.into();
                err
            })?;
            return Ok(ResolvedChain {
                pool: &*backend.pool,
                builder: &*backend.builder,
                chain_spec: &backend.chain_spec,
                entry_points: &backend.entry_points,
            });
        }

        // Node mode: exactly one chain
        if self.chains.len() == 1 {
            let backend = self.chains.values().next().unwrap();
            return Ok(ResolvedChain {
                pool: &*backend.pool,
                builder: &*backend.builder,
                chain_spec: &backend.chain_spec,
                entry_points: &backend.entry_points,
            });
        }

        // Multi-chain but no chain ID
        Err(ErrorObjectOwned::owned(
            CHAIN_NOT_FOUND_CODE,
            "No chain ID in request. Use /v1/{chain_id}/ path format.",
            None::<()>,
        ))
    }
}
