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

use std::sync::Arc;

use jsonrpsee::{Extensions, core::RpcResult};
use rundler_types::{EntryPointVersion, builder::Builder, chain::ChainSpec, pool::Pool};

/// A resolved chain context providing access to pool, builder, chain spec,
/// and enabled entry points for a given request.
pub struct ResolvedChain<'a> {
    /// Pool server for this chain
    pub pool: &'a dyn Pool,
    /// Builder server for this chain
    pub builder: &'a dyn Builder,
    /// Chain specification
    pub chain_spec: &'a ChainSpec,
    /// Enabled entry point versions
    pub entry_points: &'a [EntryPointVersion],
}

/// Trait for resolving chain context from request extensions.
///
/// In node mode, this always returns the single local chain.
/// In gateway mode, this extracts the chain ID from the request
/// extensions (set by the routing middleware) and returns the
/// corresponding chain backend.
pub trait ChainResolver: Send + Sync + 'static {
    /// Resolve the chain context for a given request.
    fn resolve(&self, ext: &Extensions) -> RpcResult<ResolvedChain<'_>>;
}

impl<R: ChainResolver> ChainResolver for Arc<R> {
    fn resolve(&self, ext: &Extensions) -> RpcResult<ResolvedChain<'_>> {
        (**self).resolve(ext)
    }
}
