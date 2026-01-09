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

use std::panic::AssertUnwindSafe;

use futures_util::{Future, FutureExt};
use jsonrpsee::{
    core::RpcResult,
    types::{ErrorObjectOwned, error::INTERNAL_ERROR_CODE},
};
use metrics::Counter;
use metrics_derive::Metrics;
use rundler_types::{EntryPointVersion, chain::ChainSpec};

use crate::{error::rpc_err, eth::EthRpcError};

#[derive(Metrics)]
#[metrics(scope = "rpc")]
struct RPCMetric {
    #[metric(describe = "the count of rpc panic.")]
    panic_count: Counter,
}

pub(crate) async fn safe_call_rpc_handler<F, R, E>(rpc_name: &'static str, f: F) -> RpcResult<R>
where
    F: Future<Output = Result<R, E>> + Send,
    E: Into<ErrorObjectOwned>,
{
    let f = AssertUnwindSafe(f);
    match f.catch_unwind().await {
        Ok(r) => r.map_err(Into::into),
        Err(_) => {
            let rpc_metric = RPCMetric::new_with_labels(&[("rpc_name", rpc_name)]);
            rpc_metric.panic_count.increment(1);
            tracing::error!("PANIC in RPC handler: {}", rpc_name);
            Err(EthRpcError::Internal(anyhow::anyhow!("internal error: panic, see logs")).into())
        }
    }
}

/// Internal RPC result type.
pub(crate) type InternalRpcResult<T> = std::result::Result<T, InternalRpcError>;

/// Internal RPC error.
///
/// Allowing easy use of anyhow in RPC handlers for internal errors.
pub(crate) struct InternalRpcError(anyhow::Error);

impl From<anyhow::Error> for InternalRpcError {
    fn from(e: anyhow::Error) -> Self {
        Self(e)
    }
}

impl From<InternalRpcError> for ErrorObjectOwned {
    fn from(e: InternalRpcError) -> Self {
        rpc_err(INTERNAL_ERROR_CODE, e.0.to_string())
    }
}

pub(crate) trait FromRpcType<T> {
    fn from_rpc_type(value: T, chain_spec: &ChainSpec, ep_version: EntryPointVersion) -> Self;
}

pub(crate) trait IntoRundlerType<T> {
    fn into_rundler_type(self, chain_spec: &ChainSpec, ep_version: EntryPointVersion) -> T;
}

impl<T, U> IntoRundlerType<U> for T
where
    U: FromRpcType<T>,
{
    fn into_rundler_type(self, chain_spec: &ChainSpec, ep_version: EntryPointVersion) -> U {
        U::from_rpc_type(self, chain_spec, ep_version)
    }
}

pub(crate) trait TryFromRpcType<T>: Sized {
    fn try_from_rpc_type(
        value: T,
        chain_spec: &ChainSpec,
        ep_version: EntryPointVersion,
    ) -> Result<Self, EthRpcError>;
}

pub(crate) trait TryIntoRundlerType<T> {
    fn try_into_rundler_type(
        self,
        chain_spec: &ChainSpec,
        ep_version: EntryPointVersion,
    ) -> Result<T, EthRpcError>;
}

impl<T, U> TryIntoRundlerType<U> for T
where
    U: TryFromRpcType<T>,
{
    fn try_into_rundler_type(
        self,
        chain_spec: &ChainSpec,
        ep_version: EntryPointVersion,
    ) -> Result<U, EthRpcError> {
        U::try_from_rpc_type(self, chain_spec, ep_version)
    }
}
