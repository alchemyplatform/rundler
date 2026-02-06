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

use alloy_primitives::Address;
use anyhow::Context;
use async_trait::async_trait;
use jsonrpsee::{Extensions, core::RpcResult, proc_macros::rpc};

use crate::{
    chain_resolver::ChainResolver,
    types::{RpcAdminClearState, RpcAdminSetTracking},
    utils::{self, InternalRpcResult},
};

/// Admin API
#[rpc(client, server, namespace = "admin")]
pub trait AdminApi {
    /// Clears the state of the mempool field if name is true
    #[method(name = "clearState", with_extensions)]
    async fn clear_state(&self, clear_params: RpcAdminClearState) -> RpcResult<String>;

    /// Sets the tracking state for the paymaster and reputation pool modules
    #[method(name = "setTracking", with_extensions)]
    async fn set_tracking(
        &self,
        entry_point: Address,
        tracking_info: RpcAdminSetTracking,
    ) -> RpcResult<String>;
}

pub(crate) struct AdminApi<R> {
    resolver: R,
}

impl<R> AdminApi<R> {
    pub(crate) fn new(resolver: R) -> Self {
        Self { resolver }
    }
}

#[async_trait]
impl<R> AdminApiServer for AdminApi<R>
where
    R: ChainResolver,
{
    async fn clear_state(
        &self,
        ext: &Extensions,
        clear_params: RpcAdminClearState,
    ) -> RpcResult<String> {
        let chain = self.resolver.resolve(ext)?;
        utils::safe_call_rpc_handler(
            "admin_clearState",
            Self::clear_state_inner(chain.pool, clear_params),
        )
        .await
    }

    async fn set_tracking(
        &self,
        ext: &Extensions,
        entry_point: Address,
        tracking_params: RpcAdminSetTracking,
    ) -> RpcResult<String> {
        let chain = self.resolver.resolve(ext)?;
        utils::safe_call_rpc_handler(
            "admin_setTracking",
            Self::set_tracking_inner(chain.pool, entry_point, tracking_params),
        )
        .await
    }
}

impl<R> AdminApi<R> {
    async fn clear_state_inner(
        pool: &dyn rundler_types::pool::Pool,
        clear_params: RpcAdminClearState,
    ) -> InternalRpcResult<String> {
        pool.debug_clear_state(
            clear_params.clear_mempool.unwrap_or(false),
            clear_params.clear_paymaster.unwrap_or(false),
            clear_params.clear_reputation.unwrap_or(false),
        )
        .await
        .context("should clear state")?;

        Ok("ok".to_string())
    }

    async fn set_tracking_inner(
        pool: &dyn rundler_types::pool::Pool,
        entry_point: Address,
        tracking_params: RpcAdminSetTracking,
    ) -> InternalRpcResult<String> {
        pool.admin_set_tracking(
            entry_point,
            tracking_params.paymaster_tracking,
            tracking_params.reputation_tracking,
        )
        .await
        .context("should set tracking")?;

        Ok("ok".to_string())
    }
}
