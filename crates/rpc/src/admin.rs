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

use anyhow::Context;
use async_trait::async_trait;
use ethers::types::Address;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use rundler_types::pool::Pool;

use crate::{
    types::{RpcAdminClearState, RpcAdminSetTracking},
    utils::{self, InternalRpcResult},
};

/// Admin API
#[rpc(client, server, namespace = "admin")]
pub trait AdminApi {
    /// Clears the state of the mempool field if name is true
    #[method(name = "clearState")]
    async fn clear_state(&self, clear_params: RpcAdminClearState) -> RpcResult<String>;

    /// Sets the tracking state for the paymaster and reputation pool modules
    #[method(name = "setTracking")]
    async fn set_tracking(
        &self,
        entry_point: Address,
        tracking_info: RpcAdminSetTracking,
    ) -> RpcResult<String>;
}

pub(crate) struct AdminApi<P> {
    pool: P,
}

impl<P> AdminApi<P> {
    pub(crate) fn new(pool: P) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl<P> AdminApiServer for AdminApi<P>
where
    P: Pool,
{
    async fn clear_state(&self, clear_params: RpcAdminClearState) -> RpcResult<String> {
        utils::safe_call_rpc_handler(
            "admin_clearState",
            AdminApi::clear_state(self, clear_params),
        )
        .await
    }

    async fn set_tracking(
        &self,
        entry_point: Address,
        tracking_params: RpcAdminSetTracking,
    ) -> RpcResult<String> {
        utils::safe_call_rpc_handler(
            "admin_setTracking",
            AdminApi::set_tracking(self, entry_point, tracking_params),
        )
        .await
    }
}

impl<P> AdminApi<P>
where
    P: Pool,
{
    async fn clear_state(&self, clear_params: RpcAdminClearState) -> InternalRpcResult<String> {
        self.pool
            .debug_clear_state(
                clear_params.clear_mempool.unwrap_or(false),
                clear_params.clear_paymaster.unwrap_or(false),
                clear_params.clear_reputation.unwrap_or(false),
            )
            .await
            .context("should clear state")?;

        Ok("ok".to_string())
    }

    async fn set_tracking(
        &self,
        entry_point: Address,
        tracking_params: RpcAdminSetTracking,
    ) -> InternalRpcResult<String> {
        self.pool
            .admin_set_tracking(
                entry_point,
                tracking_params.paymaster_tracking,
                tracking_params.reputation_tracking,
            )
            .await
            .context("should set tracking")?;

        Ok("ok".to_string())
    }
}
