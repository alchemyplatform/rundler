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

use async_trait::async_trait;
use ethers::types::Address;
use jsonrpsee::{core::RpcResult, proc_macros::rpc, types::error::INTERNAL_ERROR_CODE};
use rundler_pool::PoolServer;

use crate::error::rpc_err;

/// Admin API
#[rpc(client, server, namespace = "admin")]
pub trait AdminApi {
    /// Clears the state of the mempool field if name is true
    #[method(name = "clearState")]
    async fn admin_clear_state(
        &self,
        mempool: bool,
        paymaster: bool,
        reputation: bool,
    ) -> RpcResult<String>;

    /// Clears paymaster tracker state.
    #[method(name = "setTracking")]
    async fn admin_set_tracking(
        &self,
        entrypoint: Address,
        paymaster: bool,
        reputation: bool,
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
    P: PoolServer,
{
    async fn admin_clear_state(
        &self,
        mempool: bool,
        paymaster: bool,
        reputation: bool,
    ) -> RpcResult<String> {
        let _ = self
            .pool
            .debug_clear_state(mempool, paymaster, reputation)
            .await
            .map_err(|e| rpc_err(INTERNAL_ERROR_CODE, e.to_string()))?;

        Ok("ok".to_string())
    }

    async fn admin_set_tracking(
        &self,
        entrypoint: Address,
        paymaster: bool,
        reputation: bool,
    ) -> RpcResult<String> {
        let _ = self
            .pool
            .admin_set_tracking(entrypoint, paymaster, reputation)
            .await
            .map_err(|e| rpc_err(INTERNAL_ERROR_CODE, e.to_string()))?;

        Ok("ok".to_string())
    }
}
