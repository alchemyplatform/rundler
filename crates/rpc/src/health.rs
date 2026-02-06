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

use async_trait::async_trait;
use jsonrpsee::{core::RpcResult, proc_macros::rpc, types::error::INTERNAL_ERROR_CODE};
use rundler_task::server::ServerStatus;

use crate::{error::rpc_err, gateway::ChainRouter};

#[rpc(server, namespace = "system")]
pub trait SystemApi {
    #[method(name = "health")]
    async fn get_health(&self) -> RpcResult<String>;
}

pub(crate) struct HealthChecker {
    router: Arc<ChainRouter>,
}

impl HealthChecker {
    pub(crate) fn new(router: Arc<ChainRouter>) -> Self {
        Self { router }
    }
}

#[async_trait]
impl SystemApiServer for HealthChecker {
    async fn get_health(&self) -> RpcResult<String> {
        let mut errors = Vec::new();
        for backend in self.router.chains() {
            let chain_name = backend.chain_name();

            let pool_status = backend.pool_health.status().await;
            if !matches!(pool_status, ServerStatus::Serving) {
                errors.push(format!("{}(pool)", chain_name));
            }

            let builder_status = backend.builder_health.status().await;
            if !matches!(builder_status, ServerStatus::Serving) {
                errors.push(format!("{}(builder)", chain_name));
            }
        }
        if errors.is_empty() {
            Ok("ok".to_owned())
        } else {
            Err(rpc_err(
                INTERNAL_ERROR_CODE,
                format!("Some servers are not serving: {}", errors.join(", ")),
            ))
        }
    }
}
