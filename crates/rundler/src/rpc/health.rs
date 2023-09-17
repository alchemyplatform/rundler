use jsonrpsee::{core::RpcResult, proc_macros::rpc, types::error::INTERNAL_ERROR_CODE};
use rundler_task::server::{HealthCheck, ServerStatus};
use tonic::async_trait;

use super::rpc_err;

#[rpc(server, namespace = "system")]
pub trait SystemApi {
    #[method(name = "health")]
    async fn get_health(&self) -> RpcResult<String>;
}

pub struct HealthChecker {
    servers: Vec<Box<dyn HealthCheck>>,
}

impl HealthChecker {
    pub fn new(servers: Vec<Box<dyn HealthCheck>>) -> Self {
        Self { servers }
    }
}

#[async_trait]
impl SystemApiServer for HealthChecker {
    async fn get_health(&self) -> RpcResult<String> {
        let mut errors = Vec::new();
        for server in &self.servers {
            match server.status().await {
                ServerStatus::Serving => {}
                ServerStatus::NotServing => errors.push(server.name()),
            }
        }
        if errors.is_empty() {
            Ok("ok".to_owned())
        } else {
            Err(rpc_err(
                INTERNAL_ERROR_CODE,
                format!("Some servers are not serving {}", errors.join(", ")),
            ))
        }
    }
}
