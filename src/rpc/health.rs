use anyhow::Context;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use tonic::{async_trait, transport::Channel};
use tonic_health::pb::{health_client::HealthClient, HealthCheckRequest};

#[rpc(server, namespace = "system")]
pub trait SystemApi {
    #[method(name = "health")]
    async fn get_health(&self) -> RpcResult<String>;
}

pub struct SystemApi {
    op_pool_health_client: HealthClient<Channel>,
    builder_health_client: HealthClient<Channel>,
}

impl SystemApi {
    pub fn new(
        op_pool_health_client: HealthClient<Channel>,
        builder_health_client: HealthClient<Channel>,
    ) -> Self {
        Self {
            op_pool_health_client,
            builder_health_client,
        }
    }
}

#[async_trait]
impl SystemApiServer for SystemApi {
    async fn get_health(&self) -> RpcResult<String> {
        self.op_pool_health_client
            .clone()
            .check(HealthCheckRequest::default())
            .await
            .context("Op pool server should be live")?;

        self.builder_health_client
            .clone()
            .check(HealthCheckRequest::default())
            .await
            .context("Builder server should be live")?;

        Ok("ok".to_string())
    }
}
