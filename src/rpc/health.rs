use anyhow::Context;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use tonic::{async_trait, transport::Channel};
use tonic_health::pb::{health_client::HealthClient, HealthCheckRequest};

use crate::{
    builder::{BuilderClient, LocalBuilderClient},
    op_pool::{LocalPoolClient, PoolClient},
};

#[rpc(server, namespace = "system")]
pub trait SystemApi {
    #[method(name = "health")]
    async fn get_health(&self) -> RpcResult<String>;
}

pub struct RemoteHealthCheck {
    op_pool_health_client: HealthClient<Channel>,
    builder_health_client: HealthClient<Channel>,
}

impl RemoteHealthCheck {
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
impl SystemApiServer for RemoteHealthCheck {
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

pub struct LocalHealthCheck {
    pool_client: LocalPoolClient,
    builder_client: LocalBuilderClient,
}

impl LocalHealthCheck {
    pub fn new(pool_client: LocalPoolClient, builder_client: LocalBuilderClient) -> Self {
        Self {
            pool_client,
            builder_client,
        }
    }
}

#[async_trait]
impl SystemApiServer for LocalHealthCheck {
    async fn get_health(&self) -> RpcResult<String> {
        self.pool_client
            .get_supported_entry_points()
            .await
            .context("Op pool server should be live")?;
        self.builder_client
            .get_supported_entry_points()
            .await
            .context("Builder server should be live")?;

        Ok("ok".to_string())
    }
}
