use ethers::types::{Address, H256};
use jsonrpsee::{core::RpcResult, proc_macros::rpc, types::error::INTERNAL_ERROR_CODE};
use rundler_pool::PoolServer;
use tonic::async_trait;

use super::{rpc_err, RpcReputation, RpcUserOperation};
use crate::builder::{BuilderServer, BundlingMode};

/// Debug API
#[rpc(client, server, namespace = "debug")]
pub trait DebugApi {
    #[method(name = "bundler_clearState")]
    async fn bundler_clear_state(&self) -> RpcResult<String>;

    #[method(name = "bundler_dumpMempool")]
    async fn bundler_dump_mempool(&self, entry_point: Address) -> RpcResult<Vec<RpcUserOperation>>;

    #[method(name = "bundler_sendBundleNow")]
    async fn bundler_send_bundle_now(&self) -> RpcResult<H256>;

    #[method(name = "bundler_setBundlingMode")]
    async fn bundler_set_bundling_mode(&self, mode: BundlingMode) -> RpcResult<String>;

    #[method(name = "bundler_setReputation")]
    async fn bundler_set_reputation(
        &self,
        reputations: Vec<RpcReputation>,
        entry_point: Address,
    ) -> RpcResult<String>;

    #[method(name = "bundler_dumpReputation")]
    async fn bundler_dump_reputation(&self, entry_point: Address) -> RpcResult<Vec<RpcReputation>>;
}

pub struct DebugApi<P, B> {
    pool: P,
    builder: B,
}

impl<P, B> DebugApi<P, B> {
    pub fn new(pool: P, builder: B) -> Self {
        Self { pool, builder }
    }
}

#[async_trait]
impl<P, B> DebugApiServer for DebugApi<P, B>
where
    P: PoolServer,
    B: BuilderServer,
{
    async fn bundler_clear_state(&self) -> RpcResult<String> {
        let _ = self
            .pool
            .debug_clear_state()
            .await
            .map_err(|e| rpc_err(INTERNAL_ERROR_CODE, e.to_string()))?;

        Ok("ok".to_string())
    }

    async fn bundler_dump_mempool(&self, entry_point: Address) -> RpcResult<Vec<RpcUserOperation>> {
        Ok(self
            .pool
            .debug_dump_mempool(entry_point)
            .await
            .map_err(|e| rpc_err(INTERNAL_ERROR_CODE, e.to_string()))?
            .into_iter()
            .map(|pop| pop.uo.into())
            .collect::<Vec<RpcUserOperation>>())
    }

    async fn bundler_send_bundle_now(&self) -> RpcResult<H256> {
        self.builder
            .debug_send_bundle_now()
            .await
            .map_err(|e| rpc_err(INTERNAL_ERROR_CODE, e.to_string()))
    }

    async fn bundler_set_bundling_mode(&self, mode: BundlingMode) -> RpcResult<String> {
        self.builder
            .debug_set_bundling_mode(mode)
            .await
            .map_err(|e| rpc_err(INTERNAL_ERROR_CODE, e.to_string()))?;

        Ok("ok".to_string())
    }

    async fn bundler_set_reputation(
        &self,
        reputations: Vec<RpcReputation>,
        entry_point: Address,
    ) -> RpcResult<String> {
        let _ = self
            .pool
            .debug_set_reputations(
                entry_point,
                reputations.into_iter().map(Into::into).collect(),
            )
            .await;

        Ok("ok".to_string())
    }

    async fn bundler_dump_reputation(&self, entry_point: Address) -> RpcResult<Vec<RpcReputation>> {
        let result = self
            .pool
            .debug_dump_reputation(entry_point)
            .await
            .map_err(|e| rpc_err(INTERNAL_ERROR_CODE, e.to_string()))?;

        result
            .into_iter()
            .map(|r| r.try_into())
            .collect::<Result<Vec<_>, anyhow::Error>>()
            .map_err(|e| rpc_err(INTERNAL_ERROR_CODE, e.to_string()))
    }
}
