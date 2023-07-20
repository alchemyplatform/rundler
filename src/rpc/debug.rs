use ethers::types::{Address, H256};
use jsonrpsee::{
    core::{Error as RpcError, RpcResult},
    proc_macros::rpc,
};
use tonic::{async_trait, transport::Channel};

use super::{RpcReputation, RpcUserOperation};
use crate::{
    common::{
        protos::builder::{
            builder_client, BundlingMode as ProtoBundlingMode, DebugSendBundleNowRequest,
            DebugSetBundlingModeRequest,
        },
        types::BundlingMode,
    },
    op_pool::PoolClient,
};

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

pub struct DebugApi<P> {
    op_pool_client: P,
    builder_client: builder_client::BuilderClient<Channel>,
}

impl<P> DebugApi<P> {
    pub fn new(op_pool_client: P, builder_client: builder_client::BuilderClient<Channel>) -> Self {
        Self {
            op_pool_client,
            builder_client,
        }
    }
}

#[async_trait]
impl<P> DebugApiServer for DebugApi<P>
where
    P: PoolClient,
{
    async fn bundler_clear_state(&self) -> RpcResult<String> {
        let _ = self
            .op_pool_client
            .debug_clear_state()
            .await
            .map_err(|e| RpcError::Custom(e.to_string()))?;

        Ok("ok".to_string())
    }

    async fn bundler_dump_mempool(&self, entry_point: Address) -> RpcResult<Vec<RpcUserOperation>> {
        Ok(self
            .op_pool_client
            .debug_dump_mempool(entry_point)
            .await
            .map_err(|e| RpcError::Custom(e.to_string()))?
            .into_iter()
            .map(|pop| pop.uo.into())
            .collect::<Vec<RpcUserOperation>>())
    }

    async fn bundler_send_bundle_now(&self) -> RpcResult<H256> {
        let response = self
            .builder_client
            .clone()
            .debug_send_bundle_now(DebugSendBundleNowRequest {})
            .await
            .map_err(|e| RpcError::Custom(e.to_string()))?;

        Ok(H256::from_slice(&response.into_inner().transaction_hash))
    }

    async fn bundler_set_bundling_mode(&self, mode: BundlingMode) -> RpcResult<String> {
        let mode: ProtoBundlingMode = mode.into();

        self.builder_client
            .clone()
            .debug_set_bundling_mode(DebugSetBundlingModeRequest { mode: mode.into() })
            .await
            .map_err(|e| RpcError::Custom(e.to_string()))?;

        Ok("ok".to_string())
    }

    async fn bundler_set_reputation(
        &self,
        reputations: Vec<RpcReputation>,
        entry_point: Address,
    ) -> RpcResult<String> {
        let _ = self
            .op_pool_client
            .debug_set_reputations(
                entry_point,
                reputations.into_iter().map(Into::into).collect(),
            )
            .await;

        Ok("ok".to_string())
    }

    async fn bundler_dump_reputation(&self, entry_point: Address) -> RpcResult<Vec<RpcReputation>> {
        let result = self
            .op_pool_client
            .debug_dump_reputation(entry_point)
            .await
            .map_err(|e| RpcError::Custom(e.to_string()))?;

        result
            .into_iter()
            .map(|r| r.try_into())
            .collect::<Result<Vec<_>, anyhow::Error>>()
            .map_err(|e| RpcError::Custom(e.to_string()))
    }
}
