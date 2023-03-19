use super::RpcReputation;
use crate::common::protos;
use crate::common::protos::op_pool::{
    op_pool_client, DebugClearStateRequest, DebugDumpMempoolRequest, DebugDumpReputationRequest,
    DebugSetReputationRequest,
};
use crate::common::types::{CheapClone, UserOperation};
use ethers::types::{Address, H256};
use jsonrpsee::core::{Error as RpcError, RpcResult};
use jsonrpsee::proc_macros::rpc;
use tonic::async_trait;
use tonic::transport::Channel;

/// Debug API
#[rpc(server, namespace = "debug")]
pub trait DebugApi {
    #[method(name = "bundler_clearState")]
    async fn bundler_clear_state(&self) -> RpcResult<String>;

    #[method(name = "bundler_dumpMempool")]
    async fn bundler_dump_mempool(&self, entry_point: Address) -> RpcResult<Vec<UserOperation>>;

    #[method(name = "bundler_sendBundleNow")]
    async fn bundler_send_bundle_now(&self, entry_point: Address) -> RpcResult<H256>;

    #[method(name = "bundler_setBundlingMode")]
    async fn bundler_set_bundling_mode(&self, mode: String) -> RpcResult<String>;

    #[method(name = "bundler_setReputation")]
    async fn bundler_set_reputation(
        &self,
        reputations: Vec<RpcReputation>,
        entry_point: Address,
    ) -> RpcResult<String>;

    #[method(name = "bundler_dumpReputation")]
    async fn bundler_dump_reputation(&self, entry_point: Address) -> RpcResult<Vec<RpcReputation>>;
}

pub struct DebugApi {
    op_pool_client: op_pool_client::OpPoolClient<Channel>,
}

impl DebugApi {
    pub fn new(op_pool_client: op_pool_client::OpPoolClient<Channel>) -> Self {
        Self { op_pool_client }
    }
}

#[async_trait]
impl DebugApiServer for DebugApi {
    async fn bundler_clear_state(&self) -> RpcResult<String> {
        let _ = self
            .op_pool_client
            // https://docs.rs/tonic/latest/tonic/client/index.html#concurrent-usage
            // solution to using in concurrent context is to clone
            .cheap_clone()
            .debug_clear_state(DebugClearStateRequest {})
            .await
            .map_err(|e| RpcError::Custom(e.to_string()))?;

        Ok("ok".to_string())
    }

    async fn bundler_dump_mempool(&self, entry_point: Address) -> RpcResult<Vec<UserOperation>> {
        let response = self
            .op_pool_client
            .cheap_clone()
            .debug_dump_mempool(DebugDumpMempoolRequest {
                entry_point: entry_point.to_fixed_bytes().into(),
            })
            .await
            .map_err(|e| RpcError::Custom(e.to_string()))?;

        Ok(response
            .into_inner()
            .ops
            .into_iter()
            .filter_map(|mop| mop.uo)
            .map(|uo| uo.try_into())
            .collect::<Result<Vec<_>, protos::ConversionError>>()
            .map_err(|e| RpcError::Custom(e.to_string()))?)
    }

    // TODO: we need bundler module defined before we can impl these two
    async fn bundler_send_bundle_now(&self, _entry_point: Address) -> RpcResult<H256> {
        Err(RpcError::HttpNotImplemented)
    }

    async fn bundler_set_bundling_mode(&self, _mode: String) -> RpcResult<String> {
        Err(RpcError::HttpNotImplemented)
    }

    async fn bundler_set_reputation(
        &self,
        reputations: Vec<RpcReputation>,
        entry_point: Address,
    ) -> RpcResult<String> {
        let _ = self
            .op_pool_client
            .cheap_clone()
            .debug_set_reputation(DebugSetReputationRequest {
                entry_point: entry_point.to_fixed_bytes().into(),
                reputations: reputations.into_iter().map(Into::into).collect(),
            })
            .await;

        Ok("ok".to_string())
    }

    async fn bundler_dump_reputation(&self, entry_point: Address) -> RpcResult<Vec<RpcReputation>> {
        let result = self
            .op_pool_client
            .cheap_clone()
            .debug_dump_reputation(DebugDumpReputationRequest {
                entry_point: entry_point.to_fixed_bytes().into(),
            })
            .await
            .map_err(|e| RpcError::Custom(e.to_string()))?;

        Ok(result
            .into_inner()
            .reputations
            .into_iter()
            .map(|r| r.try_into())
            .collect::<Result<Vec<_>, anyhow::Error>>()
            .map_err(|e| RpcError::Custom(e.to_string()))?)
    }
}
