use ethers::types::{Address, H256};
use jsonrpsee::core::{Error as RpcError, RpcResult};
use jsonrpsee::proc_macros::rpc;
use tonic::async_trait;

use super::RpcReputation;
use crate::common::types::UserOperation;

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

pub struct DebugApi;

#[async_trait]
impl DebugApiServer for DebugApi {
    async fn bundler_clear_state(&self) -> RpcResult<String> {
        Err(RpcError::HttpNotImplemented)
    }

    async fn bundler_dump_mempool(&self, _entry_point: Address) -> RpcResult<Vec<UserOperation>> {
        Err(RpcError::HttpNotImplemented)
    }

    async fn bundler_send_bundle_now(&self, _entry_point: Address) -> RpcResult<H256> {
        Err(RpcError::HttpNotImplemented)
    }

    async fn bundler_set_bundling_mode(&self, _mode: String) -> RpcResult<String> {
        Err(RpcError::HttpNotImplemented)
    }

    async fn bundler_set_reputation(
        &self,
        _reputations: Vec<RpcReputation>,
        _entry_point: Address,
    ) -> RpcResult<String> {
        Err(RpcError::HttpNotImplemented)
    }

    async fn bundler_dump_reputation(
        &self,
        _entry_point: Address,
    ) -> RpcResult<Vec<RpcReputation>> {
        Err(RpcError::HttpNotImplemented)
    }
}
