mod api;
mod error;
mod server;

pub use api::EthApi;
use ethers::types::{Address, H256, U64};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use rundler_sim::{GasEstimate, UserOperationOptionalGas};

use super::{RichUserOperation, RpcUserOperation, UserOperationReceipt};

/// Eth API
#[rpc(client, server, namespace = "eth")]
#[cfg_attr(test, automock)]
pub trait EthApi {
    #[method(name = "sendUserOperation")]
    async fn send_user_operation(
        &self,
        op: RpcUserOperation,
        entry_point: Address,
    ) -> RpcResult<H256>;

    #[method(name = "estimateUserOperationGas")]
    async fn estimate_user_operation_gas(
        &self,
        op: UserOperationOptionalGas,
        entry_point: Address,
    ) -> RpcResult<GasEstimate>;

    #[method(name = "getUserOperationByHash")]
    async fn get_user_operation_by_hash(&self, hash: H256) -> RpcResult<Option<RichUserOperation>>;

    #[method(name = "getUserOperationReceipt")]
    async fn get_user_operation_receipt(
        &self,
        hash: H256,
    ) -> RpcResult<Option<UserOperationReceipt>>;

    #[method(name = "supportedEntryPoints")]
    async fn supported_entry_points(&self) -> RpcResult<Vec<String>>;

    #[method(name = "chainId")]
    async fn chain_id(&self) -> RpcResult<U64>;
}
