use ethers::types::{Address, H256, U64};
use jsonrpsee::core::RpcResult;
use rundler_pool::PoolServer;
use rundler_provider::{EntryPoint, Provider};
use rundler_sim::{GasEstimate, UserOperationOptionalGas};

use super::{api::EthApi, EthApiServer};
use crate::rpc::{RichUserOperation, RpcUserOperation, UserOperationReceipt};

#[tonic::async_trait]
impl<P, E, PS> EthApiServer for EthApi<P, E, PS>
where
    P: Provider,
    E: EntryPoint,
    PS: PoolServer,
{
    async fn send_user_operation(
        &self,
        op: RpcUserOperation,
        entry_point: Address,
    ) -> RpcResult<H256> {
        Ok(EthApi::send_user_operation(self, op, entry_point).await?)
    }

    async fn estimate_user_operation_gas(
        &self,
        op: UserOperationOptionalGas,
        entry_point: Address,
    ) -> RpcResult<GasEstimate> {
        Ok(EthApi::estimate_user_operation_gas(self, op, entry_point).await?)
    }

    async fn get_user_operation_by_hash(&self, hash: H256) -> RpcResult<Option<RichUserOperation>> {
        Ok(EthApi::get_user_operation_by_hash(self, hash).await?)
    }

    async fn get_user_operation_receipt(
        &self,
        hash: H256,
    ) -> RpcResult<Option<UserOperationReceipt>> {
        Ok(EthApi::get_user_operation_receipt(self, hash).await?)
    }

    async fn supported_entry_points(&self) -> RpcResult<Vec<String>> {
        Ok(EthApi::supported_entry_points(self).await?)
    }

    async fn chain_id(&self) -> RpcResult<U64> {
        Ok(EthApi::chain_id(self).await?)
    }
}
