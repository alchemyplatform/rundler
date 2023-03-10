use crate::common::types::UserOperation;
use ethers::types::{Address, H256, U256};
use jsonrpsee::core::{Error as RpcError, RpcResult};
use jsonrpsee::proc_macros::rpc;
use tonic::async_trait;

use super::{GasEstimate, RichUserOperation, UserOperationOptionalGas, UserOperationReceipt};

/// Eth API
#[rpc(server, namespace = "eth")]
pub trait EthApi {
    #[method(name = "sendUserOperation")]
    async fn send_user_operation(&self, op: UserOperation, entry_point: Address)
        -> RpcResult<H256>;

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
    async fn supported_entry_points(&self) -> RpcResult<Vec<Address>>;

    #[method(name = "chainId")]
    async fn chain_id(&self) -> RpcResult<U256>;
}

pub struct EthApi {
    entry_points: Vec<Address>,
    chain_id: U256,
}

impl EthApi {
    pub fn new(entry_points: Vec<Address>, chain_id: U256) -> Self {
        Self {
            entry_points,
            chain_id,
        }
    }
}

#[async_trait]
impl EthApiServer for EthApi {
    async fn send_user_operation(
        &self,
        _op: UserOperation,
        _entry_point: Address,
    ) -> RpcResult<H256> {
        Err(RpcError::HttpNotImplemented)
    }

    async fn estimate_user_operation_gas(
        &self,
        _op: UserOperationOptionalGas,
        _entry_point: Address,
    ) -> RpcResult<GasEstimate> {
        Err(RpcError::HttpNotImplemented)
    }

    async fn get_user_operation_by_hash(
        &self,
        _hash: H256,
    ) -> RpcResult<Option<RichUserOperation>> {
        Err(RpcError::HttpNotImplemented)
    }

    async fn get_user_operation_receipt(
        &self,
        _hash: H256,
    ) -> RpcResult<Option<UserOperationReceipt>> {
        Err(RpcError::HttpNotImplemented)
    }

    async fn supported_entry_points(&self) -> RpcResult<Vec<Address>> {
        Ok(self.entry_points.clone())
    }

    async fn chain_id(&self) -> RpcResult<U256> {
        Ok(self.chain_id)
    }
}
