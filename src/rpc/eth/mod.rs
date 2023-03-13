mod error;

use crate::common::{
    contracts::{
        entry_point::{EntryPointCalls, EntryPointEvents, UserOperationEventFilter},
        shared_types,
    },
    types::UserOperation,
};
use anyhow::anyhow;
use ethers::{
    abi::{AbiDecode, RawLog},
    prelude::{EthEvent, EthLogDecode},
    providers::{Http, Middleware, Provider},
    types::{Address, Bytes, Filter, Log, H256, U256},
};
use jsonrpsee::core::{Error as RpcError, RpcResult};
use jsonrpsee::proc_macros::rpc;
use std::sync::Arc;
use tonic::async_trait;

use self::error::EthRpcError;

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
    provider: Arc<Provider<Http>>,
    chain_id: U256,
}

impl EthApi {
    pub fn new(provider: Arc<Provider<Http>>, entry_points: Vec<Address>, chain_id: U256) -> Self {
        Self {
            entry_points,
            provider,
            chain_id,
        }
    }

    async fn get_user_operation_event_by_hash(
        &self,
        hash: H256,
    ) -> Result<Option<Log>, anyhow::Error> {
        let filter = Filter::new()
            .event(&UserOperationEventFilter::abi_signature())
            .address(self.entry_points.clone())
            .topic1(hash);

        let logs = self.provider.get_logs(&filter).await?;

        Ok(logs.first().cloned())
    }

    fn get_user_operations_from_tx_data(
        &self,
        tx_data: Bytes,
    ) -> Result<Vec<shared_types::UserOperation>, anyhow::Error> {
        let entry_point_calls: EntryPointCalls =
            AbiDecode::decode(tx_data).map_err(|e| anyhow!("Failed to parse tx data: {}", e))?;

        match entry_point_calls {
            EntryPointCalls::HandleOps(handle_ops_call) => Ok(handle_ops_call.ops),
            EntryPointCalls::HandleAggregatedOps(handle_aggregated_ops_call) => {
                Ok(handle_aggregated_ops_call
                    .ops_per_aggregator
                    .into_iter()
                    .map(|ops| ops.user_ops)
                    .flatten()
                    .collect())
            }
            _ => Err(anyhow!("tx does not contain user operations")),
        }
    }

    fn decode_user_operation_event(
        &self,
        log: Log,
    ) -> Result<UserOperationEventFilter, anyhow::Error> {
        let decoded: EntryPointEvents = EntryPointEvents::decode_log(&RawLog {
            topics: log.topics,
            data: log.data.to_vec(),
        })?;

        match decoded {
            EntryPointEvents::UserOperationEventFilter(event) => Ok(event),
            _ => Err(anyhow!("Log is not a user operation event")),
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

    async fn get_user_operation_by_hash(&self, hash: H256) -> RpcResult<Option<RichUserOperation>> {
        if hash == H256::zero() {
            return Err(EthRpcError::InvalidParams("hash cannot be zero".to_string()).into());
        }

        // 1. Get event associated with hash (need to check all entry point addresses associated with this API)
        let Some(event) = self
            .get_user_operation_event_by_hash(hash)
            .await
            .map_err(|e| EthRpcError::Internal(e.into()))? else {
                return Ok(None)
            };

        // 2. If the event is found, get the TX
        let Some(tx_hash) = event
            .transaction_hash else {
                return Err(EthRpcError::Internal(anyhow!("tx_hash should be present".to_string())).into())
            };

        let Some(tx) = self
            .provider
            .get_transaction(tx_hash)
            .await
            .map_err(|e| EthRpcError::Internal(e.into()))? else {
                return Err(EthRpcError::Internal(anyhow!("Failed to parse tx")).into())
            };

        let to = match tx.to {
            Some(to) if self.entry_points.contains(&to) => to,
            _ => {
                return Err(EthRpcError::Internal(anyhow!(
                    "Failed to parse tx or tx doesn't belong to entry point"
                ))
                .into())
            }
        };

        // 3. parse the tx data using the EntryPoint interface and extract UserOperation[] from it
        let user_ops = self
            .get_user_operations_from_tx_data(tx.input)
            .map_err(|e| EthRpcError::Internal(e))?;

        // 4. find first op matching sender + nonce with the event
        let event = self
            .decode_user_operation_event(event)
            .map_err(|e| EthRpcError::Internal(e))?;

        let Some(uo) = user_ops
            .iter()
            .find(|op| op.sender == event.sender && op.nonce == event.nonce) else {
                return Err(EthRpcError::Internal(anyhow!("Failed to find matching user operation in tx data")).into())
            };

        // 5. return the result
        Ok(Some(RichUserOperation {
            user_operation: uo.clone(),
            entry_point: to,
            block_number: tx
                .block_number
                .map(|n| U256::from(n.as_u64()))
                .unwrap_or(U256::zero()),
            block_hash: tx.block_hash.unwrap_or(H256::zero()),
            transaction_hash: tx_hash,
        }))
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
