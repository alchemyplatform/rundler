mod error;

use crate::common::{
    contracts::entry_point::{EntryPointCalls, EntryPointEvents, UserOperationEventFilter},
    eth::log_to_raw_log,
    types::UserOperation,
};
use anyhow::{anyhow, bail, Context};
use ethers::{
    abi::AbiDecode,
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

    async fn get_user_operation_event_by_hash(&self, hash: H256) -> anyhow::Result<Option<Log>> {
        let filter = Filter::new()
            .address(self.entry_points.clone())
            .topic1(hash);

        // we don't do .query().await here because we still need the raw logs for the TX
        // hash later. But hopefully this is a bit clearer than using .abi_signature()
        let filter = UserOperationEventFilter::new(filter, &self.provider).filter;

        let logs = self.provider.get_logs(&filter).await?;

        Ok(logs.into_iter().next())
    }

    fn get_user_operations_from_tx_data(
        &self,
        tx_data: Bytes,
    ) -> anyhow::Result<Vec<UserOperation>> {
        let entry_point_calls = EntryPointCalls::decode(tx_data)
            .context("should parse tx data as calls to the entry point")?;

        match entry_point_calls {
            EntryPointCalls::HandleOps(handle_ops_call) => Ok(handle_ops_call.ops),
            EntryPointCalls::HandleAggregatedOps(handle_aggregated_ops_call) => {
                Ok(handle_aggregated_ops_call
                    .ops_per_aggregator
                    .into_iter()
                    .flat_map(|ops| ops.user_ops)
                    .collect())
            }
            _ => bail!("tx should contain a user operations"),
        }
    }

    fn decode_user_operation_event(&self, log: Log) -> anyhow::Result<UserOperationEventFilter> {
        let decoded: EntryPointEvents = EntryPointEvents::decode_log(&log_to_raw_log(log))?;

        match decoded {
            EntryPointEvents::UserOperationEventFilter(event) => Ok(event),
            _ => bail!("Log should be a user operation event"),
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
            return Err(EthRpcError::InvalidParams(
                "hash cannot be zero".to_string(),
            ))?;
        }

        // 1. Get event associated with hash (need to check all entry point addresses associated with this API)
        let event = self
            .get_user_operation_event_by_hash(hash)
            .await
            .context("should have successfully queried for user op events by hash")?;

        let Some(event) = event else {
            return Ok(None)
        };

        // 2. If the event is found, get the TX
        let Some(transaction_hash) = event
            .transaction_hash else {
                return Err(anyhow!("tx_hash should be present"))?
            };

        let tx = self
            .provider
            .get_transaction(transaction_hash)
            .await
            .context("should have fetched tx from provider")?;

        let Some(tx) = tx else {
                return Err(anyhow!("should have found tx"))?
            };

        let to = match tx.to {
            Some(to) if self.entry_points.contains(&to) => to,
            _ => {
                return Err(anyhow!(
                    "should parse tx and tx should have been called to an entry point"
                ))?
            }
        };

        // 3. parse the tx data using the EntryPoint interface and extract UserOperation[] from it
        let user_ops = self
            .get_user_operations_from_tx_data(tx.input)
            .context("should have parsed tx data as user operations")?;

        // 4. find first op matching sender + nonce with the event
        let event = self
            .decode_user_operation_event(event)
            .context("should have decoded log event as user operation event")?;

        let Some(user_operation) = user_ops
            .into_iter()
            .find(|op| op.sender == event.sender && op.nonce == event.nonce) else {
                return Err(anyhow!("matching user operation should be found in tx data"))?
            };

        // 5. return the result
        Ok(Some(RichUserOperation {
            user_operation,
            entry_point: to,
            block_number: tx
                .block_number
                .map(|n| U256::from(n.as_u64()))
                .unwrap_or_default(),
            block_hash: tx.block_hash.unwrap_or_default(),
            transaction_hash,
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
