use std::{fmt::Debug, sync::Arc};

use anyhow::Context;
use ethers::{
    contract::ContractError,
    providers::{JsonRpcClient, Middleware, Provider as EthersProvider, ProviderError},
    types::{
        transaction::eip2718::TypedTransaction, Address, Block, BlockId, BlockNumber, Bytes,
        Eip1559TransactionRequest, Filter, GethDebugTracingCallOptions, GethDebugTracingOptions,
        GethTrace, Log, Transaction, TransactionReceipt, TxHash, H160, H256, U256, U64,
    },
};
use rundler_types::{
    contracts::{
        gas_price_oracle::GasPriceOracle, i_aggregator::IAggregator, i_entry_point::IEntryPoint,
        node_interface::NodeInterface,
    },
    UserOperation,
};
use serde::{de::DeserializeOwned, Serialize};

use crate::{AggregatorOut, AggregatorSimOut, Provider};

const ARBITRUM_NITRO_NODE_INTERFACE_ADDRESS: Address = H160([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xc8,
]);

const OPTIMISM_BEDROCK_GAS_ORACLE_ADDRESS: Address = H160([
    0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0F,
]);

#[async_trait::async_trait]
impl<C: JsonRpcClient + 'static> Provider for EthersProvider<C> {
    // We implement `ProviderLike` for `Provider` rather than for all
    // `Middleware` because forming a `PendingTransaction` specifically requires
    // a `Provider`.

    async fn request<T, R>(&self, method: &str, params: T) -> Result<R, ProviderError>
    where
        T: Debug + Serialize + Send + Sync + 'static,
        R: Serialize + DeserializeOwned + Debug + Send + 'static,
    {
        EthersProvider::request(self, method, params).await
    }

    async fn call(
        &self,
        tx: &TypedTransaction,
        block: Option<BlockId>,
    ) -> Result<Bytes, ProviderError> {
        Middleware::call(self, tx, block).await
    }

    async fn get_block_number(&self) -> anyhow::Result<u64> {
        Ok(Middleware::get_block_number(self)
            .await
            .context("should get block number from provider")?
            .as_u64())
    }

    async fn get_block<T: Into<BlockId> + Send + Sync + 'static>(
        &self,
        block_hash_or_number: T,
    ) -> anyhow::Result<Option<Block<H256>>> {
        Middleware::get_block(self, block_hash_or_number)
            .await
            .context("should get block from provider")
    }

    async fn get_transaction<T: Send + Sync + Into<TxHash>>(
        &self,
        transaction_hash: T,
    ) -> Result<Option<Transaction>, ProviderError> {
        Middleware::get_transaction(self, transaction_hash).await
    }

    async fn get_transaction_receipt<T: Send + Sync + Into<TxHash> + 'static>(
        &self,
        transaction_hash: T,
    ) -> Result<Option<TransactionReceipt>, ProviderError> {
        Middleware::get_transaction_receipt(self, transaction_hash).await
    }

    async fn debug_trace_transaction(
        &self,
        tx_hash: TxHash,
        trace_options: GethDebugTracingOptions,
    ) -> Result<GethTrace, ProviderError> {
        Middleware::debug_trace_transaction(self, tx_hash, trace_options).await
    }

    async fn debug_trace_call(
        &self,
        tx: &TypedTransaction,
        block_id: Option<BlockId>,
        trace_options: GethDebugTracingCallOptions,
    ) -> Result<GethTrace, ProviderError> {
        Middleware::debug_trace_call(self, (*tx).clone(), block_id, trace_options).await
    }

    async fn get_balance(&self, address: Address, block: Option<BlockId>) -> anyhow::Result<U256> {
        Middleware::get_balance(self, address, block)
            .await
            .context("should get balance from provider")
    }

    async fn get_latest_block_hash(&self) -> anyhow::Result<H256> {
        Middleware::get_block(self, BlockId::Number(BlockNumber::Latest))
            .await
            .context("should load block to get hash")?
            .context("block should exist to get latest hash")?
            .hash
            .context("hash should be present on block")
    }

    async fn get_base_fee(&self) -> anyhow::Result<U256> {
        Middleware::get_block(self, BlockNumber::Pending)
            .await
            .context("should load pending block to get base fee")?
            .context("pending block should exist")?
            .base_fee_per_gas
            .context("pending block should have a nonempty base fee")
    }

    async fn get_max_priority_fee(&self) -> anyhow::Result<U256> {
        self.request("eth_maxPriorityFeePerGas", ())
            .await
            .context("should get max priority fee from provider")
    }

    async fn get_logs(&self, filter: &Filter) -> anyhow::Result<Vec<Log>> {
        Middleware::get_logs(self, filter)
            .await
            .context("provider should get logs")
    }

    async fn aggregate_signatures(
        self: Arc<Self>,
        aggregator_address: Address,
        ops: Vec<UserOperation>,
    ) -> anyhow::Result<Option<Bytes>> {
        let aggregator = IAggregator::new(aggregator_address, self);
        // TODO: Cap the gas here.
        let result = aggregator.aggregate_signatures(ops).call().await;
        match result {
            Ok(bytes) => Ok(Some(bytes)),
            Err(ContractError::Revert(_)) => Ok(None),
            Err(error) => Err(error).context("aggregator contract should aggregate signatures")?,
        }
    }

    async fn validate_user_op_signature(
        self: Arc<Self>,
        aggregator_address: Address,
        user_op: UserOperation,
        gas_cap: u64,
    ) -> anyhow::Result<AggregatorOut> {
        let aggregator = IAggregator::new(aggregator_address, self);
        let result = aggregator
            .validate_user_op_signature(user_op)
            .gas(gas_cap)
            .call()
            .await;

        match result {
            Ok(sig) => Ok(AggregatorOut::SuccessWithInfo(AggregatorSimOut {
                address: aggregator_address,
                signature: sig,
            })),
            Err(ContractError::Revert(_)) => Ok(AggregatorOut::ValidationReverted),
            Err(error) => Err(error).context("should call aggregator to validate signature")?,
        }
    }

    async fn get_code(&self, address: Address, block_hash: Option<H256>) -> anyhow::Result<Bytes> {
        Middleware::get_code(self, address, block_hash.map(|b| b.into()))
            .await
            .context("provider should get contract code")
    }

    async fn get_transaction_count(&self, address: Address) -> anyhow::Result<U256> {
        Middleware::get_transaction_count(self, address, None)
            .await
            .context("provider should get transaction count")
    }

    async fn calc_arbitrum_l1_gas(
        self: Arc<Self>,
        entry_point_address: Address,
        op: UserOperation,
    ) -> anyhow::Result<U256> {
        let entry_point = IEntryPoint::new(entry_point_address, Arc::clone(&self));
        let data = entry_point
            .handle_ops(vec![op], Address::random())
            .calldata()
            .context("should get calldata for entry point handle ops")?;

        let arb_node = NodeInterface::new(ARBITRUM_NITRO_NODE_INTERFACE_ADDRESS, self);
        let gas = arb_node
            .gas_estimate_l1_component(entry_point_address, false, data)
            .call()
            .await?;
        Ok(U256::from(gas.0))
    }

    async fn calc_optimism_l1_gas(
        self: Arc<Self>,
        entry_point_address: Address,
        op: UserOperation,
    ) -> anyhow::Result<U256> {
        let entry_point = IEntryPoint::new(entry_point_address, Arc::clone(&self));
        let data = entry_point
            .handle_ops(vec![op], Address::random())
            .calldata()
            .context("should get calldata for entry point handle ops")?;

        // construct an unsigned transaction with default values just for L1 gas estimation
        let tx = Eip1559TransactionRequest::new()
            .from(Address::random())
            .to(entry_point_address)
            .gas(U256::from(1_000_000))
            .max_priority_fee_per_gas(U256::from(100_000_000))
            .max_fee_per_gas(U256::from(100_000_000))
            .value(U256::from(0))
            .data(data)
            .nonce(U256::from(100_000))
            .chain_id(U64::from(100_000))
            .rlp();

        let gas_oracle =
            GasPriceOracle::new(OPTIMISM_BEDROCK_GAS_ORACLE_ADDRESS, Arc::clone(&self));

        let (l1_fee, l2_base_fee, l2_priority_fee) = tokio::try_join!(
            async {
                let l1_gas = gas_oracle.get_l1_fee(tx).call().await?;
                Ok(l1_gas)
            },
            self.get_base_fee(),
            self.get_max_priority_fee(),
        )?;

        Ok(l1_fee / (l2_base_fee + l2_priority_fee))
    }
}
