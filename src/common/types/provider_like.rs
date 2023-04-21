use std::sync::Arc;

use anyhow::Context;
use ethers::{
    contract::ContractError,
    providers::{JsonRpcClient, Middleware, PendingTransaction, Provider},
    types::{Address, BlockId, BlockNumber, Bytes, TransactionReceipt, H256, U256},
};
#[cfg(test)]
use mockall::automock;
use tonic::async_trait;

use crate::common::{contracts::i_aggregator::IAggregator, types::UserOperation};

#[cfg_attr(test, automock)]
#[async_trait]
pub trait ProviderLike: Send + Sync + 'static {
    async fn get_latest_block_hash(&self) -> anyhow::Result<H256>;

    async fn get_max_priority_fee(&self) -> anyhow::Result<U256>;

    async fn aggregate_signatures(
        self: Arc<Self>,
        aggregator_address: Address,
        ops: Vec<UserOperation>,
    ) -> anyhow::Result<Option<Bytes>>;

    async fn wait_until_mined(&self, tx_hash: H256) -> anyhow::Result<Option<TransactionReceipt>>;

    async fn get_code(&self, address: Address, block_hash: H256) -> anyhow::Result<Bytes>;
}

#[async_trait]
impl<C: JsonRpcClient + 'static> ProviderLike for Provider<C> {
    // We implement `ProviderLike` for `Provider` rather than for all
    // `Middleware` because forming a `PendingTransaction` specifically requires
    // a `Provider`.

    async fn get_latest_block_hash(&self) -> anyhow::Result<H256> {
        self.get_block(BlockId::Number(BlockNumber::Latest))
            .await
            .context("should load block to get hash")?
            .context("block should exist to get latest hash")?
            .hash
            .context("hash should be present on block")
    }

    async fn get_max_priority_fee(&self) -> anyhow::Result<U256> {
        Ok(self
            .request("eth_maxPriorityFeePerGas", ())
            .await
            .context("should get max priority fee from provider")?)
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

    async fn wait_until_mined(&self, tx_hash: H256) -> anyhow::Result<Option<TransactionReceipt>> {
        PendingTransaction::new(tx_hash, self)
            .await
            .context("should wait for transaction to be mined or dropped")
    }

    async fn get_code(&self, address: Address, block_hash: H256) -> anyhow::Result<Bytes> {
        Middleware::get_code(self, address, Some(block_hash.into()))
            .await
            .context("provider should get contract code")
    }
}
