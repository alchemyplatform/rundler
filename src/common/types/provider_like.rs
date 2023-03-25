use std::sync::Arc;

use anyhow::Context;
use ethers::{
    contract::ContractError,
    providers::Middleware,
    types::{Address, BlockId, BlockNumber, Bytes, H256},
};
#[cfg(test)]
use mockall::automock;
use tonic::async_trait;

use crate::common::{contracts::i_aggregator::IAggregator, types::UserOperation};

#[cfg_attr(test, automock)]
#[async_trait]
pub trait ProviderLike: Send + Sync {
    async fn get_latest_block_hash(&self) -> anyhow::Result<H256>;

    async fn aggregate_signatures(
        self: Arc<Self>,
        aggregator_address: Address,
        ops: Vec<UserOperation>,
    ) -> anyhow::Result<Option<Bytes>>;
}

#[async_trait]
impl<M> ProviderLike for M
where
    M: Middleware + 'static,
    M::Error: 'static,
{
    async fn get_latest_block_hash(&self) -> anyhow::Result<H256> {
        self.get_block(BlockId::Number(BlockNumber::Latest))
            .await
            .context("should load block to get hash")?
            .context("block should exist to get latest hash")?
            .hash
            .context("hash should be present on block")
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
}
