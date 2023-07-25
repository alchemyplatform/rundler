use std::time::Duration;

use ethers::types::{Block, BlockNumber, H256};
use tokio::time;
use tracing::error;

use crate::common::{retry, retry::UnlimitedRetryOpts, types::ProviderLike};

pub async fn wait_for_new_block(
    provider: &impl ProviderLike,
    last_block_hash: H256,
    poll_interval: Duration,
) -> (H256, Block<H256>) {
    loop {
        let block = retry::with_unlimited_retries(
            "watch latest block",
            || provider.get_block(BlockNumber::Latest),
            UnlimitedRetryOpts::default(),
        )
        .await;
        let Some(block) = block else {
            error!("Latest block should be present when waiting for new block.");
            continue;
        };
        let Some(hash) = block.hash else {
            error!("Latest block should have hash.");
            continue;
        };
        if last_block_hash != hash {
            return (hash, block);
        }
        time::sleep(poll_interval).await;
    }
}

pub async fn wait_for_new_block_number(
    provider: &impl ProviderLike,
    last_block_number: u64,
    poll_interval: Duration,
) -> u64 {
    loop {
        let block_number = retry::with_unlimited_retries(
            "watch latest block number",
            || provider.get_block_number(),
            UnlimitedRetryOpts::default(),
        )
        .await;
        if last_block_number < block_number {
            return block_number;
        }
        time::sleep(poll_interval).await;
    }
}
