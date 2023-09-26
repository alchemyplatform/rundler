// This file is part of Rundler.
//
// Rundler is free software: you can redistribute it and/or modify it under the
// terms of the GNU Lesser General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later version.
//
// Rundler is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with Rundler.
// If not, see https://www.gnu.org/licenses/.

//! Block watcher utility functions.

use std::time::Duration;

use ethers::types::{Block, BlockNumber, H256};
use rundler_provider::Provider;
use rundler_utils::retry::{self, UnlimitedRetryOpts};
use tokio::time;
use tracing::error;

/// Wait for a new block (by hash) to be discovered and return it.
///
/// This function polls the provider for the latest block until a new block is discovered, with
/// unlimited retries.
pub async fn wait_for_new_block(
    provider: &impl Provider,
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

/// Wait for a new block number to be discovered and return it.
///
/// This function polls the provider for the latest block number until a new block number is discovered,
/// with unlimited retries.
pub async fn wait_for_new_block_number(
    provider: &impl Provider,
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
