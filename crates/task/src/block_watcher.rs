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

use alloy_primitives::B256;
use rundler_provider::{Block, BlockId, EvmProvider, ProviderResult};
use rundler_utils::retry::{self, RetryOpts};
use tokio::time;
use tracing::error;

/// Wait for a new block (by hash) to be discovered and return it.
///
/// This function polls the provider for the latest block until a new block is discovered, with
/// unlimited retries.
pub async fn wait_for_new_block(
    provider: &impl EvmProvider,
    last_block_hash: B256,
    poll_interval: Duration,
    block_id: BlockId,
) -> (B256, Block) {
    loop {
        let Some((hash, block)) = get_block(provider, block_id, u64::MAX).await.unwrap() else {
            error!("Latest block should be present when waiting for new block.");
            continue;
        };
        if hash != last_block_hash {
            return (hash, block);
        }
        time::sleep(poll_interval).await;
    }
}

/// get a block by tag.
///
/// This function polls the provider for the `block_id` block.
pub async fn get_block(
    provider: &impl EvmProvider,
    block_id: BlockId,
    max_attempts: u64,
) -> ProviderResult<Option<(B256, Block)>> {
    let retry_opts = RetryOpts {
        max_attempts,
        ..Default::default()
    };
    let block = retry::with_retries(
        "watch latest block",
        || provider.get_full_block(block_id),
        retry_opts,
    )
    .await?;

    if let Some(block) = block {
        return Ok(Some((block.header.hash, block)));
    }
    Ok(None)
}
