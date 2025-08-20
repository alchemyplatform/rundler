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
use rundler_provider::{Block, BlockId, EvmProvider};
use rundler_utils::retry::{self, UnlimitedRetryOpts};
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
    flashblocks: bool,
) -> (B256, Block) {
    loop {
        let block_id = if flashblocks {
            BlockId::pending()
        } else {
            BlockId::latest()
        };
        let block = retry::with_unlimited_retries(
            "watch latest block",
            || provider.get_full_block(block_id),
            UnlimitedRetryOpts::default(),
        )
        .await;
        let Some(block) = block else {
            error!("Latest block should be present when waiting for new block.");
            continue;
        };
        if last_block_hash != block.header.hash {
            return (block.header.hash, block);
        }
        time::sleep(poll_interval).await;
    }
}
