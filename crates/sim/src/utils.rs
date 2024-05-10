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

use anyhow::Context;
use ethers::types::{spoof, Address, BlockId, H256};
use rundler_provider::Provider;
use rundler_types::contracts::utils::get_code_hashes::{CodeHashesResult, GETCODEHASHES_BYTECODE};

/// Hashes together the code from all the provided addresses. The order of the input addresses does
/// not matter.
pub(crate) async fn get_code_hash<P: Provider>(
    provider: &P,
    mut addresses: Vec<Address>,
    block_id: Option<BlockId>,
) -> anyhow::Result<H256> {
    addresses.sort();
    let out: CodeHashesResult = provider
        .call_constructor(
            &GETCODEHASHES_BYTECODE,
            addresses,
            block_id,
            &spoof::state(),
        )
        .await
        .context("should compute code hashes")?;
    Ok(H256(out.hash))
}
