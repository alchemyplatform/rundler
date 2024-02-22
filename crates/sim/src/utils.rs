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
use ethers::{
    abi::AbiEncode,
    types::{spoof, Address, BlockId, Bytes, Selector, H256, U256},
};
use rundler_provider::Provider;
use rundler_types::contracts::{
    get_code_hashes::{CodeHashesResult, GETCODEHASHES_BYTECODE},
    get_gas_used::{GasUsedResult, GETGASUSED_BYTECODE},
};

/// Creates call data from a method and its arguments. The arguments should be
/// passed as a tuple.
///
/// Important: if the method takes a single argument, then this function should
/// be passed a single-element tuple, and not just the argument by itself.
pub(crate) fn call_data_of(selector: Selector, args: impl AbiEncode) -> Bytes {
    let mut bytes = selector.to_vec();
    bytes.extend(args.encode());
    bytes.into()
}

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

/// Measures the gas used by a call to target with value and data.
pub(crate) async fn get_gas_used<P: Provider>(
    provider: &P,
    target: Address,
    value: U256,
    data: Bytes,
    state_overrides: &spoof::State,
) -> anyhow::Result<GasUsedResult> {
    provider
        .call_constructor(
            &GETGASUSED_BYTECODE,
            (target, value, data),
            None,
            state_overrides,
        )
        .await
}
