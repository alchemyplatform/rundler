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
    abi::{AbiDecode, AbiEncode},
    types::{Address, BlockId, Bytes, Eip1559TransactionRequest, Selector, H256, U256},
};
use rundler_provider::{Provider, ProviderError};
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
    let out: CodeHashesResult =
        call_constructor(provider, &GETCODEHASHES_BYTECODE, addresses, block_id)
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
) -> anyhow::Result<GasUsedResult> {
    call_constructor(provider, &GETGASUSED_BYTECODE, (target, value, data), None).await
}

async fn call_constructor<P: Provider, Args: AbiEncode, Ret: AbiDecode>(
    provider: &P,
    bytecode: &Bytes,
    args: Args,
    block_id: Option<BlockId>,
) -> anyhow::Result<Ret> {
    let mut data = bytecode.to_vec();
    data.extend(AbiEncode::encode(args));
    let tx = Eip1559TransactionRequest {
        data: Some(data.into()),
        ..Default::default()
    };
    let error = provider
        .call(&tx.into(), block_id)
        .await
        .err()
        .context("called constructor should revert")?;
    get_revert_data(error).context("should decode revert data from called constructor")
}

// Gets and decodes the revert data from a provider error, if it is a revert error.
fn get_revert_data<D: AbiDecode>(error: ProviderError) -> Result<D, ProviderError> {
    let ProviderError::JsonRpcError(jsonrpc_error) = &error else {
        return Err(error);
    };
    if !jsonrpc_error.is_revert() {
        return Err(error);
    }
    match jsonrpc_error.decode_revert_data() {
        Some(ret) => Ok(ret),
        None => Err(error),
    }
}
