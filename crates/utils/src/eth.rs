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

//! Utilities for working with an Ethereum-like chain via Ethers.

use ethers::{
    abi::{AbiDecode, AbiEncode, RawLog},
    contract::ContractError,
    providers::Middleware,
    types::{Address, Bytes, Log, Selector},
};

/// Creates call data from a method and its arguments. The arguments should be
/// passed as a tuple.
///
/// Important: if the method takes a single argument, then this function should
/// be passed a single-element tuple, and not just the argument by itself.
pub fn call_data_of(selector: Selector, args: impl AbiEncode) -> Bytes {
    let mut bytes = selector.to_vec();
    bytes.extend(args.encode());
    bytes.into()
}

/// Gets the revert data from a contract error if it is a revert error,
/// otherwise returns the original error.
pub fn get_revert_bytes<M: Middleware>(error: ContractError<M>) -> Result<Bytes, ContractError<M>> {
    if let ContractError::Revert(bytes) = error {
        Ok(bytes)
    } else {
        Err(error)
    }
}

/// The abi for what happens when you just `revert("message")` in a contract
#[derive(Clone, Debug, Default, Eq, PartialEq, ethers::contract::EthError)]
#[etherror(name = "Error", abi = "Error(string)")]
pub struct ContractRevertError {
    /// Revert reason
    pub reason: String,
}

/// Parses the revert message from the revert data
pub fn parse_revert_message(revert_data: &[u8]) -> Option<String> {
    ContractRevertError::decode(revert_data)
        .ok()
        .map(|err| err.reason)
}

/// Converts an ethers `Log` into an ethabi `RawLog`.
pub fn log_to_raw_log(log: Log) -> RawLog {
    let Log { topics, data, .. } = log;
    RawLog {
        topics,
        data: data.to_vec(),
    }
}

/// Format the ethers address type to string without ellipsis
pub fn format_address(address: Address) -> String {
    format!("{:#x}", address).to_string()
}
