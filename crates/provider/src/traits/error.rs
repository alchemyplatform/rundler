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

use ethers::providers::JsonRpcError;

/// Error enumeration for the Provider trait
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    /// JSON-RPC error
    #[error(transparent)]
    JsonRpcError(#[from] JsonRpcError),
    /// Contract Error
    #[error("Contract Error: {0}")]
    ContractError(String),
    /// Internal errors
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
