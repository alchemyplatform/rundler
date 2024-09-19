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

use alloy_contract::Error as ContractError;
use alloy_transport::TransportError;

/// Error enumeration for the Provider trait
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    /// RPC Error
    #[error("RPC Error: {0}")]
    RPC(TransportError),
    /// Contract Error
    #[error("Contract Error: {0}")]
    ContractError(ContractError),
    /// Internal errors
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl From<TransportError> for ProviderError {
    fn from(err: TransportError) -> Self {
        ProviderError::RPC(err)
    }
}

impl From<ContractError> for ProviderError {
    fn from(err: ContractError) -> Self {
        ProviderError::ContractError(err)
    }
}

/// Result of a provider method call
pub type ProviderResult<T> = Result<T, ProviderError>;
