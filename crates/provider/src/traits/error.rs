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
use alloy_primitives::Bytes;
use alloy_sol_types::SolInterface;
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

impl ProviderError {
    /// Attempt to extract revert data from a provider error
    pub fn as_revert_data(&self) -> Option<Bytes> {
        match self {
            ProviderError::RPC(TransportError::ErrorResp(e)) => e.as_revert_data(),
            ProviderError::ContractError(ContractError::TransportError(
                TransportError::ErrorResp(e),
            )) => e.as_revert_data(),
            _ => None,
        }
    }

    /// Attempt to decode a contract error from a provider error
    pub fn as_decoded_error<E: SolInterface>(&self) -> Option<E> {
        match self {
            ProviderError::RPC(TransportError::ErrorResp(e)) => e.as_decoded_error(false),
            ProviderError::ContractError(ContractError::TransportError(
                TransportError::ErrorResp(e),
            )) => e.as_decoded_error(false),
            _ => None,
        }
    }
}

/// Result of a provider method call
pub type ProviderResult<T> = Result<T, ProviderError>;
