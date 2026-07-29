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
use alloy_json_rpc::RpcError;
use alloy_primitives::Bytes;
use alloy_sol_types::SolError;
use alloy_transport::{TransportError, TransportErrorKind};

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
    pub fn as_decoded_error<E: SolError>(&self) -> Option<E> {
        match self {
            ProviderError::RPC(TransportError::ErrorResp(e)) => e.as_decoded_error(),
            ProviderError::ContractError(ContractError::TransportError(
                TransportError::ErrorResp(e),
            )) => e.as_decoded_error(),
            _ => None,
        }
    }

    /// Returns true when the endpoint reported that it is rate limiting us.
    ///
    /// Rate limits arrive in several shapes - HTTP 429, a `429`/`-32005`-style
    /// JSON-RPC error response, or a stringified 429 from a transport that lost
    /// the status code - so detection is delegated to alloy rather than
    /// re-listing every provider's wording here.
    ///
    /// HTTP 503 is deliberately excluded even though alloy groups it with rate
    /// limits as "retryable": a temporarily unavailable endpoint is evidence
    /// about the endpoint's health, which callers classify differently from
    /// being asked to send fewer requests.
    pub fn is_rate_limited(&self) -> bool {
        let ProviderError::RPC(error) = self else {
            return false;
        };
        match error {
            RpcError::Transport(TransportErrorKind::HttpError(http)) => http.is_rate_limit_err(),
            RpcError::Transport(TransportErrorKind::Custom(err)) => {
                err.to_string().contains("429 Too Many Requests")
            }
            RpcError::ErrorResp(resp) => resp.is_retry_err(),
            _ => false,
        }
    }
}

/// Result of a provider method call
pub type ProviderResult<T> = Result<T, ProviderError>;
