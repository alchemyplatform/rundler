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
use alloy_json_rpc::{ErrorPayload, RpcError};
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
    /// Alloy handles standard transport and JSON-RPC rate-limit responses. The
    /// additional message check handles a mixed-case 429 response that Alloy
    /// currently matches case-sensitively. Checks are delegated per variant
    /// rather than via `TransportErrorKind::is_retry_err` for the whole enum,
    /// which is broader than a rate limit: it also retries `MissingBatchResponse`
    /// and HTTP 503, and 503 is provider-health evidence.
    pub fn is_rate_limited(&self) -> bool {
        let ProviderError::RPC(error) = self else {
            return false;
        };
        match error {
            RpcError::Transport(TransportErrorKind::HttpError(http)) => http.is_rate_limit_err(),
            RpcError::Transport(kind @ TransportErrorKind::Custom(_)) => kind.is_retry_err(),
            RpcError::ErrorResp(resp) => {
                let message = resp.message.to_ascii_lowercase();
                resp.is_retry_err()
                    || (message.contains("429") && message.contains("too many requests"))
            }
            _ => false,
        }
    }

    /// Returns true when the node rejected a call before running it because its fee cap was
    /// below the block's base fee, as `eth_call` and `eth_simulateV1` in validation mode do. The
    /// call never ran, so this says nothing about what it does.
    pub fn is_base_fee_too_low(&self) -> bool {
        self.error_response().is_some_and(|e| {
            e.code == ETH_SIMULATE_BASE_FEE_TOO_LOW
                || crate::alloy::entry_point::is_base_fee_too_low(&e.message)
        })
    }

    /// Returns true when the node rejected a call before running it because its sender cannot
    /// pay for its gas at its fee cap, as `eth_simulateV1` in validation mode does. The call never
    /// ran, so this says nothing about what it does.
    pub fn is_insufficient_funds(&self) -> bool {
        self.error_response().is_some_and(|e| {
            e.code == ETH_SIMULATE_INSUFFICIENT_FUNDS
                || e.message.to_lowercase().contains("insufficient funds")
        })
    }

    /// The node's JSON-RPC error response, if this is one
    fn error_response(&self) -> Option<&ErrorPayload> {
        match self {
            ProviderError::RPC(TransportError::ErrorResp(e))
            | ProviderError::ContractError(ContractError::TransportError(
                TransportError::ErrorResp(e),
            )) => Some(e),
            _ => None,
        }
    }
}

/// `eth_simulateV1`'s error code for a call whose fee cap is below the block's base fee
/// (execution-apis; reth's `BaseFeePerGasTooLow`)
const ETH_SIMULATE_BASE_FEE_TOO_LOW: i64 = -38012;

/// `eth_simulateV1`'s error code for a call whose sender cannot pay for its gas and value
/// (execution-apis; reth's `InsufficientFunds`)
const ETH_SIMULATE_INSUFFICIENT_FUNDS: i64 = -38014;

/// Result of a provider method call
pub type ProviderResult<T> = Result<T, ProviderError>;

#[cfg(test)]
mod tests {
    use super::*;

    fn error_response(code: i64, message: &'static str) -> ProviderError {
        ProviderError::RPC(TransportError::ErrorResp(ErrorPayload {
            code,
            message: message.into(),
            data: None,
        }))
    }

    /// reth's `eth_simulateV1` errors in validation mode (Sepolia, reth v2.10)
    const BASE_FEE_TOO_LOW: (i64, &str) = (-38012, "max fee per gas less than block base fee");
    const INSUFFICIENT_FUNDS: (i64, &str) = (
        -38014,
        "insufficient funds for gas * price + value: have 0 want 1",
    );

    #[test]
    fn classifies_base_fee_too_low() {
        let (code, message) = BASE_FEE_TOO_LOW;
        assert!(error_response(code, message).is_base_fee_too_low());
        // By the code or the message alone
        assert!(error_response(code, "fee cap too low: 1 < 18").is_base_fee_too_low());
        assert!(error_response(-32000, message).is_base_fee_too_low());
        // Through a contract call
        let contract_error = ProviderError::ContractError(ContractError::TransportError(
            TransportError::ErrorResp(ErrorPayload {
                code,
                message: message.into(),
                data: None,
            }),
        ));
        assert!(contract_error.is_base_fee_too_low());

        let (code, message) = INSUFFICIENT_FUNDS;
        assert!(!error_response(code, message).is_base_fee_too_low());
        assert!(!error_response(3, "execution reverted").is_base_fee_too_low());
        assert!(
            !ProviderError::Other(anyhow::anyhow!("max fee per gas less than block base fee"))
                .is_base_fee_too_low()
        );
    }

    #[test]
    fn classifies_insufficient_funds() {
        let (code, message) = INSUFFICIENT_FUNDS;
        assert!(error_response(code, message).is_insufficient_funds());
        assert!(error_response(code, "sender balance too low").is_insufficient_funds());
        assert!(error_response(-32000, message).is_insufficient_funds());

        let (code, message) = BASE_FEE_TOO_LOW;
        assert!(!error_response(code, message).is_insufficient_funds());
        assert!(!error_response(3, "execution reverted").is_insufficient_funds());
        assert!(
            !ProviderError::Other(anyhow::anyhow!("insufficient funds")).is_insufficient_funds()
        );
    }
}
