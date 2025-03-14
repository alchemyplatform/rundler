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

use alloy_network::Network;
use rundler_provider::ProviderError;

/// Error type for the signer crate
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid transaction
    #[error("invalid transaction: {0}")]
    InvalidTransaction(String),
    /// Signing error
    #[error("signing error: {0}")]
    SigningError(String),
    /// Provider error
    #[error("provider error: {0}")]
    ProviderError(ProviderError),
    /// Other error
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Result type for the signer crate
pub type Result<T> = std::result::Result<T, Error>;

impl From<alloy_signer::Error> for Error {
    fn from(value: alloy_signer::Error) -> Self {
        Error::SigningError(value.to_string())
    }
}

impl<N: Network> From<alloy_network::UnbuiltTransactionError<N>> for Error {
    fn from(value: alloy_network::UnbuiltTransactionError<N>) -> Self {
        Error::InvalidTransaction(value.to_string())
    }
}

impl From<ProviderError> for Error {
    fn from(value: ProviderError) -> Self {
        Error::ProviderError(value)
    }
}
