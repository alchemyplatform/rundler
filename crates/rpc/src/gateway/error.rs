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

use jsonrpsee::types::ErrorObjectOwned;

use crate::error::rpc_err;

/// Gateway-specific error codes.
pub(crate) const CHAIN_NOT_FOUND_CODE: i32 = -32001;
pub(crate) const INVALID_PATH_CODE: i32 = -32002;

/// Error type for gateway operations.
#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    /// Chain not found.
    #[error("Chain {0} not found")]
    ChainNotFound(u64),

    /// Invalid path format.
    #[error("Invalid path format: {0}")]
    InvalidPath(String),
}

impl From<GatewayError> for ErrorObjectOwned {
    fn from(err: GatewayError) -> Self {
        match err {
            GatewayError::ChainNotFound(id) => {
                rpc_err(CHAIN_NOT_FOUND_CODE, format!("Chain {} not found", id))
            }
            GatewayError::InvalidPath(msg) => rpc_err(INVALID_PATH_CODE, msg),
        }
    }
}
