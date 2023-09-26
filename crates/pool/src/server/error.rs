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

use crate::mempool::MempoolError;

/// Pool server error type
#[derive(Debug, thiserror::Error)]
pub enum PoolServerError {
    /// Mempool error occurred
    #[error(transparent)]
    MempoolError(MempoolError),
    /// Unexpected response from PoolServer
    #[error("Unexpected response from PoolServer")]
    UnexpectedResponse,
    /// Internal error
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl From<MempoolError> for PoolServerError {
    fn from(error: MempoolError) -> Self {
        match error {
            MempoolError::Other(e) => Self::Other(e),
            _ => Self::MempoolError(error),
        }
    }
}
