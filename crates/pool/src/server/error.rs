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
