use crate::op_pool::mempool::error::MempoolError;

#[derive(Debug, thiserror::Error)]
pub enum PoolServerError {
    #[error(transparent)]
    MempoolError(MempoolError),
    #[error("Unexpected response from PoolServer")]
    UnexpectedResponse,
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
