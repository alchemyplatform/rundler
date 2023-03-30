use anyhow::Context;
use tokio::task::JoinHandle;

/// Flatten a JoinHandle result.
///
/// Flattens the two types of errors that can occur when awaiting a handle.
/// Useful when using tokio::try_join! to await multiple handles.
pub async fn flatten_handle<T>(
    handle: JoinHandle<Result<T, anyhow::Error>>,
) -> Result<T, anyhow::Error> {
    match handle.await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(err)) => Err(err)?,
        Err(err) => Err(err).context("handling failed")?,
    }
}
