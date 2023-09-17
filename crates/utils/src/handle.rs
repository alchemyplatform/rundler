//! Utilities for working with future handles.

use anyhow::Context;
use futures::Future;
use tokio::task::{AbortHandle, JoinHandle};

/// Flatten a JoinHandle result.
///
/// Flattens the two types of errors that can occur when awaiting a handle.
/// Useful when using tokio::try_join! to await multiple handles.
pub async fn flatten_handle<T>(handle: JoinHandle<anyhow::Result<T>>) -> anyhow::Result<T> {
    match handle.await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(err)) => Err(err)?,
        Err(err) => Err(err).context("handling failed")?,
    }
}

/// Converts a JoinHandle result into an `anyhow::Result`. Like
/// `flatten_handle`, useful when using `tokio::try_join!` to await multiple
/// handles.
pub async fn as_anyhow_handle<T>(handle: JoinHandle<T>) -> anyhow::Result<T> {
    handle.await.context("handling failed")
}

/// A guard that aborts a spawned task when dropped.
#[derive(Debug)]
pub struct SpawnGuard(AbortHandle);

impl SpawnGuard {
    /// Spawn a future on Tokio and return a guard that will abort it when dropped.
    pub fn spawn_with_guard<T>(fut: T) -> Self
    where
        T: Future + Send + 'static,
        T::Output: Send + 'static,
    {
        Self(tokio::spawn(fut).abort_handle())
    }
}

impl Drop for SpawnGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}
