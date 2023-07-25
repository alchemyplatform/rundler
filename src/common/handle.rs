use anyhow::Context;
use futures::{future::try_join_all, Future};
use tokio::{
    sync::mpsc,
    task::{AbortHandle, JoinHandle},
};
use tokio_util::sync::CancellationToken;
use tonic::async_trait;
use tracing::{error, info};

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

#[async_trait]
pub trait Task: Sync + Send + 'static {
    async fn run(&self, shutdown_token: CancellationToken) -> anyhow::Result<()>;
}

pub async fn spawn_tasks_with_shutdown<T, R, E>(
    tasks: impl IntoIterator<Item = Box<dyn Task>>,
    signal: T,
) where
    T: Future<Output = Result<R, E>> + Send + 'static,
    E: std::fmt::Debug,
{
    let (shutdown_scope, mut shutdown_wait) = mpsc::channel::<()>(1);
    let shutdown_token = CancellationToken::new();
    let mut shutdown_scope = Some(shutdown_scope);

    let handles = tasks.into_iter().map(|task| {
        let st = shutdown_token.clone();
        let ss = shutdown_scope.clone();
        async move {
            let ret = task.run(st).await;
            drop(ss);
            ret
        }
    });
    tokio::select! {
        res = try_join_all(handles) => {
            error!("Task exited unexpectedly: {res:?}");
        }
        res = signal => {
            match res {
                Ok(_) => {
                    info!("Received signal, shutting down");
                }
                Err(err) => {
                    error!("Error while waiting for signal: {err:?}");
                }
            }
        }
    }

    shutdown_token.cancel();
    shutdown_scope.take();
    shutdown_wait.recv().await;
}
