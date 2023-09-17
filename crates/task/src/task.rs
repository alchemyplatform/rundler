//! Task trait and helper functions

use async_trait::async_trait;
use futures::{future::try_join_all, Future};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

/// Core task trait implemented by top level Rundler tasks.
#[async_trait]
pub trait Task: Sync + Send + 'static {
    /// Run the task.
    async fn run(self: Box<Self>, shutdown_token: CancellationToken) -> anyhow::Result<()>;
}

/// Spawn a set of tasks and wait for a shutdown signal.
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
