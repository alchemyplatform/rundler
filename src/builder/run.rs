use anyhow::Context;
use tokio::sync::broadcast;
use tokio::sync::mpsc;

#[derive(Debug)]
pub struct Args {}

pub async fn run(
    _args: Args,
    mut shutdown_rx: broadcast::Receiver<()>,
    _shutdown_scope: mpsc::Sender<()>,
) -> anyhow::Result<()> {
    shutdown_rx
        .recv()
        .await
        .context("should wait for shutdown signal")
}
