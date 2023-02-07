use tokio::sync::broadcast;
use tokio::sync::mpsc;

#[derive(Debug)]
pub struct Args {
    pub port: u16,
    pub host: String,
}

pub async fn run(
    _args: Args,
    _shutdown_rx: broadcast::Receiver<()>,
    _shutdown_scope: mpsc::Sender<()>,
) -> anyhow::Result<()> {
    Ok(())
}
