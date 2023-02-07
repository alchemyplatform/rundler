use tokio::sync::broadcast;
use tokio::sync::mpsc;

pub struct Args {
    pub port: u16,
    pub host: String,
}

pub async fn run(
    _args: Args,
    _shutdown_rx: broadcast::Receiver<()>,
    _shutdown_scope: mpsc::Sender<()>,
) -> Result<(), anyhow::Error> {
    Ok(())
}
