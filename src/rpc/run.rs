use ethers::types::{Address, U256};
use tokio::sync::broadcast;
use tokio::sync::mpsc;

pub struct Args {
    pub port: u16,
    pub host: String,
    pub entry_point: Address,
    pub chain_id: U256,
}

pub async fn run(
    _args: Args,
    _shutdown_rx: broadcast::Receiver<()>,
    _shutdown_scope: mpsc::Sender<()>,
) -> anyhow::Result<()> {
    Ok(())
}
