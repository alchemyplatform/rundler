use std::net::SocketAddr;

use anyhow::bail;
use ethers::types::{Address, U256};
use jsonrpsee::server::ServerBuilder;
use jsonrpsee::RpcModule;
use tokio::sync::broadcast;
use tokio::sync::mpsc;

use crate::rpc::debug::{DebugApi, DebugApiServer};
use crate::rpc::eth::{EthApi, EthApiServer};

use super::ApiNamespace;

pub struct Args {
    pub port: u16,
    pub host: String,
    pub entry_point: Address,
    pub chain_id: U256,
    pub api_namespaces: Vec<ApiNamespace>,
}

pub async fn run(
    args: Args,
    mut shutdown_rx: broadcast::Receiver<()>,
    _shutdown_scope: mpsc::Sender<()>,
) -> anyhow::Result<()> {
    let addr: SocketAddr = format!("{}:{}", args.host, args.port).parse()?;
    tracing::info!("Starting server on {}", addr);

    let mut module = RpcModule::new(());

    for api in args.api_namespaces {
        match api {
            ApiNamespace::Eth => {
                module.merge(EthApi::new(vec![args.entry_point], args.chain_id).into_rpc())?
            }
            ApiNamespace::Debug => module.merge(DebugApi.into_rpc())?,
        }
    }

    let server = ServerBuilder::default().build(addr).await?;
    let handle = server.start(module)?;

    tokio::select! {
        _ = handle.stopped() => {
            tracing::error!("Server stopped unexpectedly");
            bail!("RPC server stopped unexpectedly")
        }
        _ = shutdown_rx.recv() => {
            tracing::info!("Server shutdown");
            Ok(())
        }
    }
}
