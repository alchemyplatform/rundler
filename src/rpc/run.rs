use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context};
use ethers::providers::{Http, Provider, ProviderExt};
use ethers::types::{Address, Chain};
use jsonrpsee::server::ServerBuilder;
use jsonrpsee::RpcModule;
use tokio::sync::broadcast;
use tokio::sync::mpsc;

use crate::common::protos::op_pool::op_pool_client;
use crate::common::server::format_socket_addr;
use crate::rpc::debug::{DebugApi, DebugApiServer};
use crate::rpc::eth::{EthApi, EthApiServer};

use super::ApiNamespace;

pub struct Args {
    pub port: u16,
    pub host: String,
    pub pool_url: String,
    pub builder_url: Option<String>,
    pub entry_point: Address,
    pub chain_id: u64,
    pub api_namespaces: Vec<ApiNamespace>,
    pub rpc_url: String,
}

pub async fn run(
    args: Args,
    mut shutdown_rx: broadcast::Receiver<()>,
    _shutdown_scope: mpsc::Sender<()>,
) -> anyhow::Result<()> {
    let addr: SocketAddr = format_socket_addr(&args.host, args.port).parse()?;
    tracing::info!("Starting server on {}", addr);

    let mut module = RpcModule::new(());
    let chain: Chain = args
        .chain_id
        .try_into()
        .with_context(|| format!("{} is not a supported chain", args.chain_id))?;

    let provider: Arc<Provider<Http>> = Arc::new(
        Provider::<Http>::try_from(args.rpc_url)
            .context("Invalid RPC URL")?
            // TODO: revisit a safe default for production
            .interval(Duration::from_millis(100))
            .for_chain(chain),
    );

    for api in args.api_namespaces {
        match api {
            ApiNamespace::Eth => module.merge(
                EthApi::new(provider.clone(), vec![args.entry_point], args.chain_id).into_rpc(),
            )?,
            ApiNamespace::Debug => module.merge(
                DebugApi::new(op_pool_client::OpPoolClient::connect(args.pool_url.clone()).await?)
                    .into_rpc(),
            )?,
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
