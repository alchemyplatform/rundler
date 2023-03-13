use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
use ethers::providers::{Http, Provider, ProviderExt};
use ethers::types::{Address, Chain, U256};
use jsonrpsee::server::ServerBuilder;
use jsonrpsee::RpcModule;
use tokio::sync::broadcast;
use tokio::sync::mpsc;

use crate::common::protos::op_pool::op_pool_client;
use crate::common::server::format_server_addr;
use crate::rpc::debug::{DebugApi, DebugApiServer};
use crate::rpc::eth::{EthApi, EthApiServer};

use super::ApiNamespace;

pub struct Args {
    pub port: u16,
    pub host: String,
    pub op_pool_host: String,
    pub op_pool_port: u16,
    pub entry_point: Address,
    pub chain_id: U256,
    pub api_namespaces: Vec<ApiNamespace>,
    pub rpc_url: String,
}

pub async fn run(
    args: Args,
    mut shutdown_rx: broadcast::Receiver<()>,
    _shutdown_scope: mpsc::Sender<()>,
) -> anyhow::Result<()> {
    let addr: SocketAddr = format_server_addr(args.host, args.port).parse()?;
    tracing::info!("Starting server on {}", addr);

    let mut module = RpcModule::new(());
    let chain: Chain = args
        .chain_id
        .try_into()
        .expect(format!("{} is not a supported chain", args.chain_id).as_str());

    let provider: Arc<Provider<Http>> = Arc::new(
        Provider::<Http>::try_from(args.rpc_url)
            .expect("Invalid RPC URL")
            .interval(Duration::from_millis(100))
            .for_chain(chain),
    );

    for api in args.api_namespaces {
        match api {
            ApiNamespace::Eth => module.merge(
                EthApi::new(provider.clone(), vec![args.entry_point], args.chain_id).into_rpc(),
            )?,
            ApiNamespace::Debug => module.merge(
                DebugApi::new(
                    op_pool_client::OpPoolClient::connect(format_server_addr(
                        args.op_pool_host.clone(),
                        args.op_pool_port,
                    ))
                    .await?,
                )
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
