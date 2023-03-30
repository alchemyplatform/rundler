use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{bail, Context};
use ethers::{
    providers::{Http, Provider, ProviderExt},
    types::{Address, Chain},
};
use jsonrpsee::{server::ServerBuilder, RpcModule};
use tokio::sync::{broadcast, mpsc};

use super::ApiNamespace;
use crate::{
    common::{
        protos::{builder::builder_client, op_pool::op_pool_client},
        server::format_socket_addr,
        simulation,
    },
    rpc::{
        debug::{DebugApi, DebugApiServer},
        eth::{EthApi, EthApiServer},
        metrics::RpcMetricsLogger,
    },
};

pub struct Args {
    pub port: u16,
    pub host: String,
    pub pool_url: String,
    pub builder_url: String,
    pub entry_points: Vec<Address>,
    pub chain_id: u64,
    pub api_namespaces: Vec<ApiNamespace>,
    pub rpc_url: String,
    pub sim_settings: simulation::Settings,
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

    let op_pool_client = op_pool_client::OpPoolClient::connect(args.pool_url)
        .await
        .context("should have been able to connect to op pool")?;

    let builder_client = builder_client::BuilderClient::connect(args.builder_url)
        .await
        .context("builder server should be started")?;

    if args.entry_points.len() != 1 {
        bail!("Only one entry point is supported at the moment");
    }

    for api in args.api_namespaces {
        match api {
            ApiNamespace::Eth => module.merge(
                EthApi::new(
                    provider.clone(),
                    args.entry_points.clone(),
                    args.chain_id,
                    // NOTE: this clone is cheap according to the docs because all it's doing is copying the reference to the channel
                    op_pool_client.clone(),
                    args.sim_settings,
                )
                .into_rpc(),
            )?,
            ApiNamespace::Debug => module
                .merge(DebugApi::new(op_pool_client.clone(), builder_client.clone()).into_rpc())?,
        }
    }

    let server = ServerBuilder::default()
        .set_logger(RpcMetricsLogger)
        .http_only()
        .build(addr)
        .await?;
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
