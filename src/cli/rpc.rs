use anyhow::{bail, Context};
use clap::Args;
use tokio::{signal, sync::broadcast, sync::mpsc};
use tracing::{error, info};

use crate::{common::simulation, rpc};

use super::CommonArgs;

/// CLI options for the RPC server
#[derive(Args, Debug)]
#[command(next_help_heading = "RPC")]
pub struct RpcArgs {
    /// Port to listen on for JSON-RPC requests
    #[arg(
        long = "rpc.port",
        name = "rpc.port",
        env = "RPC_PORT",
        default_value = "3000"
    )]
    port: u16,

    /// Host to listen on for JSON-RPC requests
    #[arg(
        long = "rpc.host",
        name = "rpc.host",
        env = "RPC_HOST",
        default_value = "0.0.0.0"
    )]
    host: String,

    /// Which APIs to expose over the RPC interface
    #[arg(
        long = "rpc.api",
        name = "rpc.api",
        env = "RPC_API",
        default_value = "eth",
        value_delimiter = ',',
        value_parser = ["eth", "debug"]
    )]
    api: Vec<String>,
}

impl RpcArgs {
    /// Convert the CLI arguments into the arguments for the RPC server combining
    /// common and rpc specific arguments.
    pub fn to_args(
        &self,
        common: &CommonArgs,
        pool_url: String,
        builder_url: String,
        sim_settings: simulation::Settings,
    ) -> anyhow::Result<rpc::Args> {
        let apis = self
            .api
            .iter()
            .map(|api| api.parse())
            .collect::<Result<Vec<_>, _>>()?;

        Ok(rpc::Args {
            port: self.port,
            host: self.host.clone(),
            pool_url,
            builder_url,
            entry_point: common
                .entry_point
                .parse()
                .context("Invalid entry_point argument")?,
            rpc_url: common
                .node_http
                .clone()
                .context("rpc requires node_http arg")?,
            chain_id: common.chain_id,
            api_namespaces: apis,
            sim_settings,
        })
    }
}

/// CLI options for the RPC server standalone
#[derive(Args, Debug)]
pub struct RpcCliArgs {
    #[command(flatten)]
    rpc: RpcArgs,

    #[arg(
        long = "rpc.pool_url",
        name = "rpc.pool_url",
        env = "RPC_POOL_URL",
        default_value = "http://localhost:50051",
        global = true
    )]
    pool_url: String,

    #[arg(
        long = "rpc.builder_url",
        name = "rpc.builder_url",
        env = "RPC_BUILDER_URL",
        default_value = "http://localhost:50052",
        global = true
    )]
    builder_url: String,
}

pub async fn run(rpc_args: RpcCliArgs, common_args: CommonArgs) -> anyhow::Result<()> {
    let RpcCliArgs {
        rpc: rpc_args,
        pool_url,
        builder_url,
    } = rpc_args;

    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let (shutdown_scope, mut shutdown_wait) = mpsc::channel(1);

    let handle = tokio::spawn(rpc::run(
        rpc_args.to_args(&common_args, pool_url, builder_url, (&common_args).into())?,
        shutdown_rx,
        shutdown_scope,
    ));

    tokio::select! {
        res = handle => {
            error!("Rpc server exited unexpectedly: {res:?}");
        }
        res = signal::ctrl_c() => {
            match res {
                Ok(_) => {
                    info!("Received SIGINT, shutting down");
                    shutdown_tx.send(())?;
                    shutdown_wait.recv().await;
                }
                Err(err) => {
                    bail!("Error while waiting for SIGINT: {err:?}");
                }
            }
        }
    }

    shutdown_wait.recv().await;
    Ok(())
}
