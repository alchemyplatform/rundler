use anyhow::bail;
use clap::Args;
use tokio::{signal, sync::broadcast, sync::mpsc};
use tracing::{error, info};

use crate::{builder, common::server::format_server_addr};

use super::CommonArgs;

/// CLI options for the builder
#[derive(Args, Debug)]
#[command(next_help_heading = "BUILDER")]
pub struct BuilderArgs {
    /// Port to listen on for gRPC requests
    #[arg(
        long = "builder.port",
        name = "builder.port",
        env = "BUILDER_PORT",
        default_value = "50052"
    )]
    port: u16,

    /// Host to listen on for gRPC requests
    #[arg(
        long = "builder.host",
        name = "builder.host",
        env = "BUILDER_HOST",
        default_value = "127.0.0.1"
    )]
    host: String,
}

impl BuilderArgs {
    /// Convert the CLI arguments into the arguments for the builder combining
    /// common and builder specific arguments.
    pub fn to_args(
        &self,
        _common: &CommonArgs,
        _pool_url: String,
    ) -> anyhow::Result<builder::Args> {
        Ok(builder::Args {
            port: self.port,
            host: self.host.clone(),
        })
    }

    pub fn url(&self, secure: bool) -> String {
        format_server_addr(&self.host, self.port, secure)
    }
}

/// CLI options for the Builder server standalone
#[derive(Args, Debug)]
pub struct BuilderCliArgs {
    #[command(flatten)]
    builder: BuilderArgs,

    #[arg(
        long = "builder.pool_url",
        name = "builder.pool_url",
        env = "BUILDER_POOL_URL",
        default_value = "http://localhost:50051",
        global = true
    )]
    pool_url: String,
}

pub async fn run(builder_args: BuilderCliArgs, common_args: CommonArgs) -> anyhow::Result<()> {
    let BuilderCliArgs {
        builder: builder_args,
        pool_url,
    } = builder_args;

    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let (shutdown_scope, mut shutdown_wait) = mpsc::channel(1);

    let handle = tokio::spawn(builder::run(
        builder_args.to_args(&common_args, pool_url)?,
        shutdown_rx,
        shutdown_scope,
    ));

    tokio::select! {
        res = handle => {
            error!("Pool server exited unexpectedly: {res:?}");
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
