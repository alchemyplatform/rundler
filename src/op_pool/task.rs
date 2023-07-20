use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{bail, Context};
use ethers::providers::{
    Http, HttpRateLimitRetryPolicy, JsonRpcClient, Provider, RetryClientBuilder,
};
use futures::future;
use tokio::{
    sync::{broadcast, mpsc},
    task::JoinHandle,
    try_join,
};
use tokio_util::sync::CancellationToken;
use tonic::async_trait;
use url::Url;

use super::{
    mempool::{HourlyMovingAverageReputation, PoolConfig, ReputationParams},
    server::ServerRequest,
};
use crate::{
    common::{
        contracts::i_entry_point::IEntryPoint,
        emit::WithEntryPoint,
        eth, handle,
        handle::Task,
        precheck::{Prechecker, PrecheckerImpl},
        simulation::{Simulator, SimulatorImpl},
    },
    op_pool::{
        chain::{self, Chain, ChainUpdate},
        emit::OpPoolEvent,
        mempool::{uo_pool::UoPool, MempoolGroup},
        server::{spawn_local_mempool_server, spawn_remote_mempool_server},
    },
};

#[derive(Debug)]
pub enum PoolServerMode {
    Local {
        receiver: Option<mpsc::Receiver<ServerRequest>>,
    },
    Remote {
        addr: SocketAddr,
    },
}

#[derive(Debug)]
pub struct Args {
    pub http_url: String,
    pub http_poll_interval: Duration,
    pub chain_id: u64,
    pub chain_history_size: u64,
    pub pool_configs: Vec<PoolConfig>,
    pub server_mode: PoolServerMode,
}

#[derive(Debug)]
pub struct PoolTask {
    args: Args,
    event_sender: broadcast::Sender<WithEntryPoint<OpPoolEvent>>,
}

#[async_trait]
impl Task for PoolTask {
    async fn run(&mut self, shutdown_token: CancellationToken) -> anyhow::Result<()> {
        let chain_id = self.args.chain_id;
        tracing::info!("Chain id: {chain_id}");
        tracing::info!("Http url: {:?}", self.args.http_url);

        // create chain
        let chain_settings = chain::Settings {
            history_size: self.args.chain_history_size,
            poll_interval: self.args.http_poll_interval,
            entry_point_addresses: self
                .args
                .pool_configs
                .iter()
                .map(|config| config.entry_point)
                .collect(),
        };
        let provider = eth::new_provider(&self.args.http_url, self.args.http_poll_interval)?;
        let chain = Chain::new(provider, chain_settings);
        let (update_sender, _) = broadcast::channel(1000);
        let chain_handle = chain.spawn_watcher(update_sender.clone(), shutdown_token.clone());

        let parsed_url = Url::parse(&self.args.http_url).context("Invalid RPC URL")?;
        let http = Http::new(parsed_url);
        // this retry policy will retry on 429ish errors OR connectivity errors
        let client = RetryClientBuilder::default()
            // these retries are if the server returns a 429
            .rate_limit_retries(10)
            // these retries are if the connection is dubious
            .timeout_retries(3)
            .initial_backoff(Duration::from_millis(500))
            .build(http, Box::<HttpRateLimitRetryPolicy>::default());
        let provider = Arc::new(Provider::new(client));

        // create mempools
        let mut mempools = vec![];
        let mut mempool_handles = Vec::new();
        for pool_config in &self.args.pool_configs {
            let (pool, handle) = PoolTask::create_mempool(
                pool_config,
                update_sender.subscribe(),
                self.event_sender.clone(),
                provider.clone(),
                shutdown_token.clone(),
            )
            .await
            .context("should have created mempool")?;

            mempools.push(pool);
            mempool_handles.push(handle);
        }

        // handle to wait for mempools to terminate
        let mempool_handle = tokio::spawn(async move {
            future::join_all(mempool_handles)
                .await
                .into_iter()
                .collect::<Result<Vec<_>, _>>()
                .map(|_| ())
                .context("should have joined mempool handles")
        });

        let mempool_group = MempoolGroup::new(mempools);
        let server_handle = match &mut self.args.server_mode {
            PoolServerMode::Local { ref mut receiver } => {
                let recv = receiver
                    .take()
                    .context("should have local server message receiver")?;
                spawn_local_mempool_server(mempool_group, recv, shutdown_token.clone())?
            }
            PoolServerMode::Remote { addr } => {
                spawn_remote_mempool_server(
                    self.args.chain_id,
                    mempool_group,
                    *addr,
                    shutdown_token.clone(),
                )
                .await?
            }
        };

        tracing::info!("Started op_pool");

        match try_join!(
            handle::flatten_handle(mempool_handle),
            handle::flatten_handle(server_handle),
            handle::as_anyhow_handle(chain_handle),
        ) {
            Ok(_) => {
                tracing::info!("Pool server shutdown");
                Ok(())
            }
            Err(e) => {
                tracing::error!("Pool server error: {e:?}");
                bail!("Pool server error: {e:?}")
            }
        }
    }
}

impl PoolTask {
    pub fn new(
        args: Args,
        event_sender: broadcast::Sender<WithEntryPoint<OpPoolEvent>>,
    ) -> PoolTask {
        Self { args, event_sender }
    }

    pub fn boxed(self) -> Box<dyn Task> {
        Box::new(self)
    }

    async fn create_mempool<C: JsonRpcClient + 'static>(
        pool_config: &PoolConfig,
        update_rx: broadcast::Receiver<Arc<ChainUpdate>>,
        event_sender: broadcast::Sender<WithEntryPoint<OpPoolEvent>>,
        provider: Arc<Provider<C>>,
        shutdown_token: CancellationToken,
    ) -> anyhow::Result<(
        Arc<UoPool<HourlyMovingAverageReputation, impl Prechecker, impl Simulator>>,
        JoinHandle<()>,
    )> {
        // Reputation manager
        let reputation = Arc::new(HourlyMovingAverageReputation::new(
            ReputationParams::bundler_default(),
            pool_config.blocklist.clone(),
            pool_config.allowlist.clone(),
        ));
        // Start reputation manager
        let reputation_runner = Arc::clone(&reputation);
        tokio::spawn(async move { reputation_runner.run().await });

        let i_entry_point = IEntryPoint::new(pool_config.entry_point, Arc::clone(&provider));
        let prechecker = PrecheckerImpl::new(
            Arc::clone(&provider),
            pool_config.chain_id,
            i_entry_point.clone(),
            pool_config.precheck_settings,
        );
        let simulator = SimulatorImpl::new(
            Arc::clone(&provider),
            i_entry_point,
            pool_config.sim_settings,
            pool_config.mempool_channel_configs.clone(),
        );

        // Mempool
        let mp = Arc::new(UoPool::new(
            pool_config.clone(),
            Arc::clone(&reputation),
            event_sender,
            prechecker,
            simulator,
        ));
        let mp_runner = Arc::clone(&mp);
        let handle =
            tokio::spawn(async move { mp_runner.run(update_rx, shutdown_token.clone()).await });

        Ok((mp, handle))
    }
}
