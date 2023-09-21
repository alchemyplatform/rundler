use std::{
    collections::HashMap,
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};

use anyhow::{bail, Context};
use ethers::{
    providers::{JsonRpcClient, Provider},
    types::{Address, H256},
};
use ethers_signers::Signer;
use futures::future;
use futures_util::TryFutureExt;
use rusoto_core::Region;
use tokio::{
    select,
    sync::{broadcast, mpsc},
    task::JoinHandle,
    time, try_join,
};
use tokio_util::sync::CancellationToken;
use tonic::{
    async_trait,
    transport::{Channel, Server},
};
use tracing::info;

use super::bundle_sender::SendBundleRequest;
use crate::{
    builder::{
        self,
        bundle_proposer::{self, BundleProposerImpl},
        bundle_sender::BundleSender,
        emit::BuilderEvent,
        sender::get_sender,
        server::{BuilderImpl, DummyBuilder},
        signer::{BundlerSigner, KmsSigner, LocalSigner},
        transaction_tracker::{self, TransactionTrackerImpl},
    },
    common::{
        contracts::i_entry_point::IEntryPoint,
        emit::WithEntryPoint,
        eth,
        gas::PriorityFeeMode,
        handle::Task,
        mempool::MempoolConfig,
        protos::{
            builder::{builder_server::BuilderServer, BUILDER_FILE_DESCRIPTOR_SET},
            op_pool::op_pool_client::OpPoolClient,
        },
        server::{self, format_socket_addr},
        simulation::{self, SimulatorImpl},
    },
};

#[derive(Debug)]
pub struct Args {
    pub port: u16,
    pub host: String,
    pub rpc_url: String,
    pub pool_url: String,
    pub entry_point_address: Address,
    pub private_key: Option<String>,
    pub aws_kms_key_ids: Vec<String>,
    pub aws_kms_region: Region,
    pub redis_uri: String,
    pub redis_lock_ttl_millis: u64,
    pub chain_id: u64,
    pub max_bundle_size: u64,
    pub max_bundle_gas: u64,
    pub submit_url: String,
    pub use_bundle_priority_fee: Option<bool>,
    pub bundle_priority_fee_overhead_percent: u64,
    pub priority_fee_mode: PriorityFeeMode,
    pub use_conditional_send_transaction: bool,
    pub eth_poll_interval: Duration,
    pub sim_settings: simulation::Settings,
    pub mempool_configs: HashMap<H256, MempoolConfig>,
    pub max_blocks_to_wait_for_mine: u64,
    pub replacement_fee_percent_increase: u64,
    pub max_fee_increases: u64,
    pub num_bundle_builders: u64,
    pub bundle_builder_id_offset: u64,
}

#[derive(Debug)]
pub struct BuilderTask {
    args: Args,
    event_sender: broadcast::Sender<WithEntryPoint<BuilderEvent>>,
}

#[async_trait]
impl Task for BuilderTask {
    async fn run(&self, shutdown_token: CancellationToken) -> anyhow::Result<()> {
        let addr = format_socket_addr(&self.args.host, self.args.port).parse()?;
        info!("Starting builder server on {}", addr);
        tracing::info!("Mempool config: {:?}", self.args.mempool_configs);

        let provider = eth::new_provider(&self.args.rpc_url, self.args.eth_poll_interval)?;
        let manual_bundling_mode = Arc::new(AtomicBool::new(false));

        let mut sender_handles = vec![];
        let mut send_bundle_txs = vec![];
        for i in 0..self.args.num_bundle_builders {
            let (spawn_guard, send_bundle_tx) = self
                .create_bundle_sender(
                    i + self.args.bundle_builder_id_offset,
                    Arc::clone(&manual_bundling_mode),
                    Arc::clone(&provider),
                    shutdown_token.clone(),
                )
                .await?;
            sender_handles.push(spawn_guard);
            send_bundle_txs.push(send_bundle_tx);
        }
        // flatten the senders handles to one handle, short-circuit on errors
        let sender_handle = tokio::spawn(
            future::try_join_all(sender_handles)
                .map_ok(|_| ())
                .map_err(|e| anyhow::anyhow!(e)),
        );

        // gRPC server
        let builder = BuilderImpl::new(manual_bundling_mode, send_bundle_txs);
        let builder_server = BuilderServer::new(builder);

        let reflection_service = tonic_reflection::server::Builder::configure()
            .register_encoded_file_descriptor_set(BUILDER_FILE_DESCRIPTOR_SET)
            .build()?;

        // health service
        let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
        health_reporter
            .set_serving::<BuilderServer<DummyBuilder>>()
            .await;

        let server_handle = tokio::spawn(
            Server::builder()
                .add_service(builder_server)
                .add_service(reflection_service)
                .add_service(health_service)
                .serve_with_shutdown(addr, async move { shutdown_token.cancelled().await }),
        );

        info!("Started bundle builder");

        match try_join!(server_handle, sender_handle) {
            Ok(_) => {
                tracing::info!("Builder server shutdown");
                Ok(())
            }
            Err(e) => {
                tracing::error!("Builder server error: {:?}", e);
                Err(e).context("Builder server error")
            }
        }
    }
}

impl BuilderTask {
    pub fn new(
        args: Args,
        event_sender: broadcast::Sender<WithEntryPoint<BuilderEvent>>,
    ) -> BuilderTask {
        Self { args, event_sender }
    }

    pub fn boxed(self) -> Box<dyn Task> {
        Box::new(self)
    }

    async fn connect_client_with_shutdown(
        op_pool_url: &str,
        shutdown_token: CancellationToken,
    ) -> anyhow::Result<OpPoolClient<Channel>> {
        select! {
            _ = shutdown_token.cancelled() => {
                tracing::error!("bailing from connecting client, server shutting down");
                bail!("Server shutting down")
            }
            res = server::connect_with_retries("op pool from builder", op_pool_url, OpPoolClient::connect) => {
                res
            }
        }
    }

    async fn create_bundle_sender<C: JsonRpcClient + 'static>(
        &self,
        id: u64,
        manual_bundling_mode: Arc<AtomicBool>,
        provider: Arc<Provider<C>>,
        shutdown_token: CancellationToken,
    ) -> anyhow::Result<(JoinHandle<()>, mpsc::Sender<SendBundleRequest>)> {
        let signer = if let Some(pk) = &self.args.private_key {
            info!("Using local signer");
            BundlerSigner::Local(
                LocalSigner::connect(Arc::clone(&provider), self.args.chain_id, pk.to_owned())
                    .await?,
            )
        } else {
            info!("Using AWS KMS signer");
            let signer = time::timeout(
                // timeout must be << than the lock TTL to avoid a
                // bug in the redis lock implementation that panics if connection
                // takes longer than the TTL. Generally the TLL should be on the order of 10s of seconds
                // so this should give ample time for the connection to establish.
                Duration::from_millis(self.args.redis_lock_ttl_millis / 10),
                KmsSigner::connect(
                    Arc::clone(&provider),
                    self.args.chain_id,
                    self.args.aws_kms_region.clone(),
                    self.args.aws_kms_key_ids.clone(),
                    self.args.redis_uri.clone(),
                    self.args.redis_lock_ttl_millis,
                ),
            )
            .await
            .context("timeout connecting to KMS")?
            .context("failure connecting to KMS")?;
            let ret = BundlerSigner::Kms(signer);
            info!("Created AWS KMS signer");
            ret
        };
        let beneficiary = signer.address();
        let proposer_settings = bundle_proposer::Settings {
            chain_id: self.args.chain_id,
            max_bundle_size: self.args.max_bundle_size,
            max_bundle_gas: self.args.max_bundle_gas,
            beneficiary,
            use_bundle_priority_fee: self.args.use_bundle_priority_fee,
            priority_fee_mode: self.args.priority_fee_mode,
            bundle_priority_fee_overhead_percent: self.args.bundle_priority_fee_overhead_percent,
        };
        let op_pool =
            Self::connect_client_with_shutdown(&self.args.pool_url, shutdown_token.clone()).await?;

        let entry_point = IEntryPoint::new(self.args.entry_point_address, Arc::clone(&provider));
        let simulator = SimulatorImpl::new(
            Arc::clone(&provider),
            entry_point.clone(),
            self.args.sim_settings,
            self.args.mempool_configs.clone(),
        );

        let proposer = BundleProposerImpl::new(
            id,
            op_pool.clone(),
            simulator,
            entry_point.clone(),
            Arc::clone(&provider),
            proposer_settings,
            self.event_sender.clone(),
        );
        let submit_provider =
            eth::new_provider(&self.args.submit_url, self.args.eth_poll_interval)?;
        let transaction_sender = get_sender(
            submit_provider,
            signer,
            self.args.use_conditional_send_transaction,
            &self.args.submit_url,
        );
        let tracker_settings = transaction_tracker::Settings {
            poll_interval: self.args.eth_poll_interval,
            max_blocks_to_wait_for_mine: self.args.max_blocks_to_wait_for_mine,
            replacement_fee_percent_increase: self.args.replacement_fee_percent_increase,
        };
        let transaction_tracker = TransactionTrackerImpl::new(
            Arc::clone(&provider),
            transaction_sender,
            tracker_settings,
        )
        .await?;

        let builder_settings = builder::bundle_sender::Settings {
            replacement_fee_percent_increase: self.args.replacement_fee_percent_increase,
            max_fee_increases: self.args.max_fee_increases,
        };

        let (send_bundle_tx, send_bundle_rx) = mpsc::channel(1);

        let bundle_sender = BundleSender::new(
            id,
            manual_bundling_mode.clone(),
            send_bundle_rx,
            self.args.chain_id,
            beneficiary,
            self.args.eth_poll_interval,
            op_pool,
            proposer,
            entry_point,
            transaction_tracker,
            provider,
            builder_settings,
            self.event_sender.clone(),
        );

        Ok((
            tokio::spawn(bundle_sender.send_bundles_in_loop()),
            send_bundle_tx,
        ))
    }
}
