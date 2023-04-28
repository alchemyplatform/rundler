use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::Context;
use ethers::{
    providers::{Http, Middleware, Provider, RetryClient},
    types::{Address, TransactionReceipt, H256},
};
use tokio::{join, time};
use tonic::{async_trait, transport::Channel, Request, Response, Status};
use tracing::{
    error,
    log::{debug, info, trace},
};

use crate::{
    builder::bundle_proposer::BundleProposer,
    common::{
        protos::{
            builder::{
                builder_server::Builder, BundlingMode, DebugSendBundleNowRequest,
                DebugSendBundleNowResponse, DebugSetBundlingModeRequest,
                DebugSetBundlingModeResponse,
            },
            op_pool::{
                self, op_pool_client::OpPoolClient, RemoveEntitiesRequest, RemoveOpsRequest,
            },
        },
        types::{EntityType, EntryPointLike, ProviderLike, UserOperation},
    },
};

#[derive(Debug)]
pub struct BuilderImpl<P, E>
where
    P: BundleProposer,
    E: EntryPointLike,
{
    is_manual_bundling_mode: AtomicBool,
    chain_id: u64,
    beneficiary: Address,
    eth_poll_interval: Duration,
    op_pool: OpPoolClient<Channel>,
    proposer: P,
    entry_point: E,
    // TODO: Figure out what we really want to do for detecting new blocks.
    provider: Arc<Provider<RetryClient<Http>>>,
}

impl<P, E> BuilderImpl<P, E>
where
    P: BundleProposer,
    E: EntryPointLike,
{
    pub fn new(
        chain_id: u64,
        beneficiary: Address,
        eth_poll_interval: Duration,
        op_pool: OpPoolClient<Channel>,
        proposer: P,
        entry_point: E,
        provider: Arc<Provider<RetryClient<Http>>>,
    ) -> Self {
        Self {
            is_manual_bundling_mode: AtomicBool::new(false),
            chain_id,
            beneficiary,
            eth_poll_interval,
            op_pool,
            proposer,
            entry_point,
            provider,
        }
    }

    /// Loops forever, attempting to form and send a bundle on each new block,
    /// then waiting for one bundle to be mined or dropped before forming the
    /// next one.
    pub async fn send_bundles_in_loop(&self) -> ! {
        let mut last_block_number = 0;
        loop {
            if self.is_manual_bundling_mode.load(Ordering::Relaxed) {
                time::sleep(self.eth_poll_interval).await;
                continue;
            }
            last_block_number = self.wait_for_new_block(last_block_number).await;
            let result = self.send_bundle_and_wait_for_mine().await;
            match result {
                Ok(Some(receipt)) => info!(
                    "Bundle with hash {:?} landed in block {}",
                    receipt.transaction_hash,
                    receipt.block_number.unwrap_or_default()
                ),
                Ok(None) => trace!("No ops to send at block {last_block_number}"),
                Err(error) => error!("Failed to send bundle. Will retry next block: {error:?}"),
            }
        }
    }

    async fn wait_for_new_block(&self, prev_block_number: u64) -> u64 {
        loop {
            let block_number = self.provider.get_block_number().await;
            match block_number {
                Ok(n) => {
                    let n = n.as_u64();
                    if n > prev_block_number {
                        return n;
                    }
                }
                Err(error) => {
                    error!(
                        "Failed to load latest block number in builder. Will keep trying: {error}"
                    );
                }
            }
            time::sleep(self.eth_poll_interval).await;
        }
    }

    /// Returns `None` if no bundle was sent because it would contain no ops.
    async fn send_bundle_and_wait_for_mine(&self) -> anyhow::Result<Option<TransactionReceipt>> {
        let tx_hash = self.send_bundle().await?;
        let Some(tx_hash) = tx_hash else {
            return Ok(None);
        };
        let receipt = self
            .provider
            .wait_until_mined(tx_hash)
            .await
            .context("builder should wait for bundle to mine")?
            .context("bundle transaction should not be dropped")?;
        Ok(Some(receipt))
    }

    /// Returns `None` if no bundle was sent because it would contain no ops.
    async fn send_bundle(&self) -> anyhow::Result<Option<H256>> {
        let bundle = self
            .proposer
            .make_bundle()
            .await
            .context("proposer should create bundle for builder")?;

        let remove_ops_future = async {
            let result = self.remove_ops_from_pool(&bundle.rejected_ops).await;
            if let Err(error) = result {
                error!("Failed to remove rejected ops from pool: {error}");
            }
        };
        let remove_entities_future = async {
            let result = self
                .remove_entities_from_pool(&bundle.rejected_entities)
                .await;
            if let Err(error) = result {
                error!("Failed to remove rejected entities from pool: {error}");
            }
        };

        if bundle.is_empty() {
            if !bundle.rejected_ops.is_empty() || !bundle.rejected_entities.is_empty() {
                info!(
                    "Empty bundle with {} rejected ops and {} rejected entities. Removing them from pool.",
                    bundle.rejected_ops.len(),
                    bundle.rejected_entities.len()
                );
                join!(remove_ops_future, remove_entities_future);
            }
            return Ok(None);
        }

        info!(
            "Selected bundle with {} op(s), with {} rejected op(s) and {} rejected entities",
            bundle.len(),
            bundle.rejected_ops.len(),
            bundle.rejected_entities.len()
        );
        // Give the estimated gas a 10% overhead to account for inaccuracies.
        let gas = bundle.gas_estimate * 11 / 10;
        let (_, _, send_bundle_result) = join!(
            remove_ops_future,
            remove_entities_future,
            self.entry_point
                .send_bundle(bundle.ops_per_aggregator, self.beneficiary, gas)
        );
        let tx_hash = send_bundle_result.context("builder should send bundle transaction")?;
        info!("Sent bundle in transaction with hash: {}", tx_hash);
        Ok(Some(tx_hash))
    }

    async fn remove_ops_from_pool(&self, ops: &[UserOperation]) -> anyhow::Result<()> {
        self.op_pool
            .clone()
            .remove_ops(RemoveOpsRequest {
                entry_point: self.entry_point.address().as_bytes().to_vec(),
                hashes: ops
                    .iter()
                    .map(|op| self.op_hash(op).as_bytes().to_vec())
                    .collect(),
            })
            .await
            .context("builder should remove rejected ops from pool")?;
        Ok(())
    }

    async fn remove_entities_from_pool(
        &self,
        entities: &[(EntityType, Address)],
    ) -> anyhow::Result<()> {
        self.op_pool
            .clone()
            .remove_entities(RemoveEntitiesRequest {
                entry_point: self.entry_point.address().as_bytes().to_vec(),
                entities: entities
                    .iter()
                    .map(|(e, a)| op_pool::Entity {
                        entity: op_pool::EntityType::from(*e).into(),
                        address: a.as_bytes().to_vec(),
                    })
                    .collect(),
            })
            .await
            .context("builder should remove rejected entities from pool")?;
        Ok(())
    }

    fn op_hash(&self, op: &UserOperation) -> H256 {
        op.op_hash(self.entry_point.address(), self.chain_id)
    }
}

#[async_trait]
impl<P, E> Builder for Arc<BuilderImpl<P, E>>
where
    P: BundleProposer,
    E: EntryPointLike,
{
    async fn debug_send_bundle_now(
        &self,
        _request: Request<DebugSendBundleNowRequest>,
    ) -> tonic::Result<Response<DebugSendBundleNowResponse>> {
        debug!("Send bundle now called");
        let result = self.send_bundle().await;
        let tx_hash = match result {
            Ok(Some(tx_hash)) => tx_hash,
            Ok(None) => return Err(Status::internal("no ops to send")),
            Err(error) => return Err(Status::internal(error.to_string())),
        };
        Ok(Response::new(DebugSendBundleNowResponse {
            transaction_hash: tx_hash.as_bytes().to_vec(),
        }))
    }

    async fn debug_set_bundling_mode(
        &self,
        request: Request<DebugSetBundlingModeRequest>,
    ) -> tonic::Result<Response<DebugSetBundlingModeResponse>> {
        let mode = BundlingMode::from_i32(request.into_inner().mode).unwrap_or_default();
        let is_manual_bundling = match mode {
            BundlingMode::Unspecified => {
                return Err(Status::invalid_argument("invalid bundling mode"))
            }
            BundlingMode::Manual => true,
            BundlingMode::Auto => false,
        };
        self.is_manual_bundling_mode
            .store(is_manual_bundling, Ordering::Relaxed);
        Ok(Response::new(DebugSetBundlingModeResponse {}))
    }
}

/// This stupid type exists because we need to write out some type that
/// implements `Builder` to set up the health reporter, i.e.
///
/// `health_reporter.set_serving::<BuilderService<ANY_BUILDER_HERE>>().await;`
///
/// It doesn't matter what the type is: the type parameter there is only used to
/// read the service name out of `BuilderService` which doesn't depend on the
/// `Builder` impl. But the only other `Builder` impl we have is `BuilderImpl`,
/// which has multiple type parameters whose concrete types themselves need type
/// parameters and is overall extremely nasty to write out. So we make ourselves
/// a non-instantiatable type that implements `Builder` that we can use instead.
pub enum DummyBuilder {}

#[async_trait]
impl Builder for DummyBuilder {
    async fn debug_send_bundle_now(
        &self,
        _request: Request<DebugSendBundleNowRequest>,
    ) -> tonic::Result<Response<DebugSendBundleNowResponse>> {
        panic!()
    }

    async fn debug_set_bundling_mode(
        &self,
        _request: Request<DebugSetBundlingModeRequest>,
    ) -> tonic::Result<Response<DebugSetBundlingModeResponse>> {
        panic!()
    }
}
