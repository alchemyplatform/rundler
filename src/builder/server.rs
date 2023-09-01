use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{bail, Context};
use ethers::types::{transaction::eip2718::TypedTransaction, Address, H256, U256};
use tokio::{join, sync::broadcast, time};
use tonic::{async_trait, transport::Channel, Request, Response, Status};
use tracing::{debug, error, info, trace, warn};

use crate::{
    builder::{
        bundle_proposer::BundleProposer,
        emit::{BuilderEvent, BundleTxDetails},
        transaction_tracker::{SendResult, TrackerUpdate, TransactionTracker},
    },
    common::{
        block_watcher,
        emit::WithEntryPoint,
        gas::GasFees,
        math,
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
        types::{Entity, EntryPointLike, ExpectedStorage, ProviderLike, UserOperation},
    },
};

// Overhead on gas estimates to account for inaccuracies.
const GAS_ESTIMATE_OVERHEAD_PERCENT: u64 = 10;

#[derive(Debug)]
pub struct Settings {
    pub replacement_fee_percent_increase: u64,
    pub max_fee_increases: u64,
}

#[derive(Debug)]
pub struct BuilderImpl<P, PL, E, T>
where
    P: BundleProposer,
    PL: ProviderLike,
    E: EntryPointLike,
    T: TransactionTracker,
{
    is_manual_bundling_mode: AtomicBool,
    chain_id: u64,
    beneficiary: Address,
    eth_poll_interval: Duration,
    op_pool: OpPoolClient<Channel>,
    proposer: P,
    entry_point: E,
    transaction_tracker: T,
    // TODO: Figure out what we really want to do for detecting new blocks.
    provider: Arc<PL>,
    settings: Settings,
    event_sender: broadcast::Sender<WithEntryPoint<BuilderEvent>>,
}

#[derive(Debug)]
struct BundleTx {
    tx: TypedTransaction,
    expected_storage: ExpectedStorage,
    op_hashes: Vec<H256>,
}

#[derive(Debug)]
enum SendBundleResult {
    Success {
        block_number: u64,
        attempt_number: u64,
        tx_hash: H256,
    },
    NoOperationsInitially,
    NoOperationsAfterFeeIncreases {
        initial_op_count: usize,
        attempt_number: u64,
    },
    StalledAtMaxFeeIncreases,
    Error(anyhow::Error),
}

impl<P, PL, E, T> BuilderImpl<P, PL, E, T>
where
    P: BundleProposer,
    PL: ProviderLike,
    E: EntryPointLike,
    T: TransactionTracker,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: u64,
        beneficiary: Address,
        eth_poll_interval: Duration,
        op_pool: OpPoolClient<Channel>,
        proposer: P,
        entry_point: E,
        transaction_tracker: T,
        provider: Arc<PL>,
        settings: Settings,
        event_sender: broadcast::Sender<WithEntryPoint<BuilderEvent>>,
    ) -> Self {
        Self {
            is_manual_bundling_mode: AtomicBool::new(false),
            chain_id,
            beneficiary,
            eth_poll_interval,
            op_pool,
            proposer,
            entry_point,
            transaction_tracker,
            provider,
            settings,
            event_sender,
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
            last_block_number = block_watcher::wait_for_new_block_number(
                &*self.provider,
                last_block_number,
                self.eth_poll_interval,
            )
            .await;
            self.check_for_and_log_transaction_update().await;
            let result = self.send_bundle_with_increasing_gas_fees().await;
            match result {
                SendBundleResult::Success {
                    block_number,
                    attempt_number,
                    tx_hash,
                } =>
                    if attempt_number == 0 {
                        info!("Bundle with hash {tx_hash:?} landed in block {block_number}");
                    } else {
                        info!("Bundle with hash {tx_hash:?} landed in block {block_number} after increasing gas fees {attempt_number} time(s)");
                    }
                SendBundleResult::NoOperationsInitially => trace!("No ops to send at block {last_block_number}"),
                SendBundleResult::NoOperationsAfterFeeIncreases {
                    initial_op_count,
                    attempt_number,
                } => info!("Bundle initially had {initial_op_count} operations, but after increasing gas fees {attempt_number} time(s) it was empty"),
                SendBundleResult::StalledAtMaxFeeIncreases => warn!("Bundle failed to mine after {} fee increases", self.settings.max_fee_increases),
                SendBundleResult::Error(error) => {
                    BuilderMetrics::increment_bundle_txns_failed();
                    error!("Failed to send bundle. Will retry next block: {error:#?}");
                }
            }
        }
    }

    async fn check_for_and_log_transaction_update(&self) {
        let update = self.transaction_tracker.check_for_update_now().await;
        let update = match update {
            Ok(update) => update,
            Err(error) => {
                error!("Failed to check for transaction updates: {error:#?}");
                return;
            }
        };
        let Some(update) = update else {
            return;
        };
        match update {
            TrackerUpdate::Mined {
                tx_hash,
                block_number,
                attempt_number,
                ..
            } => {
                BuilderMetrics::increment_bundle_txns_success();
                if attempt_number == 0 {
                    info!("Bundle with hash {tx_hash:?} landed in block {block_number}");
                } else {
                    info!("Bundle with hash {tx_hash:?} landed in block {block_number} after increasing gas fees {attempt_number} time(s)");
                }
            }
            TrackerUpdate::StillPendingAfterWait => (),
            TrackerUpdate::LatestTxDropped { nonce } => {
                self.emit(BuilderEvent::LatestTransactionDropped {
                    nonce: nonce.low_u64(),
                });
                BuilderMetrics::increment_bundle_txns_dropped();
                info!("Previous transaction dropped by sender");
            }
            TrackerUpdate::NonceUsedForOtherTx { nonce } => {
                self.emit(BuilderEvent::NonceUsedForOtherTransaction {
                    nonce: nonce.low_u64(),
                });
                BuilderMetrics::increment_bundle_txns_nonce_used();
                info!("Nonce used by external transaction")
            }
        };
    }

    /// Constructs a bundle and sends it to the entry point as a transaction. If
    /// the bundle fails to be mined after
    /// `settings.max_blocks_to_wait_for_mine` blocks, increases the gas fees by
    /// enough to send a replacement transaction, then constructs a new bundle
    /// using the new, higher gas requirements. Continues to retry with higher
    /// gas costs until one of the following happens:
    ///
    /// 1. A transaction succeeds (not necessarily the most recent one)
    /// 2. The gas fees are high enough that the bundle is empty because there
    ///    are no ops that meet the fee requirements.
    /// 3. The transaction has not succeeded after `settings.max_fee_increases`
    ///    replacements.
    async fn send_bundle_with_increasing_gas_fees(&self) -> SendBundleResult {
        let result = self.send_bundle_with_increasing_gas_fees_inner().await;
        match result {
            Ok(result) => result,
            Err(error) => SendBundleResult::Error(error),
        }
    }

    /// Helper function returning `Result` to be able to use `?`.
    async fn send_bundle_with_increasing_gas_fees_inner(&self) -> anyhow::Result<SendBundleResult> {
        let (nonce, mut required_fees) = self.transaction_tracker.get_nonce_and_required_fees()?;
        let mut initial_op_count: Option<usize> = None;
        for fee_increase_count in 0..=self.settings.max_fee_increases {
            let Some(bundle_tx) = self.get_bundle_tx(nonce, required_fees).await? else {
                self.emit(BuilderEvent::FormedBundle {
                    tx_details: None,
                    nonce: nonce.low_u64(),
                    fee_increase_count,
                    required_fees,
                });
                return Ok(match initial_op_count {
                    Some(initial_op_count) => {
                        BuilderMetrics::increment_bundle_txns_abandoned();
                        SendBundleResult::NoOperationsAfterFeeIncreases {
                            initial_op_count,
                            attempt_number: fee_increase_count,
                        }
                    }
                    None => SendBundleResult::NoOperationsInitially,
                });
            };
            let BundleTx {
                tx,
                expected_storage,
                op_hashes,
            } = bundle_tx;
            if initial_op_count.is_none() {
                initial_op_count = Some(op_hashes.len());
            }
            let current_fees = GasFees::from(&tx);

            BuilderMetrics::increment_bundle_txns_sent();
            BuilderMetrics::set_current_fees(&current_fees);

            let send_result = self
                .transaction_tracker
                .send_transaction(tx.clone(), &expected_storage)
                .await?;
            let update = match send_result {
                SendResult::TrackerUpdate(update) => update,
                SendResult::TxHash(tx_hash) => {
                    self.emit(BuilderEvent::FormedBundle {
                        tx_details: Some(BundleTxDetails {
                            tx_hash,
                            tx,
                            op_hashes: Arc::new(op_hashes),
                        }),
                        nonce: nonce.low_u64(),
                        fee_increase_count,
                        required_fees,
                    });
                    self.transaction_tracker.wait_for_update().await?
                }
            };
            match update {
                TrackerUpdate::Mined {
                    tx_hash,
                    nonce,
                    gas_fees: _,
                    block_number,
                    attempt_number,
                } => {
                    self.emit(BuilderEvent::TransactionMined {
                        tx_hash,
                        nonce: nonce.low_u64(),
                        block_number,
                    });
                    BuilderMetrics::increment_bundle_txns_success();
                    return Ok(SendBundleResult::Success {
                        block_number,
                        attempt_number,
                        tx_hash,
                    });
                }
                TrackerUpdate::StillPendingAfterWait => {
                    info!("Transaction not mined for several blocks")
                }
                TrackerUpdate::LatestTxDropped { nonce } => {
                    self.emit(BuilderEvent::LatestTransactionDropped {
                        nonce: nonce.low_u64(),
                    });
                    BuilderMetrics::increment_bundle_txns_dropped();
                    info!("Previous transaction dropped by sender");
                }
                TrackerUpdate::NonceUsedForOtherTx { nonce } => {
                    self.emit(BuilderEvent::NonceUsedForOtherTransaction {
                        nonce: nonce.low_u64(),
                    });
                    BuilderMetrics::increment_bundle_txns_nonce_used();
                    bail!("nonce used by external transaction")
                }
            };
            info!(
                "Bundle transaction failed to mine after {fee_increase_count} fee increases (maxFeePerGas: {}, maxPriorityFeePerGas: {}).",
                current_fees.max_fee_per_gas,
                current_fees.max_priority_fee_per_gas,
            );
            BuilderMetrics::increment_bundle_txn_fee_increases();
            required_fees = Some(
                current_fees.increase_by_percent(self.settings.replacement_fee_percent_increase),
            );
        }
        BuilderMetrics::increment_bundle_txns_abandoned();
        Ok(SendBundleResult::StalledAtMaxFeeIncreases)
    }

    /// Builds a bundle and returns some metadata and the transaction to send
    /// it, or `None` if there are no valid operations available.
    async fn get_bundle_tx(
        &self,
        nonce: U256,
        required_fees: Option<GasFees>,
    ) -> anyhow::Result<Option<BundleTx>> {
        let bundle = self
            .proposer
            .make_bundle(required_fees)
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
        join!(remove_ops_future, remove_entities_future);
        if bundle.is_empty() {
            if !bundle.rejected_ops.is_empty() || !bundle.rejected_entities.is_empty() {
                info!(
                "Empty bundle with {} rejected ops and {} rejected entities. Removing them from pool.",
                bundle.rejected_ops.len(),
                bundle.rejected_entities.len()
            );
            }
            return Ok(None);
        }
        info!(
            "Selected bundle with {} op(s), with {} rejected op(s) and {} rejected entities",
            bundle.len(),
            bundle.rejected_ops.len(),
            bundle.rejected_entities.len()
        );
        let gas = math::increase_by_percent(bundle.gas_estimate, GAS_ESTIMATE_OVERHEAD_PERCENT);
        let op_hashes: Vec<_> = bundle.iter_ops().map(|op| self.op_hash(op)).collect();
        let mut tx = self.entry_point.get_send_bundle_transaction(
            bundle.ops_per_aggregator,
            self.beneficiary,
            gas,
            bundle.gas_fees,
        );
        tx.set_nonce(nonce);
        Ok(Some(BundleTx {
            tx,
            expected_storage: bundle.expected_storage,
            op_hashes,
        }))
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

    async fn remove_entities_from_pool(&self, entities: &[Entity]) -> anyhow::Result<()> {
        self.op_pool
            .clone()
            .remove_entities(RemoveEntitiesRequest {
                entry_point: self.entry_point.address().as_bytes().to_vec(),
                entities: entities.iter().map(op_pool::Entity::from).collect(),
            })
            .await
            .context("builder should remove rejected entities from pool")?;
        Ok(())
    }

    fn op_hash(&self, op: &UserOperation) -> H256 {
        op.op_hash(self.entry_point.address(), self.chain_id)
    }

    fn emit(&self, event: BuilderEvent) {
        let _ = self.event_sender.send(WithEntryPoint {
            entry_point: self.entry_point.address(),
            event,
        });
    }
}

#[async_trait]
impl<P, PL, E, T> Builder for Arc<BuilderImpl<P, PL, E, T>>
where
    P: BundleProposer,
    PL: ProviderLike,
    E: EntryPointLike,
    T: TransactionTracker,
{
    async fn debug_send_bundle_now(
        &self,
        _request: Request<DebugSendBundleNowRequest>,
    ) -> tonic::Result<Response<DebugSendBundleNowResponse>> {
        debug!("Send bundle now called");
        let result = self.send_bundle_with_increasing_gas_fees().await;
        let tx_hash = match result {
            SendBundleResult::Success { tx_hash, .. } => tx_hash,
            SendBundleResult::NoOperationsInitially => {
                return Err(Status::internal("no ops to send"))
            }
            SendBundleResult::NoOperationsAfterFeeIncreases { .. } => {
                return Err(Status::internal(
                    "bundle initially had operations, but after increasing gas fees it was empty",
                ))
            }
            SendBundleResult::StalledAtMaxFeeIncreases => return Err(Status::internal("")),
            SendBundleResult::Error(error) => return Err(Status::internal(error.to_string())),
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

struct BuilderMetrics {}

impl BuilderMetrics {
    fn increment_bundle_txns_sent() {
        metrics::increment_counter!("builder_bundle_txns_sent");
    }

    fn increment_bundle_txns_success() {
        metrics::increment_counter!("builder_bundle_txns_success");
    }

    fn increment_bundle_txns_dropped() {
        metrics::increment_counter!("builder_bundle_txns_dropped");
    }

    // used when we decide to stop trying a transaction
    fn increment_bundle_txns_abandoned() {
        metrics::increment_counter!("builder_bundle_txns_abandoned");
    }

    // used when sending a transaction fails
    fn increment_bundle_txns_failed() {
        metrics::increment_counter!("builder_bundle_txns_failed");
    }

    fn increment_bundle_txns_nonce_used() {
        metrics::increment_counter!("builder_bundle_txns_nonce_used");
    }

    fn increment_bundle_txn_fee_increases() {
        metrics::increment_counter!("builder_bundle_fee_increases");
    }

    fn set_current_fees(fees: &GasFees) {
        metrics::gauge!(
            "builder_current_max_fee",
            fees.max_fee_per_gas.as_u128() as f64
        );
        metrics::gauge!(
            "builder_current_max_priority_fee",
            fees.max_priority_fee_per_gas.as_u128() as f64
        );
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
    #[allow(clippy::diverging_sub_expression)]
    async fn debug_send_bundle_now(
        &self,
        _request: Request<DebugSendBundleNowRequest>,
    ) -> tonic::Result<Response<DebugSendBundleNowResponse>> {
        panic!()
    }

    #[allow(clippy::diverging_sub_expression)]
    async fn debug_set_bundling_mode(
        &self,
        _request: Request<DebugSetBundlingModeRequest>,
    ) -> tonic::Result<Response<DebugSetBundlingModeResponse>> {
        panic!()
    }
}
