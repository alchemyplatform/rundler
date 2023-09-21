use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{bail, Context};
use async_trait::async_trait;
use ethers::types::{transaction::eip2718::TypedTransaction, Address, H256, U256};
use futures_util::StreamExt;
use rundler_pool::PoolServer;
use rundler_provider::EntryPoint;
use rundler_sim::ExpectedStorage;
use rundler_types::{Entity, GasFees, UserOperation};
use rundler_utils::emit::WithEntryPoint;
use tokio::{
    join,
    sync::{broadcast, mpsc, oneshot},
    time,
};
use tracing::{error, info, trace, warn};

use crate::{
    bundle_proposer::BundleProposer,
    emit::{BuilderEvent, BundleTxDetails},
    transaction_tracker::{SendResult, TrackerUpdate, TransactionTracker},
};

#[async_trait]
pub(crate) trait BundleSender: Send + Sync + 'static {
    async fn send_bundles_in_loop(self) -> anyhow::Result<()>;
}

#[derive(Debug)]
pub(crate) struct Settings {
    pub(crate) replacement_fee_percent_increase: u64,
    pub(crate) max_fee_increases: u64,
}

#[derive(Debug)]
pub(crate) struct BundleSenderImpl<P, E, T, C>
where
    P: BundleProposer,
    E: EntryPoint,
    T: TransactionTracker,
    C: PoolServer,
{
    builder_index: u64,
    manual_bundling_mode: Arc<AtomicBool>,
    send_bundle_receiver: mpsc::Receiver<SendBundleRequest>,
    chain_id: u64,
    beneficiary: Address,
    eth_poll_interval: Duration,
    proposer: P,
    entry_point: E,
    transaction_tracker: T,
    pool: C,
    settings: Settings,
    event_sender: broadcast::Sender<WithEntryPoint<BuilderEvent>>,
}

#[derive(Debug)]
struct BundleTx {
    tx: TypedTransaction,
    expected_storage: ExpectedStorage,
    op_hashes: Vec<H256>,
}

pub struct SendBundleRequest {
    pub responder: oneshot::Sender<SendBundleResult>,
}

#[derive(Debug)]
pub enum SendBundleResult {
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

#[async_trait]
impl<P, E, T, C> BundleSender for BundleSenderImpl<P, E, T, C>
where
    P: BundleProposer,
    E: EntryPoint,
    T: TransactionTracker,
    C: PoolServer,
{
    /// Loops forever, attempting to form and send a bundle on each new block,
    /// then waiting for one bundle to be mined or dropped before forming the
    /// next one.
    async fn send_bundles_in_loop(mut self) -> anyhow::Result<()> {
        let Ok(mut new_heads) = self.pool.subscribe_new_heads().await else {
            error!("Failed to subscribe to new blocks");
            bail!("failed to subscribe to new blocks");
        };

        // The new_heads stream can buffer up multiple blocks, but we only want to consume the latest one.
        // This task is used to consume the new heads and place them onto a channel that can be syncronously
        // consumed until the latest block is reached.
        let (tx, mut rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                match new_heads.next().await {
                    Some(b) => {
                        if tx.send(b).is_err() {
                            error!("Failed to buffer new block for bundle sender");
                            return;
                        }
                    }
                    None => {
                        error!("Block stream ended");
                        return;
                    }
                }
            }
        });

        loop {
            let mut send_bundle_response: Option<oneshot::Sender<SendBundleResult>> = None;

            if self.manual_bundling_mode.load(Ordering::Relaxed) {
                tokio::select! {
                    Some(r) = self.send_bundle_receiver.recv() => {
                        send_bundle_response = Some(r.responder);
                    }
                    _ = time::sleep(self.eth_poll_interval) => {
                        continue;
                    }
                }
            }

            // Wait for new block. Block number doesn't matter as the pool will only notify of new blocks
            // after the pool has updated its state. The bundle will be formed using the latest pool state
            // and can land in the next block
            let mut last_block = match rx.recv().await {
                Some(b) => b,
                None => {
                    error!("Block stream closed");
                    bail!("Block stream closed");
                }
            };
            // Consume any other blocks that may have been buffered up
            loop {
                match rx.try_recv() {
                    Ok(b) => {
                        last_block = b;
                    }
                    Err(mpsc::error::TryRecvError::Empty) => {
                        break;
                    }
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        error!("Block stream closed");
                        bail!("Block stream closed");
                    }
                }
            }

            self.check_for_and_log_transaction_update().await;
            let result = self.send_bundle_with_increasing_gas_fees().await;
            match &result {
                SendBundleResult::Success {
                    block_number,
                    attempt_number,
                    tx_hash,
                } =>
                    if *attempt_number == 0 {
                        info!("Bundle with hash {tx_hash:?} landed in block {block_number}");
                    } else {
                        info!("Bundle with hash {tx_hash:?} landed in block {block_number} after increasing gas fees {attempt_number} time(s)");
                    }
                SendBundleResult::NoOperationsInitially => trace!("No ops to send at block {}", last_block.block_number),
                SendBundleResult::NoOperationsAfterFeeIncreases {
                    initial_op_count,
                    attempt_number,
                } => info!("Bundle initially had {initial_op_count} operations, but after increasing gas fees {attempt_number} time(s) it was empty"),
                SendBundleResult::StalledAtMaxFeeIncreases => warn!("Bundle failed to mine after {} fee increases", self.settings.max_fee_increases),
                SendBundleResult::Error(error) => {
                    BuilderMetrics::increment_bundle_txns_failed(self.builder_index);
                    error!("Failed to send bundle. Will retry next block: {error:#?}");
                }
            }

            if let Some(t) = send_bundle_response.take() {
                if t.send(result).is_err() {
                    error!("Failed to send bundle result to manual caller");
                }
            }
        }
    }
}

impl<P, E, T, C> BundleSenderImpl<P, E, T, C>
where
    P: BundleProposer,
    E: EntryPoint,
    T: TransactionTracker,
    C: PoolServer,
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        builder_index: u64,
        manual_bundling_mode: Arc<AtomicBool>,
        send_bundle_receiver: mpsc::Receiver<SendBundleRequest>,
        chain_id: u64,
        beneficiary: Address,
        eth_poll_interval: Duration,
        proposer: P,
        entry_point: E,
        transaction_tracker: T,
        pool: C,
        settings: Settings,
        event_sender: broadcast::Sender<WithEntryPoint<BuilderEvent>>,
    ) -> Self {
        Self {
            builder_index,
            manual_bundling_mode,
            send_bundle_receiver,
            chain_id,
            beneficiary,
            eth_poll_interval,
            proposer,
            entry_point,
            transaction_tracker,
            pool,
            settings,
            event_sender,
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
                BuilderMetrics::increment_bundle_txns_success(self.builder_index);
                if attempt_number == 0 {
                    info!("Bundle with hash {tx_hash:?} landed in block {block_number}");
                } else {
                    info!("Bundle with hash {tx_hash:?} landed in block {block_number} after increasing gas fees {attempt_number} time(s)");
                }
            }
            TrackerUpdate::StillPendingAfterWait => (),
            TrackerUpdate::LatestTxDropped { nonce } => {
                self.emit(BuilderEvent::latest_transaction_dropped(
                    self.builder_index,
                    nonce.low_u64(),
                ));
                BuilderMetrics::increment_bundle_txns_dropped(self.builder_index);
                info!("Previous transaction dropped by sender");
            }
            TrackerUpdate::NonceUsedForOtherTx { nonce } => {
                self.emit(BuilderEvent::nonce_used_for_other_transaction(
                    self.builder_index,
                    nonce.low_u64(),
                ));
                BuilderMetrics::increment_bundle_txns_nonce_used(self.builder_index);
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
                self.emit(BuilderEvent::formed_bundle(
                    self.builder_index,
                    None,
                    nonce.low_u64(),
                    fee_increase_count,
                    required_fees,
                ));
                return Ok(match initial_op_count {
                    Some(initial_op_count) => {
                        BuilderMetrics::increment_bundle_txns_abandoned(self.builder_index);
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

            BuilderMetrics::increment_bundle_txns_sent(self.builder_index);
            BuilderMetrics::set_current_fees(&current_fees);

            let send_result = self
                .transaction_tracker
                .send_transaction(tx.clone(), &expected_storage)
                .await?;
            let update = match send_result {
                SendResult::TrackerUpdate(update) => update,
                SendResult::TxHash(tx_hash) => {
                    self.emit(BuilderEvent::formed_bundle(
                        self.builder_index,
                        Some(BundleTxDetails {
                            tx_hash,
                            tx,
                            op_hashes: Arc::new(op_hashes),
                        }),
                        nonce.low_u64(),
                        fee_increase_count,
                        required_fees,
                    ));
                    self.transaction_tracker.wait_for_update().await?
                }
            };
            match update {
                TrackerUpdate::Mined {
                    tx_hash,
                    nonce,
                    block_number,
                    attempt_number,
                } => {
                    self.emit(BuilderEvent::transaction_mined(
                        self.builder_index,
                        tx_hash,
                        nonce.low_u64(),
                        block_number,
                    ));
                    BuilderMetrics::increment_bundle_txns_success(self.builder_index);
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
                    self.emit(BuilderEvent::latest_transaction_dropped(
                        self.builder_index,
                        nonce.low_u64(),
                    ));
                    BuilderMetrics::increment_bundle_txns_dropped(self.builder_index);
                    info!("Previous transaction dropped by sender");
                }
                TrackerUpdate::NonceUsedForOtherTx { nonce } => {
                    self.emit(BuilderEvent::nonce_used_for_other_transaction(
                        self.builder_index,
                        nonce.low_u64(),
                    ));
                    BuilderMetrics::increment_bundle_txns_nonce_used(self.builder_index);
                    bail!("nonce used by external transaction")
                }
            };
            info!(
                "Bundle transaction failed to mine after {fee_increase_count} fee increases (maxFeePerGas: {}, maxPriorityFeePerGas: {}).",
                current_fees.max_fee_per_gas,
                current_fees.max_priority_fee_per_gas,
            );
            BuilderMetrics::increment_bundle_txn_fee_increases(self.builder_index);
            required_fees = Some(
                current_fees.increase_by_percent(self.settings.replacement_fee_percent_increase),
            );
        }
        BuilderMetrics::increment_bundle_txns_abandoned(self.builder_index);
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
        let op_hashes: Vec<_> = bundle.iter_ops().map(|op| self.op_hash(op)).collect();
        let mut tx = self.entry_point.get_send_bundle_transaction(
            bundle.ops_per_aggregator,
            self.beneficiary,
            bundle.gas_estimate,
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
        self.pool
            .remove_ops(
                self.entry_point.address(),
                ops.iter()
                    .map(|op| op.op_hash(self.entry_point.address(), self.chain_id))
                    .collect(),
            )
            .await
            .context("builder should remove rejected ops from pool")
    }

    async fn remove_entities_from_pool(&self, entities: &[Entity]) -> anyhow::Result<()> {
        self.pool
            .remove_entities(self.entry_point.address(), entities.to_vec())
            .await
            .context("builder should remove rejected entities from pool")
    }

    fn emit(&self, event: BuilderEvent) {
        let _ = self.event_sender.send(WithEntryPoint {
            entry_point: self.entry_point.address(),
            event,
        });
    }

    fn op_hash(&self, op: &UserOperation) -> H256 {
        op.op_hash(self.entry_point.address(), self.chain_id)
    }
}

struct BuilderMetrics {}

impl BuilderMetrics {
    fn increment_bundle_txns_sent(builder_index: u64) {
        metrics::increment_counter!("builder_bundle_txns_sent", "builder_index" => builder_index.to_string());
    }

    fn increment_bundle_txns_success(builder_index: u64) {
        metrics::increment_counter!("builder_bundle_txns_success", "builder_index" => builder_index.to_string());
    }

    fn increment_bundle_txns_dropped(builder_index: u64) {
        metrics::increment_counter!("builder_bundle_txns_dropped", "builder_index" => builder_index.to_string());
    }

    // used when we decide to stop trying a transaction
    fn increment_bundle_txns_abandoned(builder_index: u64) {
        metrics::increment_counter!("builder_bundle_txns_abandoned", "builder_index" => builder_index.to_string());
    }

    // used when sending a transaction fails
    fn increment_bundle_txns_failed(builder_index: u64) {
        metrics::increment_counter!("builder_bundle_txns_failed", "builder_index" => builder_index.to_string());
    }

    fn increment_bundle_txns_nonce_used(builder_index: u64) {
        metrics::increment_counter!("builder_bundle_txns_nonce_used", "builder_index" => builder_index.to_string());
    }

    fn increment_bundle_txn_fee_increases(builder_index: u64) {
        metrics::increment_counter!("builder_bundle_fee_increases", "builder_index" => builder_index.to_string());
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
