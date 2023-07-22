use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{bail, Context};
use ethers::types::{transaction::eip2718::TypedTransaction, Address, H256, U256};
use tokio::{
    join,
    sync::{broadcast, mpsc, oneshot},
    time,
};
use tonic::async_trait;
use tracing::{error, info, trace, warn};

use crate::{
    builder::{
        bundle_proposer::BundleProposer,
        transaction_tracker::{TrackerUpdate, TransactionTracker},
    },
    common::{
        gas::GasFees,
        math,
        types::{Entity, EntryPointLike, ExpectedStorage, UserOperation},
    },
    op_pool::{NewBlock, PoolClient},
};

// Overhead on gas estimates to account for inaccuracies.
const GAS_ESTIMATE_OVERHEAD_PERCENT: u64 = 10;

#[async_trait]
pub trait BundleSender: Send + Sync + 'static {
    async fn send_bundles_in_loop(&mut self);
}

#[derive(Debug)]
pub struct Settings {
    pub replacement_fee_percent_increase: u64,
    pub max_fee_increases: u64,
}

#[derive(Debug)]
pub struct BundleSenderImpl<P, E, T, C>
where
    P: BundleProposer,
    E: EntryPointLike,
    T: TransactionTracker,
    C: PoolClient,
{
    manual_bundling_mode: Arc<AtomicBool>,
    send_bundle_receiver: mpsc::Receiver<SendBundleRequest>,
    chain_id: u64,
    beneficiary: Address,
    eth_poll_interval: Duration,
    proposer: P,
    entry_point: E,
    transaction_tracker: T,
    pool_client: C,
    settings: Settings,
}

#[derive(Debug)]
struct BundleTx {
    tx: TypedTransaction,
    expected_storage: ExpectedStorage,
    op_count: usize,
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
    E: EntryPointLike,
    T: TransactionTracker,
    C: PoolClient,
{
    /// Loops forever, attempting to form and send a bundle on each new block,
    /// then waiting for one bundle to be mined or dropped before forming the
    /// next one.
    async fn send_bundles_in_loop(&mut self) {
        let mut last_block_number = 0;
        let mut new_blocks = if let Ok(new_blocks) = self.pool_client.subscribe_new_blocks().await {
            new_blocks
        } else {
            error!("Failed to subscribe to new blocks");
            return;
        };

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

            last_block_number = self
                .wait_for_new_block_number(last_block_number, &mut new_blocks)
                .await;
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
    E: EntryPointLike,
    T: TransactionTracker,
    C: PoolClient,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        manual_bundling_mode: Arc<AtomicBool>,
        send_bundle_receiver: mpsc::Receiver<SendBundleRequest>,
        chain_id: u64,
        beneficiary: Address,
        eth_poll_interval: Duration,
        proposer: P,
        entry_point: E,
        transaction_tracker: T,
        pool_client: C,
        settings: Settings,
    ) -> Self {
        Self {
            manual_bundling_mode,
            send_bundle_receiver,
            chain_id,
            beneficiary,
            eth_poll_interval,
            proposer,
            entry_point,
            transaction_tracker,
            pool_client,
            settings,
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
            TrackerUpdate::LatestTxDropped => {
                BuilderMetrics::increment_bundle_txns_dropped();
                info!("Previous transaction dropped by sender");
            }
            TrackerUpdate::NonceUsedForOtherTx => {
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
        BuilderMetrics::set_nonce(nonce);
        let mut initial_op_count: Option<usize> = None;
        for num_increases in 0..=self.settings.max_fee_increases {
            let Some(bundle_tx) = self.get_bundle_tx(nonce, required_fees).await? else {
                return Ok(match initial_op_count {
                    Some(initial_op_count) => {
                        BuilderMetrics::increment_bundle_txns_abandoned();
                        SendBundleResult::NoOperationsAfterFeeIncreases {
                            initial_op_count,
                            attempt_number: num_increases,
                        }
                    }
                    None => SendBundleResult::NoOperationsInitially,
                });
            };
            let BundleTx {
                tx,
                expected_storage,
                op_count,
            } = bundle_tx;
            if initial_op_count.is_none() {
                initial_op_count = Some(op_count);
            }
            let current_fees = GasFees::from(&tx);

            BuilderMetrics::increment_bundle_txns_sent();
            BuilderMetrics::set_current_fees(&current_fees);

            let update = self
                .transaction_tracker
                .send_transaction_and_wait(tx, &expected_storage)
                .await?;
            match update {
                TrackerUpdate::Mined {
                    tx_hash,
                    gas_fees: _,
                    block_number,
                    attempt_number,
                } => {
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
                TrackerUpdate::LatestTxDropped => {
                    BuilderMetrics::increment_bundle_txns_dropped();
                    info!("Previous transaction dropped by sender");
                }
                TrackerUpdate::NonceUsedForOtherTx => {
                    BuilderMetrics::increment_bundle_txns_nonce_used();
                    bail!("nonce used by external transaction")
                }
            };
            info!(
                "Bundle transaction failed to mine after {num_increases} fee increases (maxFeePerGas: {}, maxPriorityFeePerGas: {}).",
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

    async fn wait_for_new_block_number(
        &self,
        prev_block_number: u64,
        new_blocks: &mut broadcast::Receiver<NewBlock>,
    ) -> u64 {
        loop {
            // TODO(danc) unwrap
            let block = new_blocks.recv().await.unwrap();
            if block.number > prev_block_number {
                return block.number;
            }
        }
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
        let op_count = bundle.len();
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
            op_count,
        }))
    }

    async fn remove_ops_from_pool(&self, ops: &[UserOperation]) -> anyhow::Result<()> {
        self.pool_client
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
        self.pool_client
            .remove_entities(self.entry_point.address(), entities.to_vec())
            .await
            .context("builder should remove rejected entities from pool")
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

    fn set_nonce(nonce: U256) {
        metrics::gauge!("builder_nonce", nonce.as_u64() as f64);
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
