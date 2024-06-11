// This file is part of Rundler.
//
// Rundler is free software: you can redistribute it and/or modify it under the
// terms of the GNU Lesser General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later version.
//
// Rundler is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with Rundler.
// If not, see https://www.gnu.org/licenses/.

use std::{marker::PhantomData, sync::Arc, time::Duration};

use anyhow::{bail, Context};
use async_trait::async_trait;
use ethers::types::{transaction::eip2718::TypedTransaction, Address, H256, U256};
use futures_util::StreamExt;
use rundler_provider::{BundleHandler, EntryPoint};
use rundler_sim::ExpectedStorage;
use rundler_types::{
    builder::BundlingMode,
    chain::ChainSpec,
    pool::{NewHead, Pool},
    EntityUpdate, GasFees, UserOperation,
};
use rundler_utils::emit::WithEntryPoint;
use tokio::{
    join,
    sync::{broadcast, mpsc, mpsc::UnboundedReceiver, oneshot},
};
use tracing::{debug, error, info, instrument, warn};

use crate::{
    bundle_proposer::BundleProposer,
    emit::{BuilderEvent, BundleTxDetails},
    transaction_tracker::{TrackerUpdate, TransactionTracker, TransactionTrackerError},
};

#[async_trait]
pub(crate) trait BundleSender: Send + Sync + 'static {
    async fn send_bundles_in_loop(self) -> anyhow::Result<()>;
}

#[derive(Debug)]
pub(crate) struct Settings {
    pub(crate) max_fee_increases: u64,
    pub(crate) max_blocks_to_wait_for_mine: u64,
}

#[derive(Debug)]
pub(crate) struct BundleSenderImpl<UO, P, E, T, C> {
    builder_index: u64,
    bundle_action_receiver: Option<mpsc::Receiver<BundleSenderAction>>,
    chain_spec: ChainSpec,
    beneficiary: Address,
    proposer: P,
    entry_point: E,
    transaction_tracker: T,
    pool: C,
    settings: Settings,
    event_sender: broadcast::Sender<WithEntryPoint<BuilderEvent>>,
    _uo_type: PhantomData<UO>,
}

#[derive(Debug)]
struct BundleTx {
    tx: TypedTransaction,
    expected_storage: ExpectedStorage,
    op_hashes: Vec<H256>,
}

pub enum BundleSenderAction {
    SendBundle(SendBundleRequest),
    ChangeMode(BundlingMode),
}

pub struct SendBundleRequest {
    pub responder: oneshot::Sender<SendBundleResult>,
}

/// Response to a `SendBundleRequest` after
/// going through a full cycle of bundling, sending,
/// and waiting for the transaction to be mined.
#[derive(Debug)]
pub enum SendBundleResult {
    Success {
        block_number: u64,
        attempt_number: u64,
        tx_hash: H256,
    },
    NoOperationsInitially,
    NoOperationsAfterFeeIncreases {
        attempt_number: u64,
    },
    StalledAtMaxFeeIncreases,
    Error(anyhow::Error),
}

// Internal result of attempting to send a bundle.
enum SendBundleAttemptResult {
    // The bundle was successfully sent
    Success,
    // The bundle was empty
    NoOperations,
    // Replacement Underpriced
    ReplacementUnderpriced,
    // Nonce too low
    NonceTooLow,
}

#[async_trait]
impl<UO, P, E, T, C> BundleSender for BundleSenderImpl<UO, P, E, T, C>
where
    UO: UserOperation,
    P: BundleProposer<UO = UO>,
    E: EntryPoint + BundleHandler<UO = UO>,
    T: TransactionTracker,
    C: Pool,
{
    /// Loops forever, attempting to form and send a bundle on each new block,
    /// then waiting for one bundle to be mined or dropped before forming the
    /// next one.
    #[instrument(skip_all, fields(entry_point = self.entry_point.address().to_string(), builder_index = self.builder_index))]
    async fn send_bundles_in_loop(mut self) -> anyhow::Result<()> {
        // State of the sender loop
        enum State {
            // Building a bundle, optionally waiting for a trigger to send it
            // (wait_for_trigger, fee_increase_count)
            Building(bool, u64),
            // Waiting for a bundle to be mined
            // (wait_until_block, fee_increase_count)
            Pending(u64, u64),
            // Cancelling the last transaction
            // (fee_increase_count)
            Cancelling(u64),
            // Waiting for a cancellation transaction to be mined
            // (wait_until_block, fee_increase_count)
            CancelPending(u64, u64),
        }

        // initial state
        let mut state = State::Building(true, 0);

        // response to manual caller
        let mut send_bundle_response = None;
        let mut send_bundle_result = None;

        // trigger for sending bundles
        let mut sender_trigger = BundleSenderTrigger::new(
            &self.pool,
            self.bundle_action_receiver.take().unwrap(),
            Duration::from_millis(self.chain_spec.bundle_max_send_interval_millis),
        )
        .await?;

        loop {
            match state {
                State::Building(wait_for_trigger, fee_increase_count) => {
                    if wait_for_trigger {
                        send_bundle_response = sender_trigger.wait_for_trigger().await?;

                        // process any nonce updates, ignore result
                        self.check_for_transaction_update().await;
                    }

                    // send bundle
                    debug!(
                        "Building bundle on block {}",
                        sender_trigger.last_block.block_number
                    );
                    let result = self.send_bundle(fee_increase_count).await;

                    // handle result
                    match result {
                        Ok(SendBundleAttemptResult::Success) => {
                            // sent the bundle
                            info!("Bundle sent successfully");
                            state = State::Pending(
                                sender_trigger.last_block.block_number
                                    + self.settings.max_blocks_to_wait_for_mine,
                                0,
                            );
                        }
                        Ok(SendBundleAttemptResult::NoOperations) => {
                            debug!("No operations in bundle");

                            if fee_increase_count > 0 {
                                warn!("Abandoning bundle after fee increases {fee_increase_count}, no operations available");
                                BuilderMetrics::increment_bundle_txns_abandoned(
                                    self.builder_index,
                                    self.entry_point.address(),
                                );
                                send_bundle_result =
                                    Some(SendBundleResult::NoOperationsAfterFeeIncreases {
                                        attempt_number: fee_increase_count,
                                    });

                                // abandon the bundle by resetting the tracker and starting a new bundle process
                                // If the node we are using still has the transaction in the mempool, its
                                // possible we will get a `ReplacementUnderpriced` on the next iteration
                                // and will start a cancellation.
                                self.transaction_tracker.reset().await;
                                state = State::Building(true, 0);
                            } else {
                                debug!("No operations available, waiting for next trigger");
                                send_bundle_result = Some(SendBundleResult::NoOperationsInitially);
                                state = State::Building(true, 0);
                            }
                        }
                        Ok(SendBundleAttemptResult::NonceTooLow) => {
                            // reset the transaction tracker and try again
                            info!("Nonce too low, starting new bundle attempt");
                            self.transaction_tracker.reset().await;
                            state = State::Building(true, 0);
                        }
                        Ok(SendBundleAttemptResult::ReplacementUnderpriced) => {
                            info!(
                                "Replacement transaction underpriced, entering cancellation loop"
                            );
                            self.transaction_tracker.reset().await;
                            state = State::Cancelling(0);
                        }
                        Err(error) => {
                            error!("Bundle send error {error:?}");
                            BuilderMetrics::increment_bundle_txns_failed(
                                self.builder_index,
                                self.entry_point.address(),
                            );
                            self.transaction_tracker.reset().await;
                            send_bundle_result = Some(SendBundleResult::Error(error));
                            state = State::Building(true, 0);
                        }
                    }
                }
                State::Pending(until, fee_increase_count) => {
                    sender_trigger.wait_for_block().await?;

                    // check for transaction update
                    if let Some(update) = self.check_for_transaction_update().await {
                        match update {
                            TrackerUpdate::Mined {
                                block_number,
                                attempt_number,
                                gas_limit,
                                gas_used,
                                tx_hash,
                                nonce,
                                ..
                            } => {
                                // mined!
                                info!("Bundle transaction mined");
                                BuilderMetrics::process_bundle_txn_success(
                                    self.builder_index,
                                    self.entry_point.address(),
                                    gas_limit,
                                    gas_used,
                                );
                                self.emit(BuilderEvent::transaction_mined(
                                    self.builder_index,
                                    tx_hash,
                                    nonce.low_u64(),
                                    block_number,
                                ));
                                send_bundle_result = Some(SendBundleResult::Success {
                                    block_number,
                                    attempt_number,
                                    tx_hash,
                                });
                                state = State::Building(true, 0);
                            }
                            TrackerUpdate::LatestTxDropped { nonce } => {
                                // try again, don't wait for trigger, re-estimate fees
                                info!("Latest transaction dropped, starting new bundle attempt");
                                self.emit(BuilderEvent::latest_transaction_dropped(
                                    self.builder_index,
                                    nonce.low_u64(),
                                ));
                                BuilderMetrics::increment_bundle_txns_dropped(
                                    self.builder_index,
                                    self.entry_point.address(),
                                );

                                // force reset the transaction tracker
                                self.transaction_tracker.reset().await;
                                state = State::Building(true, 0);
                            }
                            TrackerUpdate::NonceUsedForOtherTx { nonce } => {
                                // try again, don't wait for trigger, re-estimate fees
                                info!("Nonce used externally, starting new bundle attempt");
                                self.emit(BuilderEvent::nonce_used_for_other_transaction(
                                    self.builder_index,
                                    nonce.low_u64(),
                                ));
                                BuilderMetrics::increment_bundle_txns_nonce_used(
                                    self.builder_index,
                                    self.entry_point.address(),
                                );
                                state = State::Building(true, 0);
                            }
                        }
                    } else if sender_trigger.last_block().block_number >= until {
                        // start replacement, don't wait for trigger. Continue
                        // to attempt until there are no longer any UOs priced high enough
                        // to bundle.
                        info!(
                            "Not mined after {} blocks, increasing fees, attempt: {}",
                            self.settings.max_blocks_to_wait_for_mine,
                            fee_increase_count + 1
                        );
                        BuilderMetrics::increment_bundle_txn_fee_increases(
                            self.builder_index,
                            self.entry_point.address(),
                        );
                        state = State::Building(false, fee_increase_count + 1);
                    }
                }
                State::Cancelling(fee_increase_count) => {
                    // cancel the transaction
                    info!("Cancelling last transaction");

                    let (estimated_fees, _) = self
                        .proposer
                        .estimate_gas_fees(None)
                        .await
                        .unwrap_or_default();

                    let cancel_res = self
                        .transaction_tracker
                        .cancel_transaction(self.entry_point.address(), estimated_fees)
                        .await;

                    match cancel_res {
                        Ok(Some(_)) => {
                            info!("Cancellation transaction sent, waiting for confirmation");
                            BuilderMetrics::increment_cancellation_txns_sent(
                                self.builder_index,
                                self.entry_point.address(),
                            );

                            state = State::CancelPending(
                                sender_trigger.last_block.block_number
                                    + self.settings.max_blocks_to_wait_for_mine,
                                fee_increase_count,
                            );
                        }
                        Ok(None) => {
                            info!("Soft cancellation or no transaction to cancel, starting new bundle attempt");
                            BuilderMetrics::increment_soft_cancellations(
                                self.builder_index,
                                self.entry_point.address(),
                            );

                            state = State::Building(true, 0);
                        }
                        Err(TransactionTrackerError::ReplacementUnderpriced) => {
                            info!("Replacement transaction underpriced during cancellation, trying again");
                            state = State::Cancelling(fee_increase_count + 1);
                        }
                        Err(TransactionTrackerError::NonceTooLow) => {
                            // reset the transaction tracker and try again
                            info!("Nonce too low during cancellation, starting new bundle attempt");
                            self.transaction_tracker.reset().await;
                            state = State::Building(true, 0);
                        }
                        Err(e) => {
                            error!("Failed to cancel transaction, moving back to building state: {e:#?}");
                            BuilderMetrics::increment_cancellation_txns_failed(
                                self.builder_index,
                                self.entry_point.address(),
                            );
                            state = State::Building(true, 0);
                        }
                    }
                }
                State::CancelPending(until, fee_increase_count) => {
                    sender_trigger.wait_for_block().await?;

                    // check for transaction update
                    if let Some(update) = self.check_for_transaction_update().await {
                        match update {
                            TrackerUpdate::Mined { .. } => {
                                // mined
                                info!("Cancellation transaction mined");
                                BuilderMetrics::increment_cancellation_txns_mined(
                                    self.builder_index,
                                    self.entry_point.address(),
                                );
                            }
                            TrackerUpdate::LatestTxDropped { .. } => {
                                // If a cancellation gets dropped, move to bundling state as there is no
                                // longer a pending transaction
                                info!(
                                    "Cancellation transaction dropped, starting new bundle attempt"
                                );
                                // force reset the transaction tracker
                                self.transaction_tracker.reset().await;
                            }
                            TrackerUpdate::NonceUsedForOtherTx { .. } => {
                                // If a nonce is used externally, move to bundling state as there is no longer
                                // a pending transaction
                                info!("Nonce used externally while cancelling, starting new bundle attempt");
                            }
                        }

                        state = State::Building(true, 0);
                    } else if sender_trigger.last_block().block_number >= until {
                        if fee_increase_count >= self.settings.max_fee_increases {
                            // abandon the cancellation
                            warn!("Abandoning cancellation after max fee increases {fee_increase_count}, starting new bundle attempt");
                            // force reset the transaction tracker
                            self.transaction_tracker.reset().await;
                            state = State::Building(true, 0);
                        } else {
                            // start replacement, don't wait for trigger
                            info!(
                                "Cancellation not mined after {} blocks, increasing fees, attempt: {}",
                                self.settings.max_blocks_to_wait_for_mine,
                                fee_increase_count + 1
                            );
                            state = State::Cancelling(fee_increase_count + 1);
                        }
                    }
                }
            }

            // send result to manual caller
            if let Some(res) = send_bundle_result.take() {
                if let Some(r) = send_bundle_response.take() {
                    if r.send(res).is_err() {
                        error!("Failed to send bundle result to manual caller");
                    }
                }
            }
        }
    }
}

impl<UO, P, E, T, C> BundleSenderImpl<UO, P, E, T, C>
where
    UO: UserOperation,
    P: BundleProposer<UO = UO>,
    E: EntryPoint + BundleHandler<UO = UO>,
    T: TransactionTracker,
    C: Pool,
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        builder_index: u64,
        bundle_action_receiver: mpsc::Receiver<BundleSenderAction>,
        chain_spec: ChainSpec,
        beneficiary: Address,
        proposer: P,
        entry_point: E,
        transaction_tracker: T,
        pool: C,
        settings: Settings,
        event_sender: broadcast::Sender<WithEntryPoint<BuilderEvent>>,
    ) -> Self {
        Self {
            builder_index,
            bundle_action_receiver: Some(bundle_action_receiver),
            chain_spec,
            beneficiary,
            proposer,
            entry_point,
            transaction_tracker,
            pool,
            settings,
            event_sender,
            _uo_type: PhantomData,
        }
    }

    async fn check_for_transaction_update(&mut self) -> Option<TrackerUpdate> {
        let update = self.transaction_tracker.check_for_update().await;
        let update = match update {
            Ok(update) => update?,
            Err(error) => {
                error!("Failed to check for transaction updates: {error:#?}");
                return None;
            }
        };

        match update {
            TrackerUpdate::Mined {
                tx_hash,
                block_number,
                attempt_number,
                nonce,
                ..
            } => {
                if attempt_number == 0 {
                    info!("Transaction with hash {tx_hash:?}, nonce {nonce:?}, landed in block {block_number}");
                } else {
                    info!("Transaction with hash {tx_hash:?}, nonce {nonce:?}, landed in block {block_number} after increasing gas fees {attempt_number} time(s)");
                }
            }
            TrackerUpdate::LatestTxDropped { nonce } => {
                info!("Previous transaction dropped by sender. Nonce: {nonce:?}");
            }
            TrackerUpdate::NonceUsedForOtherTx { nonce } => {
                info!("Nonce used by external transaction. Nonce: {nonce:?}");
            }
        };

        Some(update)
    }

    /// Constructs a bundle and sends it to the entry point as a transaction.
    ///
    /// Returns empty if:
    ///  - There are no ops available to bundle initially.
    ///  - The gas fees are high enough that the bundle is empty because there
    ///    are no ops that meet the fee requirements.
    async fn send_bundle(
        &mut self,
        fee_increase_count: u64,
    ) -> anyhow::Result<SendBundleAttemptResult> {
        let (nonce, required_fees) = self.transaction_tracker.get_nonce_and_required_fees()?;

        let Some(bundle_tx) = self
            .get_bundle_tx(nonce, required_fees, fee_increase_count > 0)
            .await?
        else {
            self.emit(BuilderEvent::formed_bundle(
                self.builder_index,
                None,
                nonce.low_u64(),
                fee_increase_count,
                required_fees,
            ));
            return Ok(SendBundleAttemptResult::NoOperations);
        };
        let BundleTx {
            tx,
            expected_storage,
            op_hashes,
        } = bundle_tx;

        BuilderMetrics::increment_bundle_txns_sent(self.builder_index, self.entry_point.address());

        let send_result = self
            .transaction_tracker
            .send_transaction(tx.clone(), &expected_storage)
            .await;

        match send_result {
            Ok(tx_hash) => {
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

                Ok(SendBundleAttemptResult::Success)
            }
            Err(TransactionTrackerError::NonceTooLow) => {
                warn!("Replacement transaction underpriced");
                Ok(SendBundleAttemptResult::NonceTooLow)
            }
            Err(TransactionTrackerError::ReplacementUnderpriced) => {
                BuilderMetrics::increment_bundle_txn_replacement_underpriced(
                    self.builder_index,
                    self.entry_point.address(),
                );
                warn!("Replacement transaction underpriced");
                Ok(SendBundleAttemptResult::ReplacementUnderpriced)
            }
            Err(e) => {
                error!("Failed to send bundle with unexpected error: {e:?}");
                Err(e.into())
            }
        }
    }

    /// Builds a bundle and returns some metadata and the transaction to send
    /// it, or `None` if there are no valid operations available.
    async fn get_bundle_tx(
        &self,
        nonce: U256,
        required_fees: Option<GasFees>,
        is_replacement: bool,
    ) -> anyhow::Result<Option<BundleTx>> {
        let bundle = self
            .proposer
            .make_bundle(required_fees, is_replacement)
            .await
            .context("proposer should create bundle for builder")?;
        let remove_ops_future = async {
            let result = self.remove_ops_from_pool(&bundle.rejected_ops).await;
            if let Err(error) = result {
                error!("Failed to remove rejected ops from pool: {error}");
            }
        };
        let update_entities_future = async {
            let result = self.update_entities_in_pool(&bundle.entity_updates).await;
            if let Err(error) = result {
                error!("Failed to update entities in pool: {error}");
            }
        };
        join!(remove_ops_future, update_entities_future);
        if bundle.is_empty() {
            if !bundle.rejected_ops.is_empty() || !bundle.entity_updates.is_empty() {
                info!(
                "Empty bundle with {} rejected ops and {} rejected entities. Removing them from pool.",
                bundle.rejected_ops.len(),
                bundle.entity_updates.len()
            );
            }
            return Ok(None);
        }
        info!(
            "Selected bundle with {} op(s), with {} rejected op(s) and {} updated entities",
            bundle.len(),
            bundle.rejected_ops.len(),
            bundle.entity_updates.len()
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

    async fn remove_ops_from_pool(&self, ops: &[UO]) -> anyhow::Result<()> {
        self.pool
            .remove_ops(
                self.entry_point.address(),
                ops.iter()
                    .map(|op| op.hash(self.entry_point.address(), self.chain_spec.id))
                    .collect(),
            )
            .await
            .context("builder should remove rejected ops from pool")
    }

    async fn update_entities_in_pool(&self, entity_updates: &[EntityUpdate]) -> anyhow::Result<()> {
        self.pool
            .update_entities(self.entry_point.address(), entity_updates.to_vec())
            .await
            .context("builder should remove update entities in the pool")
    }

    fn emit(&self, event: BuilderEvent) {
        let _ = self.event_sender.send(WithEntryPoint {
            entry_point: self.entry_point.address(),
            event,
        });
    }

    fn op_hash(&self, op: &UO) -> H256 {
        op.hash(self.entry_point.address(), self.chain_spec.id)
    }
}

struct BundleSenderTrigger {
    bundling_mode: BundlingMode,
    block_rx: UnboundedReceiver<NewHead>,
    bundle_action_receiver: mpsc::Receiver<BundleSenderAction>,
    timer: tokio::time::Interval,
    last_block: NewHead,
}

impl BundleSenderTrigger {
    async fn new<P: Pool>(
        pool_client: &P,
        bundle_action_receiver: mpsc::Receiver<BundleSenderAction>,
        timer_interval: Duration,
    ) -> anyhow::Result<Self> {
        let block_rx = Self::start_block_stream(pool_client).await?;

        Ok(Self {
            bundling_mode: BundlingMode::Auto,
            block_rx,
            bundle_action_receiver,
            timer: tokio::time::interval(timer_interval),
            last_block: NewHead {
                block_hash: H256::zero(),
                block_number: 0,
            },
        })
    }

    async fn start_block_stream<P: Pool>(
        pool_client: &P,
    ) -> anyhow::Result<UnboundedReceiver<NewHead>> {
        let Ok(mut new_heads) = pool_client.subscribe_new_heads().await else {
            error!("Failed to subscribe to new blocks");
            bail!("failed to subscribe to new blocks");
        };

        let (tx, rx) = mpsc::unbounded_channel();
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

        Ok(rx)
    }

    async fn wait_for_trigger(
        &mut self,
    ) -> anyhow::Result<Option<oneshot::Sender<SendBundleResult>>> {
        let mut send_bundle_response: Option<oneshot::Sender<SendBundleResult>> = None;

        loop {
            // 3 triggers for loop logic:
            // 1 - new block
            //      - If auto mode, send next bundle
            // 2 - timer tick
            //      - If auto mode, send next bundle
            // 3 - action recv
            //      - If change mode, change and restart loop
            //      - If send bundle and manual mode, send next bundle
            tokio::select! {
                b = self.block_rx.recv() => {
                    let Some(b) = b else {
                        error!("Block stream closed");
                        bail!("Block stream closed");
                    };

                    self.last_block = b;

                    match self.bundling_mode {
                        BundlingMode::Manual => continue,
                        BundlingMode::Auto => break,
                    }
                },
                _ = self.timer.tick() => {
                    match self.bundling_mode {
                        BundlingMode::Manual => continue,
                        BundlingMode::Auto => break,
                    }
                },
                a = self.bundle_action_receiver.recv() => {
                    match a {
                        Some(BundleSenderAction::ChangeMode(mode)) => {
                            debug!("changing bundling mode to {mode:?}");
                            self.bundling_mode = mode;
                            continue;
                        },
                        Some(BundleSenderAction::SendBundle(r)) => {
                            match self.bundling_mode {
                                BundlingMode::Manual => {
                                    send_bundle_response = Some(r.responder);
                                    break;
                                },
                                BundlingMode::Auto => {
                                    error!("Received bundle send action while in auto mode, ignoring");
                                    continue;
                                }
                            }
                        },
                        None => {
                            error!("Bundle action recv closed");
                            bail!("Bundle action recv closed");
                        }
                    }
                }
            };
        }

        self.consume_blocks()?;

        Ok(send_bundle_response)
    }

    async fn wait_for_block(&mut self) -> anyhow::Result<NewHead> {
        self.last_block = self
            .block_rx
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("Block stream closed"))?;
        self.consume_blocks()?;
        Ok(self.last_block.clone())
    }

    fn consume_blocks(&mut self) -> anyhow::Result<()> {
        // Consume any other blocks that may have been buffered up
        loop {
            match self.block_rx.try_recv() {
                Ok(b) => {
                    self.last_block = b;
                }
                Err(mpsc::error::TryRecvError::Empty) => {
                    return Ok(());
                }
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    error!("Block stream closed");
                    bail!("Block stream closed");
                }
            }
        }
    }

    fn last_block(&self) -> &NewHead {
        &self.last_block
    }
}

struct BuilderMetrics {}

impl BuilderMetrics {
    fn increment_bundle_txns_sent(builder_index: u64, entry_point: Address) {
        metrics::counter!("builder_bundle_txns_sent", "entry_point" => entry_point.to_string(), "builder_index" => builder_index.to_string())
            .increment(1);
    }

    fn process_bundle_txn_success(
        builder_index: u64,
        entry_point: Address,
        gas_limit: Option<U256>,
        gas_used: Option<U256>,
    ) {
        metrics::counter!("builder_bundle_txns_success", "entry_point" => entry_point.to_string(), "builder_index" => builder_index.to_string()).increment(1);

        if let Some(limit) = gas_limit {
            metrics::counter!("builder_bundle_gas_limit", "entry_point" => entry_point.to_string(), "builder_index" => builder_index.to_string()).increment(limit.as_u64());
        }
        if let Some(used) = gas_used {
            metrics::counter!("builder_bundle_gas_used", "entry_point" => entry_point.to_string(), "builder_index" => builder_index.to_string()).increment(used.as_u64());
        }
    }

    fn increment_bundle_txns_dropped(builder_index: u64, entry_point: Address) {
        metrics::counter!("builder_bundle_txns_dropped", "entry_point" => entry_point.to_string(), "builder_index" => builder_index.to_string()).increment(1);
    }

    // used when we decide to stop trying a transaction
    fn increment_bundle_txns_abandoned(builder_index: u64, entry_point: Address) {
        metrics::counter!("builder_bundle_txns_abandoned", "entry_point" => entry_point.to_string(), "builder_index" => builder_index.to_string()).increment(1);
    }

    // used when sending a transaction fails
    fn increment_bundle_txns_failed(builder_index: u64, entry_point: Address) {
        metrics::counter!("builder_bundle_txns_failed", "entry_point" => entry_point.to_string(), "builder_index" => builder_index.to_string()).increment(1);
    }

    fn increment_bundle_txns_nonce_used(builder_index: u64, entry_point: Address) {
        metrics::counter!("builder_bundle_txns_nonce_used", "entry_point" => entry_point.to_string(), "builder_index" => builder_index.to_string()).increment(1);
    }

    fn increment_bundle_txn_fee_increases(builder_index: u64, entry_point: Address) {
        metrics::counter!("builder_bundle_fee_increases", "entry_point" => entry_point.to_string(), "builder_index" => builder_index.to_string()).increment(1);
    }

    fn increment_bundle_txn_replacement_underpriced(builder_index: u64, entry_point: Address) {
        metrics::counter!("builder_bundle_replacement_underpriced", "entry_point" => entry_point.to_string(), "builder_index" => builder_index.to_string()).increment(1);
    }

    fn increment_cancellation_txns_sent(builder_index: u64, entry_point: Address) {
        metrics::counter!("builder_cancellation_txns_sent", "entry_point" => entry_point.to_string(), "builder_index" => builder_index.to_string()).increment(1);
    }

    fn increment_cancellation_txns_mined(builder_index: u64, entry_point: Address) {
        metrics::counter!("builder_cancellation_txns_mined", "entry_point" => entry_point.to_string(), "builder_index" => builder_index.to_string()).increment(1);
    }

    fn increment_soft_cancellations(builder_index: u64, entry_point: Address) {
        metrics::counter!("builder_soft_cancellations", "entry_point" => entry_point.to_string(), "builder_index" => builder_index.to_string()).increment(1);
    }

    fn increment_cancellation_txns_failed(builder_index: u64, entry_point: Address) {
        metrics::counter!("builder_cancellation_txns_failed", "entry_point" => entry_point.to_string(), "builder_index" => builder_index.to_string()).increment(1);
    }
}
