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

use std::{collections::HashMap, pin::Pin, sync::Arc, time::Duration};

use alloy_primitives::{Address, B256, hex};
use anyhow::{Context, bail};
use async_trait::async_trait;
use futures::Stream;
use futures_util::StreamExt;
#[cfg(test)]
use mockall::automock;
use rand::Rng;
use rundler_provider::FeeEstimator;
use rundler_task::TaskSpawner;
use rundler_types::{
    builder::BundlingMode,
    chain::ChainSpec,
    pool::{AddressUpdate, NewHead, Pool},
};
use rundler_utils::{emit::WithEntryPoint, eth};
use tokio::{
    join,
    sync::{
        broadcast, mpsc,
        mpsc::{UnboundedReceiver, UnboundedSender},
        oneshot,
    },
};
use tracing::{debug, error, info, instrument, warn};

use crate::{
    ProposerKey,
    assigner::{Assigner, AssignmentResult},
    bundle_proposer::{BundleData, BundleProposerError, BundleProposerT},
    emit::{BuilderEvent, BundleTxDetails},
    transaction_tracker::{
        TrackerState, TrackerUpdate, TransactionTracker, TransactionTrackerError,
    },
};

const SLEEP_JITTER_MAX_MILLIS: u64 = 9;

#[async_trait]
pub(crate) trait BundleSender: Send + Sync {
    async fn send_bundles_in_loop<T: TaskSpawner>(self, task_spawner: T);
}

#[derive(Debug)]
pub(crate) struct Settings {
    pub(crate) max_replacement_underpriced_blocks: u64,
    pub(crate) max_cancellation_fee_increases: u64,
    pub(crate) max_blocks_to_wait_for_mine: u64,
}

pub(crate) struct BundleSenderImpl<T, C> {
    builder_tag: String,
    bundle_action_receiver: Option<mpsc::Receiver<BundleSenderAction>>,
    chain_spec: ChainSpec,
    sender_eoa: Address,
    transaction_tracker: Option<T>,
    fee_estimator: Box<dyn FeeEstimator>,
    assigner: Arc<Assigner>,
    /// Proposers keyed by (entrypoint address, filter_id) for shared signer support
    proposers: Arc<HashMap<ProposerKey, Box<dyn BundleProposerT>>>,
    pool: C,
    settings: Settings,
    event_sender: broadcast::Sender<WithEntryPoint<BuilderEvent>>,
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
        tx_hash: B256,
    },
    NoOperationsInitially,
    Error(anyhow::Error),
}

// Internal result of attempting to send a bundle.
#[derive(Debug)]
enum SendBundleAttemptResult {
    // The bundle was successfully sent with the given (sender, op_hash) pairs
    Success(Arc<Vec<(Address, B256)>>),
    // There are no operations available to bundle
    NoOperationsInitially,
    // There were no operations after the fee was increased
    NoOperationsAfterFeeFilter,
    // There were no operations after the bundle was simulated
    NoOperationsAfterSimulation,
    // Underpriced
    Underpriced,
    // Replacement Underpriced
    ReplacementUnderpriced,
    // Condition not met
    ConditionNotMet,
    // Rejected
    Rejected,
    // Insufficient Funds
    InsufficientFunds,
    // Nonce too low
    NonceTooLow,
}

#[async_trait]
impl<T, C> BundleSender for BundleSenderImpl<T, C>
where
    T: TransactionTracker,
    C: Pool,
{
    /// Loops forever, attempting to form and send a bundle on each new block,
    /// then waiting for one bundle to be mined or dropped before forming the
    /// next one.
    async fn send_bundles_in_loop<TS: TaskSpawner>(mut self, task_spawner: TS) {
        // trigger for sending bundles
        let sender_trigger = BundleSenderTrigger::new(
            &task_spawner,
            &self.pool,
            self.bundle_action_receiver.take().unwrap(),
            Duration::from_millis(self.chain_spec.bundle_max_send_interval_millis),
            self.sender_eoa,
        )
        .await
        .expect("Failed to create bundle sender trigger");

        // initial state
        let mut state =
            SenderMachineState::new(sender_trigger, self.transaction_tracker.take().unwrap());

        loop {
            if let Err(e) = self.step_state(&mut state).await {
                error!("Error in bundle sender loop: {e:#?}");
                let pinned = self.assigner.pinned_proposer(self.sender_eoa);
                self.increment_counter("builder_state_machine_errors", &pinned, 1);
                // release all operations, this may orphan an outstanding transaction and
                // cause an onchain collision. Errors should be rare.
                self.assigner.release_all(self.sender_eoa);
                state.reset();
            }
        }
    }
}

impl<T, C> BundleSenderImpl<T, C>
where
    T: TransactionTracker,
    C: Pool,
{
    async fn sleep_jitter(&self) {
        let jitter_ms = rand::thread_rng().gen_range(0..=SLEEP_JITTER_MAX_MILLIS);
        if jitter_ms > 0 {
            tokio::time::sleep(Duration::from_millis(jitter_ms)).await;
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        builder_tag: String,
        bundle_action_receiver: mpsc::Receiver<BundleSenderAction>,
        chain_spec: ChainSpec,
        sender_eoa: Address,
        transaction_tracker: T,
        fee_estimator: Box<dyn FeeEstimator>,
        assigner: Arc<Assigner>,
        proposers: Arc<HashMap<ProposerKey, Box<dyn BundleProposerT>>>,
        pool: C,
        settings: Settings,
        event_sender: broadcast::Sender<WithEntryPoint<BuilderEvent>>,
    ) -> Self {
        Self {
            builder_tag,
            bundle_action_receiver: Some(bundle_action_receiver),
            chain_spec,
            sender_eoa,
            transaction_tracker: Some(transaction_tracker),
            fee_estimator,
            assigner,
            proposers,
            pool,
            settings,
            event_sender,
        }
    }

    fn increment_counter(
        &self,
        name: &'static str,
        pinned_proposer: &Option<ProposerKey>,
        value: u64,
    ) {
        let ep = pinned_proposer
            .as_ref()
            .map(|(addr, _)| addr.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        metrics::counter!(name, "sender" => self.sender_eoa.to_string(), "entry_point" => ep)
            .increment(value);
    }

    fn increment_counter_ep(&self, name: &'static str, entry_point: Address, value: u64) {
        metrics::counter!(name, "sender" => self.sender_eoa.to_string(), "entry_point" => entry_point.to_string())
            .increment(value);
    }

    fn record_histogram_ep(&self, name: &'static str, entry_point: Address, value: f64) {
        metrics::histogram!(name, "sender" => self.sender_eoa.to_string(), "entry_point" => entry_point.to_string())
            .record(value);
    }

    #[instrument(skip_all, fields(
        tag = self.builder_tag,
    ))]
    async fn step_state<TRIG: Trigger>(
        &mut self,
        state: &mut SenderMachineState<T, TRIG>,
    ) -> anyhow::Result<()> {
        let tracker_update = state.wait_for_trigger().await?;
        let has_tracker_update = tracker_update.is_some();

        match state.inner {
            InnerState::Building(building_state) => {
                if has_tracker_update {
                    // Building state has no tracker-dependent cleanup, so release immediately.
                    self.assigner.release_all(self.sender_eoa);
                }
                self.handle_building_state(state, building_state).await?;
            }
            InnerState::Pending(pending_state) => {
                self.handle_pending_state(state, pending_state, tracker_update)
                    .await?;
                if has_tracker_update {
                    // Defer lock release until after pending handling so reverted bundles
                    // are cleaned from the pool before senders become assignable again.
                    self.assigner.release_all(self.sender_eoa);
                }
            }
            InnerState::Cancelling(cancelling_state) => {
                if has_tracker_update {
                    self.assigner.release_all(self.sender_eoa);
                }
                self.handle_cancelling_state(state, cancelling_state)
                    .await?;
            }
            InnerState::CancelPending(cancel_pending_state) => {
                self.handle_cancel_pending_state(state, cancel_pending_state, tracker_update)
                    .await?;
                if has_tracker_update {
                    self.assigner.release_all(self.sender_eoa);
                }
            }
        }

        Ok(())
    }

    async fn handle_building_state<TRIG: Trigger>(
        &mut self,
        state: &mut SenderMachineState<T, TRIG>,
        inner: BuildingState,
    ) -> anyhow::Result<()> {
        // Add a small jitter only on triggered attempts to reduce synchronized contention.
        if inner.wait_for_trigger {
            self.sleep_jitter().await;
        }

        // send bundle
        let block_number = state.block_number();
        debug!("Building bundle on block {block_number}");
        let result = self.send_bundle(state, inner.fee_increase_count).await;

        // Snapshot pinned proposer after send_bundle (pin is set during assignment)
        let pinned = self.assigner.pinned_proposer(self.sender_eoa);

        match result {
            Ok(SendBundleAttemptResult::Success(_)) => {
                // Senders confirmed in send_bundle, no lock release needed
                info!("Bundle sent successfully");
                state.update(InnerState::Pending(inner.to_pending(
                    block_number + self.settings.max_blocks_to_wait_for_mine,
                )));
            }
            Ok(SendBundleAttemptResult::NoOperationsInitially)
            | Ok(SendBundleAttemptResult::NoOperationsAfterSimulation) => {
                // Release all locks — cycle ending
                self.assigner.release_all(self.sender_eoa);
                debug!("No operations available");
                if inner.fee_increase_count > 0 {
                    state.transaction_tracker.abandon();
                }
                state.no_operations();
            }
            Ok(SendBundleAttemptResult::NoOperationsAfterFeeFilter) => {
                // Release locks only when nothing is pending (continuing)
                if state.transaction_tracker.num_pending_transactions() == 0 {
                    self.assigner.release_all(self.sender_eoa);
                }
                debug!("No operations to bundle after fee filtering");
                if let Some(underpriced_info) = inner.underpriced_info {
                    // If we are here, there are UOs in the pool that may be correctly priced, but are being blocked by an underpriced replacement
                    // after a fee increase. If we repeatedly get into this state, initiate a cancellation.
                    if block_number.saturating_sub(underpriced_info.since_block)
                        >= self.settings.max_replacement_underpriced_blocks
                    {
                        warn!(
                            "No operations available, but last replacement underpriced, moving to cancelling state. Round: {}. Since block {}. Current block {}. Max underpriced blocks: {}",
                            underpriced_info.rounds,
                            underpriced_info.since_block,
                            block_number,
                            self.settings.max_replacement_underpriced_blocks
                        );
                        state.update(InnerState::Cancelling(inner.to_cancelling()));
                    } else {
                        info!(
                            "No operations available, but last replacement underpriced, starting over and waiting for next trigger. Round: {}. Since block {}. Current block {}",
                            underpriced_info.rounds, underpriced_info.since_block, block_number
                        );
                        // Abandon the transaction tracker when we start the next bundle attempt fresh, may cause a `ReplacementUnderpriced` in next round
                        state.transaction_tracker.abandon();
                        state.update(InnerState::Building(inner.underpriced_round()));
                    }
                } else if inner.fee_increase_count > 0 {
                    warn!(
                        "Abandoning bundle after {} fee increases, no operations available after fee increase",
                        inner.fee_increase_count
                    );
                    self.increment_counter("builder_bundle_txns_abandoned", &pinned, 1);

                    // abandon the bundle by starting a new bundle process
                    // If the node we are using still has the transaction in the mempool, its
                    // possible we will get a `ReplacementUnderpriced` on the next iteration
                    // and will start a cancellation.
                    state.transaction_tracker.abandon();
                    state.initial();
                } else {
                    debug!("No operations available, waiting for next trigger");
                    state.no_operations();
                }
            }
            Ok(SendBundleAttemptResult::NonceTooLow) => {
                // Release all locks — cycle ending
                self.assigner.release_all(self.sender_eoa);
                info!("Nonce too low, starting new bundle attempt");
                state.reset();
            }
            Ok(SendBundleAttemptResult::Underpriced) => {
                // Release locks only when nothing is pending (continuing)
                if state.transaction_tracker.num_pending_transactions() == 0 {
                    self.assigner.release_all(self.sender_eoa);
                }
                let fee_increases = inner.fee_increase_count;
                info!(
                    "Bundle underpriced, marking as underpriced. Num fee increases {fee_increases}"
                );
                state.update(InnerState::Building(inner.underpriced(block_number)));
            }
            Ok(SendBundleAttemptResult::ReplacementUnderpriced) => {
                // Release locks only when nothing is pending (continuing)
                if state.transaction_tracker.num_pending_transactions() == 0 {
                    self.assigner.release_all(self.sender_eoa);
                }
                let fee_increases = inner.fee_increase_count;
                info!(
                    "Replacement transaction underpriced, marking as underpriced. Num fee increases {fee_increases}"
                );
                // unabandon to allow fee estimation to consider any submitted transactions, wait for next trigger
                state.transaction_tracker.unabandon();
                state.update(InnerState::Building(inner.underpriced(block_number)));
            }
            Ok(SendBundleAttemptResult::ConditionNotMet) => {
                // Release locks only when nothing is pending (continuing)
                if state.transaction_tracker.num_pending_transactions() == 0 {
                    self.assigner.release_all(self.sender_eoa);
                }
                info!("Condition not met, will re-check conditions on next bundle attempt");
                // Set flag to pass to proposer on next make_bundle call
                state.condition_not_met = true;
                state.update(InnerState::Building(inner.retry()));
            }
            Ok(SendBundleAttemptResult::InsufficientFunds) => {
                // Release all locks — cycle ending
                self.assigner.release_all(self.sender_eoa);
                info!(
                    "Insufficient funds sending bundle, resetting state and starting new bundle attempt"
                );
                state.reset();
            }
            Ok(SendBundleAttemptResult::Rejected) => {
                // Release locks only when nothing is pending (continuing)
                if state.transaction_tracker.num_pending_transactions() == 0 {
                    self.assigner.release_all(self.sender_eoa);
                }
                // Bundle was rejected, try with a higher price
                // May want to consider a simple retry instead of increasing fees, but this should be rare
                let fee_increases = inner.fee_increase_count;
                info!("Bundle rejected, assuming underpriced. Num fee increases {fee_increases}");
                state.update(InnerState::Building(inner.underpriced(block_number)));
            }
            Err(error) => {
                // Release all locks — cycle ending
                self.assigner.release_all(self.sender_eoa);
                error!("Bundle send error {error:?}");
                self.increment_counter("builder_bundle_txns_failed", &pinned, 1);
                state.bundle_error(error);
                state.transaction_tracker.reset().await;
            }
        }

        Ok(())
    }

    async fn handle_pending_state<TRIG: Trigger>(
        &mut self,
        state: &mut SenderMachineState<T, TRIG>,
        inner: PendingState,
        tracker_update: Option<TrackerUpdate>,
    ) -> anyhow::Result<()> {
        let pinned = self.assigner.pinned_proposer(self.sender_eoa);

        if let Some(update) = tracker_update {
            match update {
                TrackerUpdate::Mined {
                    block_number,
                    attempt_number,
                    gas_limit,
                    gas_used,
                    tx_hash,
                    nonce,
                    is_success,
                    ..
                } => {
                    info!(
                        "Bundle transaction mined: block number {block_number}, attempt number {attempt_number}, gas limit {gas_limit:?}, gas used {gas_used:?}, tx hash {tx_hash}, nonce {nonce}, success {is_success}"
                    );

                    if is_success {
                        self.increment_counter("builder_bundle_txns_success", &pinned, 1);
                    } else {
                        self.increment_counter("builder_bundle_txns_reverted", &pinned, 1);
                    }
                    if let Some(limit) = gas_limit {
                        self.increment_counter("builder_bundle_gas_limit", &pinned, limit);
                    }
                    if let Some(used) = gas_used {
                        self.increment_counter("builder_bundle_gas_used", &pinned, used);
                    }

                    if !is_success && let Err(e) = self.process_revert(tx_hash, &pinned).await {
                        warn!(
                            "Failed to process revert for bundle transaction {tx_hash:?}: {e:#?}"
                        );
                    }

                    self.emit(
                        BuilderEvent::transaction_mined(
                            self.builder_tag.clone(),
                            tx_hash,
                            nonce,
                            block_number,
                        ),
                        &pinned,
                    );
                    state.bundle_mined(block_number, attempt_number, tx_hash);
                }
                TrackerUpdate::LatestTxDropped { nonce } => {
                    info!("Latest transaction dropped, starting new bundle attempt");
                    self.emit(
                        BuilderEvent::latest_transaction_dropped(self.builder_tag.clone(), nonce),
                        &pinned,
                    );
                    self.increment_counter("builder_bundle_txns_dropped", &pinned, 1);
                    // try again, increasing fees
                    state.update(InnerState::Building(inner.to_building()));
                }
                TrackerUpdate::NonceUsedForOtherTx { nonce } => {
                    info!("Nonce used externally, starting new bundle attempt");
                    self.emit(
                        BuilderEvent::nonce_used_for_other_transaction(
                            self.builder_tag.clone(),
                            nonce,
                        ),
                        &pinned,
                    );
                    self.increment_counter("builder_bundle_txns_nonce_used", &pinned, 1);
                    state.reset();
                }
            }
        } else if state.block_number() >= inner.until {
            // start replacement, don't wait for trigger. Continue
            // to attempt until there are no longer any UOs priced high enough
            // to bundle.
            info!(
                "Not mined after {} blocks, increasing fees, attempt: {}",
                self.settings.max_blocks_to_wait_for_mine,
                inner.fee_increase_count + 1
            );
            self.increment_counter("builder_bundle_txn_fee_increases", &pinned, 1);
            state.update(InnerState::Building(inner.to_building()))
        }

        Ok(())
    }

    async fn handle_cancelling_state<TRIG: Trigger>(
        &mut self,
        state: &mut SenderMachineState<T, TRIG>,
        inner: CancellingState,
    ) -> anyhow::Result<()> {
        let pinned = self.assigner.pinned_proposer(self.sender_eoa);

        info!(
            "Cancelling last transaction, attempt {}",
            inner.fee_increase_count
        );

        // Use the tracker's required_fees as a floor so the cancellation tx
        // is priced above any pending transaction (avoids a wasted ReplacementUnderpriced round-trip).
        let required_fees = state.transaction_tracker.get_state()?.required_fees;
        let (estimated_fees, _) = self
            .fee_estimator
            .required_bundle_fees(state.block_hash(), required_fees)
            .await
            .unwrap_or_default();

        let cancel_res = state
            .transaction_tracker
            .cancel_transaction(estimated_fees)
            .await;

        match cancel_res {
            Ok(Some(_)) => {
                info!("Cancellation transaction sent, waiting for confirmation");
                self.increment_counter("builder_cancellation_txns_sent", &pinned, 1);

                state.update(InnerState::CancelPending(inner.to_cancel_pending(
                    state.block_number() + self.settings.max_blocks_to_wait_for_mine,
                )));
            }
            Ok(None) => {
                info!("Soft cancellation or no transaction to cancel, starting new bundle attempt");
                // release all operations after the soft cancellation
                self.assigner.release_all(self.sender_eoa);
                self.increment_counter("builder_soft_cancellations", &pinned, 1);
                state.reset();
            }
            Err(TransactionTrackerError::Rejected)
            | Err(TransactionTrackerError::Underpriced)
            | Err(TransactionTrackerError::ReplacementUnderpriced) => {
                info!(
                    "Transaction underpriced/rejected during cancellation, trying again. {cancel_res:?}"
                );
                if inner.fee_increase_count >= self.settings.max_cancellation_fee_increases {
                    // abandon the cancellation
                    warn!(
                        "Abandoning cancellation after max fee increases {}, starting new bundle attempt",
                        inner.fee_increase_count
                    );
                    self.increment_counter("builder_cancellations_abandoned", &pinned, 1);
                    self.assigner.release_all(self.sender_eoa);
                    state.reset();
                } else {
                    // Increase fees again
                    info!(
                        "Cancellation increasing fees, attempt: {}",
                        inner.fee_increase_count + 1
                    );
                    state.update(InnerState::Cancelling(inner.to_self()));
                }
            }
            Err(TransactionTrackerError::NonceTooLow) => {
                // reset the transaction tracker and try again
                info!("Nonce too low during cancellation, starting new bundle attempt");
                self.assigner.release_all(self.sender_eoa);
                state.reset();
            }
            Err(TransactionTrackerError::InsufficientFunds) => {
                error!("Insufficient funds during cancellation, starting new bundle attempt");
                self.increment_counter("builder_cancellation_txns_failed", &pinned, 1);
                self.assigner.release_all(self.sender_eoa);
                state.reset();
            }
            Err(TransactionTrackerError::ConditionNotMet) => {
                error!(
                    "Unexpected condition not met during cancellation, starting new bundle attempt"
                );
                self.increment_counter("builder_cancellation_txns_failed", &pinned, 1);
                self.assigner.release_all(self.sender_eoa);
                state.reset();
            }
            Err(TransactionTrackerError::Other(e)) => {
                error!("Failed to cancel transaction, moving back to building state: {e:#?}");
                self.increment_counter("builder_cancellation_txns_failed", &pinned, 1);
                self.assigner.release_all(self.sender_eoa);
                state.reset();
            }
        }

        Ok(())
    }

    async fn handle_cancel_pending_state<TRIG: Trigger>(
        &mut self,
        state: &mut SenderMachineState<T, TRIG>,
        inner: CancelPendingState,
        tracker_update: Option<TrackerUpdate>,
    ) -> anyhow::Result<()> {
        let pinned = self.assigner.pinned_proposer(self.sender_eoa);

        // check for transaction update
        if let Some(update) = tracker_update {
            match update {
                TrackerUpdate::Mined {
                    gas_used,
                    gas_price,
                    ..
                } => {
                    let fee = gas_used
                        .zip(gas_price)
                        .map(|(used, price)| used as u128 * price);
                    info!("Cancellation transaction mined. Price (wei) {fee:?}");
                    self.increment_counter("builder_cancellation_txns_mined", &pinned, 1);
                    if let Some(fee) = fee {
                        self.increment_counter(
                            "builder_cancellation_txns_total_fee",
                            &pinned,
                            fee.min(u64::MAX as u128) as u64,
                        );
                    };
                }
                TrackerUpdate::LatestTxDropped { .. } => {
                    // If a cancellation gets dropped, move to bundling state as there is no
                    // longer a pending transaction
                    info!("Cancellation transaction dropped, starting new bundle attempt");
                }
                TrackerUpdate::NonceUsedForOtherTx { .. } => {
                    // If a nonce is used externally, move to bundling state as there is no longer
                    // a pending transaction
                    info!("Nonce used externally while cancelling, starting new bundle attempt");
                }
            }
            state.reset();
        } else if state.block_number() >= inner.until {
            if inner.fee_increase_count >= self.settings.max_cancellation_fee_increases {
                // abandon the cancellation
                // release all operations after the cancellation abandonment
                self.assigner.release_all(self.sender_eoa);
                warn!(
                    "Abandoning cancellation after max fee increases {}, starting new bundle attempt",
                    inner.fee_increase_count
                );
                self.increment_counter("builder_cancellations_abandoned", &pinned, 1);
                state.reset();
            } else {
                // start replacement, don't wait for trigger
                info!(
                    "Cancellation not mined after {} blocks, increasing fees, attempt: {}",
                    self.settings.max_blocks_to_wait_for_mine,
                    inner.fee_increase_count + 1
                );
                state.update(InnerState::Cancelling(inner.to_cancelling()));
            }
        }

        Ok(())
    }

    async fn send_bundle<TRIG: Trigger>(
        &mut self,
        state: &mut SenderMachineState<T, TRIG>,
        fee_increase_count: u64,
    ) -> anyhow::Result<SendBundleAttemptResult> {
        // Get tracker state first to pass required_fees to assign_work
        let TrackerState {
            nonce,
            required_fees,
            balance,
        } = state.transaction_tracker.get_state()?;

        // Estimate fresh fees, using tracker's required_fees as a floor so the
        // 10% replacement bump is respected when a prior tx exists.
        let (bundle_fees, base_fee) = self
            .fee_estimator
            .required_bundle_fees(state.block_hash(), required_fees)
            .await?;
        let is_replacement = fee_increase_count > 0;
        let required_op_fees = if is_replacement {
            bundle_fees
        } else {
            self.fee_estimator.required_op_fees(bundle_fees)
        };
        let assignment = self
            .assigner
            .assign_work(self.sender_eoa, state.block_number(), required_op_fees)
            .await?;

        let result = match assignment {
            AssignmentResult::Assigned(assignment) => {
                let entry_point = assignment.entry_point;
                let filter_id = assignment.filter_id;
                let ops = assignment.operations;

                // Build and send bundle. Keep this as a single result path so assigner
                // cleanup runs for all outcomes, including hard errors.
                let proposer_key = (entry_point, filter_id.clone());
                if let Some(proposer) = self.proposers.get(&proposer_key) {
                    // Clear condition_not_met once make_bundle completes (success or
                    // NoOperationsAfterFeeFilter), and keep it set for hard failures so the
                    // next attempt still re-checks conditions.
                    let condition_not_met = state.condition_not_met;
                    match proposer
                        .make_bundle(
                            ops,
                            self.sender_eoa,
                            nonce,
                            state.block_hash(),
                            balance,
                            bundle_fees,
                            base_fee,
                            required_op_fees,
                            condition_not_met,
                        )
                        .await
                    {
                        Ok(bundle_data) => {
                            state.condition_not_met = false;
                            self.send_bundle_from_data(
                                state,
                                entry_point,
                                bundle_data,
                                nonce,
                                fee_increase_count,
                            )
                            .await
                        }
                        Err(BundleProposerError::NoOperationsAfterFeeFilter) => {
                            state.condition_not_met = false;
                            Ok(SendBundleAttemptResult::NoOperationsAfterFeeFilter)
                        }
                        Err(e) => Err(anyhow::anyhow!("Failed to make bundle: {e:?}")),
                    }
                } else {
                    Err(anyhow::anyhow!(
                        "Unknown entrypoint config: {entry_point:?}, filter_id: {filter_id:?}"
                    ))
                }
            }
            AssignmentResult::NoOperations => Ok(SendBundleAttemptResult::NoOperationsInitially),
            AssignmentResult::NoOperationsAfterFeeFilter => {
                Ok(SendBundleAttemptResult::NoOperationsAfterFeeFilter)
            }
        };

        // Confirm senders used in successful bundles, drop all unused locks.
        // Lock release policy (release_all vs keep-for-retry) is handled by
        // handle_building_state which has state-machine context.
        match &result {
            Ok(SendBundleAttemptResult::Success(ops)) => {
                self.assigner
                    .confirm_senders_drop_unused(self.sender_eoa, ops.iter().map(|op| &op.0))?;
            }
            _ => {
                self.assigner
                    .confirm_senders_drop_unused(self.sender_eoa, &[])?;
            }
        }

        result
    }

    /// Sends a bundle using BundleData from the type-erased proposer.
    async fn send_bundle_from_data<TRIG: Trigger>(
        &mut self,
        state: &mut SenderMachineState<T, TRIG>,
        entry_point: Address,
        bundle_data: BundleData,
        nonce: u64,
        fee_increase_count: u64,
    ) -> anyhow::Result<SendBundleAttemptResult> {
        // Handle rejected ops and entity updates
        let remove_ops_future = async {
            if bundle_data.rejected_op_hashes.is_empty() {
                return;
            }
            let result = self
                .pool
                .remove_ops(entry_point, bundle_data.rejected_op_hashes.clone())
                .await;
            if let Err(error) = result {
                error!("Failed to remove rejected ops from pool: {error}");
            }
        };

        let update_entities_future = async {
            if bundle_data.entity_updates.is_empty() {
                return;
            }
            let result = self
                .pool
                .update_entities(entry_point, bundle_data.entity_updates.clone())
                .await;
            if let Err(error) = result {
                error!("Failed to update entities in pool: {error}");
            }
        };

        join!(remove_ops_future, update_entities_future);

        // Check if bundle is empty
        if bundle_data.is_empty() {
            if !bundle_data.rejected_op_hashes.is_empty() || !bundle_data.entity_updates.is_empty()
            {
                info!(
                    "Empty bundle with {} rejected ops and {} rejected entities. Removed from pool.",
                    bundle_data.rejected_op_hashes.len(),
                    bundle_data.entity_updates.len()
                );
            }
            self.emit_for_entrypoint(
                entry_point,
                BuilderEvent::formed_bundle(
                    self.builder_tag.clone(),
                    None,
                    nonce,
                    fee_increase_count,
                    Some(bundle_data.gas_fees),
                ),
            );
            return Ok(SendBundleAttemptResult::NoOperationsAfterSimulation);
        }

        let tx = bundle_data.tx;
        let gas_fees = bundle_data.gas_fees;
        let ops = bundle_data.ops;

        let num_rejected = bundle_data.rejected_op_hashes.len();
        let num_updated_entities = bundle_data.entity_updates.len();
        info!(
            "Selected bundle for {entry_point:?}: nonce: {nonce:?}. Ops: {ops:?}. Num rejected: {num_rejected}. Num updated entities: {num_updated_entities}"
        );

        // Send the transaction
        let send_result = state
            .transaction_tracker
            .send_transaction(
                tx.clone(),
                &bundle_data.expected_storage,
                state.block_number(),
            )
            .await;
        self.increment_counter_ep("builder_bundle_txns_sent", entry_point, 1);

        let bundle_data_size = tx.input.input().map_or(0, |data| data.len());
        let tx_size = eth::calculate_transaction_size(
            bundle_data_size,
            tx.authorization_list.as_ref().map_or(0, |list| list.len()),
        );
        self.record_histogram_ep("builder_bundle_txn_size_bytes", entry_point, tx_size as f64);

        match send_result {
            Ok(tx_hash) => {
                let ops = Arc::new(ops);

                self.emit_for_entrypoint(
                    entry_point,
                    BuilderEvent::formed_bundle(
                        self.builder_tag.clone(),
                        Some(BundleTxDetails {
                            tx_hash,
                            tx,
                            ops: ops.clone(),
                        }),
                        nonce,
                        fee_increase_count,
                        Some(gas_fees),
                    ),
                );

                // Notify the pool about the pending bundle
                let uo_hashes: Vec<B256> = ops.iter().map(|(_, hash)| *hash).collect();
                if let Err(e) = self
                    .pool
                    .notify_pending_bundle(
                        entry_point,
                        tx_hash,
                        state.block_number(),
                        self.sender_eoa,
                        uo_hashes,
                    )
                    .await
                {
                    warn!("Failed to notify pool of pending bundle: {e:?}");
                }

                Ok(SendBundleAttemptResult::Success(ops))
            }
            Err(TransactionTrackerError::NonceTooLow) => {
                self.increment_counter_ep("builder_bundle_txn_nonce_too_low", entry_point, 1);
                warn!("Bundle attempt nonce too low");
                Ok(SendBundleAttemptResult::NonceTooLow)
            }
            Err(TransactionTrackerError::Underpriced) => {
                self.increment_counter_ep("builder_bundle_txn_underpriced", entry_point, 1);
                warn!("Bundle attempt underpriced");
                Ok(SendBundleAttemptResult::Underpriced)
            }
            Err(TransactionTrackerError::ReplacementUnderpriced) => {
                self.increment_counter_ep("builder_bundle_replacement_underpriced", entry_point, 1);
                warn!("Bundle attempt replacement transaction underpriced");
                Ok(SendBundleAttemptResult::ReplacementUnderpriced)
            }
            Err(TransactionTrackerError::ConditionNotMet) => {
                self.increment_counter_ep("builder_bundle_txn_condition_not_met", entry_point, 1);
                warn!("Bundle attempt condition not met");
                Ok(SendBundleAttemptResult::ConditionNotMet)
            }
            Err(TransactionTrackerError::Rejected) => {
                self.increment_counter_ep("builder_bundle_txn_rejected", entry_point, 1);
                warn!("Bundle attempt rejected");
                Ok(SendBundleAttemptResult::Rejected)
            }
            Err(TransactionTrackerError::InsufficientFunds) => {
                self.increment_counter_ep("builder_bundle_txn_insufficient_funds", entry_point, 1);
                error!("Bundle attempt insufficient funds");
                Ok(SendBundleAttemptResult::InsufficientFunds)
            }
            Err(TransactionTrackerError::Other(e)) => {
                error!("Failed to send bundle with unexpected error: {e:?}");
                if Self::is_intrinsic_gas_too_low_error(&e) {
                    let tx_bytes = tx.input.input().map_or_else(
                        || String::from("0x"),
                        |data| format!("0x{}", hex::encode(data)),
                    );
                    error!(
                        "Bundle transaction bytes for intrinsic gas too low: tx_bytes={tx_bytes}"
                    );
                }
                Err(e)
            }
        }
    }

<<<<<<< HEAD
    fn is_intrinsic_gas_too_low_error(error: &anyhow::Error) -> bool {
        format!("{error:#}")
            .to_lowercase()
            .contains("intrinsic gas too low")
    }

    /// Builds a bundle and returns some metadata and the transaction to send
    /// it, or `None` if there are no valid operations available.
    async fn get_bundle_tx(
        &mut self,
        nonce: u64,
        bundle: Bundle<EP::UO>,
    ) -> anyhow::Result<Option<BundleTx>> {
        let remove_ops_future = async {
            if bundle.rejected_ops.is_empty() {
                return;
            }

            let result = self.remove_ops_from_pool(&bundle.rejected_ops).await;
            if let Err(error) = result {
                error!("Failed to remove rejected ops from pool: {error}");
            }
        };

        let update_entities_future = async {
            if bundle.entity_updates.is_empty() {
                return;
            }

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
        let ops: Vec<_> = bundle
            .iter_ops()
            .map(|op| (op.sender(), op.hash()))
            .collect();

        let mut tx = self.ep_providers.entry_point().get_send_bundle_transaction(
            bundle.ops_per_aggregator,
            self.sender_eoa,
            bundle.gas_estimate,
            bundle.gas_fees,
            self.submission_proxy.as_ref().map(|p| p.address()),
        );
        tx = tx.nonce(nonce);

        info!(
            "Selected bundle: nonce: {:?}. Ops: {:?}. Num rejected ops: {:?}. Num updated entities: {:?}",
            nonce,
            ops,
            bundle.rejected_ops.len(),
            bundle.entity_updates.len()
        );

        Ok(Some(BundleTx {
            tx,
            expected_storage: bundle.expected_storage,
            ops,
        }))
=======
    /// Emits an event for a specific entrypoint (used for shared signer support)
    fn emit_for_entrypoint(&self, entry_point: Address, event: BuilderEvent) {
        let _ = self
            .event_sender
            .send(WithEntryPoint { entry_point, event });
>>>>>>> 20e4b8a9 (feat(builder): implement signer sharing in builder)
    }

    async fn remove_ops_from_pool_by_hash(
        &self,
        ep_address: Address,
        hashes: Vec<B256>,
    ) -> anyhow::Result<()> {
        self.pool
            .remove_ops(ep_address, hashes)
            .await
            .context("builder should remove rejected ops from pool")
    }

    async fn process_revert(
        &self,
        tx_hash: B256,
        pinned_proposer: &Option<ProposerKey>,
    ) -> anyhow::Result<()> {
        warn!("Bundle transaction {tx_hash:?} reverted onchain");

        let proposer_key = pinned_proposer
            .clone()
            .context("No entry point for revert processing")?;
        let ep_address = proposer_key.0;

        let filter_id = &proposer_key.1;
        let proposer = self.proposers.get(&proposer_key).context(format!(
            "Unknown entry point config: {ep_address:?}, filter_id: {filter_id:?}"
        ))?;

        let to_remove = proposer.process_revert(tx_hash).await?;

        self.remove_ops_from_pool_by_hash(ep_address, to_remove)
            .await
    }

    fn emit(&self, event: BuilderEvent, pinned_proposer: &Option<ProposerKey>) {
        // Use the pinned proposer entry point, defaulting to zero address if none
        let entry_point = pinned_proposer
            .as_ref()
            .map(|(addr, _)| *addr)
            .unwrap_or(Address::ZERO);
        let _ = self
            .event_sender
            .send(WithEntryPoint { entry_point, event });
    }
}

struct SenderMachineState<T, TRIG> {
    trigger: TRIG,
    pub transaction_tracker: T,
    send_bundle_response: Option<oneshot::Sender<SendBundleResult>>,
    inner: InnerState,
    requires_reset: bool,
    /// Flag indicating a condition was not met on last bundle attempt
    /// Passed to proposer on next make_bundle call to re-check conditions
    condition_not_met: bool,
}

impl<T: TransactionTracker, TRIG: Trigger> SenderMachineState<T, TRIG> {
    fn new(trigger: TRIG, transaction_tracker: T) -> Self {
        Self {
            trigger,
            transaction_tracker,
            send_bundle_response: None,
            inner: InnerState::new(),
            requires_reset: false,
            condition_not_met: false,
        }
    }

    // Custom update function, use to move to a non-building state
    fn update(&mut self, inner: InnerState) {
        self.inner = inner;
    }

    /*
     * Reset moves
     */

    // Move to the initial state, will wait for the next trigger.
    // Preserves the transaction tracker state.
    fn initial(&mut self) {
        self.condition_not_met = false;
        self.inner = InnerState::new();
    }

    // Resets the state and transaction tracker, doesn't wait for next trigger.
    // Callers must call `assigner.release_all()` before this to avoid leaking sender locks.
    fn reset(&mut self) {
        self.requires_reset = true;
        self.condition_not_met = false;
        let building_state = BuildingState {
            wait_for_trigger: false,
            fee_increase_count: 0,
            underpriced_info: None,
        };
        self.inner = InnerState::Building(building_state);
    }

    /*
     * Completion moves, these always end back at the Building state and send a result.
     */

    // Sends an error result and moves to initial state
    fn bundle_error(&mut self, err: anyhow::Error) {
        self.send_result(SendBundleResult::Error(err));
        self.initial();
    }

    // Sends a success result and moves to initial state
    //
    // In auto mode, will not wait for trigger and will move to the next bundle.
    // In manual mode, will wait for the next trigger
    fn bundle_mined(&mut self, block_number: u64, attempt_number: u64, tx_hash: B256) {
        self.send_result(SendBundleResult::Success {
            block_number,
            attempt_number,
            tx_hash,
        });
        self.condition_not_met = false;
        self.update(InnerState::Building(BuildingState {
            wait_for_trigger: self.trigger.builder_must_wait_for_trigger(),
            fee_increase_count: 0,
            underpriced_info: None,
        }));
    }

    // No operations are available, send result, move to initial state
    // Preserves fee/underpriced info for further rounds.
    fn no_operations(&mut self) {
        self.send_result(SendBundleResult::NoOperationsInitially);
        self.condition_not_met = false;

        self.inner = match &self.inner {
            InnerState::Building(s) => InnerState::Building(BuildingState {
                wait_for_trigger: true,
                fee_increase_count: s.fee_increase_count,
                underpriced_info: s.underpriced_info,
            }),
            _ => {
                panic!("invalid state transition, no_operations called when not in building state")
            }
        }
    }

    /*
     * Helpers
     */

    async fn wait_for_trigger(&mut self) -> anyhow::Result<Option<TrackerUpdate>> {
        if self.requires_reset {
            self.transaction_tracker.reset().await;
            self.requires_reset = false;
        }

        match &self.inner {
            InnerState::Building(s) => {
                if !s.wait_for_trigger {
                    return Ok(None);
                }

                self.send_bundle_response = self.trigger.wait_for_trigger().await?;

                let Some(update) = self.find_address_update() else {
                    return Ok(None);
                };

                self.transaction_tracker
                    .process_update(&update)
                    .await
                    .map_err(|e| anyhow::anyhow!("transaction tracker update error {e:?}"))
            }
            InnerState::Pending(..) | InnerState::CancelPending(..) => {
                self.trigger.wait_for_block().await?;

                let Some(update) = self.find_address_update() else {
                    return Ok(None);
                };

                self.transaction_tracker
                    .process_update(&update)
                    .await
                    .map_err(|e| anyhow::anyhow!("transaction tracker update error {e:?}"))
            }
            InnerState::Cancelling(..) => Ok(None),
        }
    }

    fn block_number(&self) -> u64 {
        self.trigger.last_block().block_number
    }

    fn block_hash(&self) -> B256 {
        self.trigger.last_block().block_hash
    }

    fn send_result(&mut self, result: SendBundleResult) {
        if let Some(r) = self.send_bundle_response.take()
            && r.send(result).is_err()
        {
            error!("Failed to send bundle result to manual caller");
        }
    }

    fn find_address_update(&self) -> Option<AddressUpdate> {
        self.trigger
            .last_block()
            .address_updates
            .iter()
            .find(|u| u.address == self.transaction_tracker.address())
            .cloned()
    }
}

// State of the sender loop
enum InnerState {
    // Building a bundle, optionally waiting for a trigger to send it
    Building(BuildingState),
    // Waiting for a bundle to be mined
    Pending(PendingState),
    // Cancelling the last transaction
    Cancelling(CancellingState),
    // Waiting for a cancellation transaction to be mined
    CancelPending(CancelPendingState),
}

impl InnerState {
    fn new() -> Self {
        InnerState::Building(BuildingState {
            wait_for_trigger: true,
            fee_increase_count: 0,
            underpriced_info: None,
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct BuildingState {
    wait_for_trigger: bool,
    fee_increase_count: u64,
    underpriced_info: Option<UnderpricedInfo>,
}

#[derive(Debug, Clone, Copy)]
struct UnderpricedInfo {
    since_block: u64,
    rounds: u64,
}

impl BuildingState {
    // Transition to pending state
    fn to_pending(self, until: u64) -> PendingState {
        PendingState {
            until,
            fee_increase_count: self.fee_increase_count,
        }
    }

    // Transition to cancelling state
    fn to_cancelling(self) -> CancellingState {
        CancellingState {
            fee_increase_count: 0,
        }
    }

    // Retry the build
    fn retry(mut self) -> Self {
        self.wait_for_trigger = false;
        self
    }

    // Mark as underpriced
    //
    // The next state will wait for a trigger to reduce bundle building loops
    fn underpriced(self, block_number: u64) -> Self {
        let ui = if let Some(underpriced_info) = self.underpriced_info {
            underpriced_info
        } else {
            UnderpricedInfo {
                since_block: block_number,
                rounds: 1,
            }
        };

        BuildingState {
            wait_for_trigger: true,
            fee_increase_count: self.fee_increase_count + 1,
            underpriced_info: Some(ui),
        }
    }

    // Finalize an underpriced round.
    //
    // This will clear out the count of fee increases and increment the count of underpriced rounds.
    // Use this when we are in an underpriced state, but there are no longer any UOs available to bundle.
    fn underpriced_round(self) -> Self {
        let mut underpriced_info = self
            .underpriced_info
            .expect("underpriced_info must be Some when calling underpriced_round");
        underpriced_info.rounds += 1;

        BuildingState {
            wait_for_trigger: true,
            fee_increase_count: 0,
            underpriced_info: Some(underpriced_info),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct PendingState {
    until: u64,
    fee_increase_count: u64,
}

impl PendingState {
    fn to_building(self) -> BuildingState {
        BuildingState {
            wait_for_trigger: false,
            fee_increase_count: self.fee_increase_count + 1,
            underpriced_info: None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct CancellingState {
    fee_increase_count: u64,
}

impl CancellingState {
    fn to_self(mut self) -> Self {
        self.fee_increase_count += 1;
        self
    }

    fn to_cancel_pending(self, until: u64) -> CancelPendingState {
        CancelPendingState {
            until,
            fee_increase_count: self.fee_increase_count,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct CancelPendingState {
    until: u64,
    fee_increase_count: u64,
}

impl CancelPendingState {
    fn to_cancelling(self) -> CancellingState {
        CancellingState {
            fee_increase_count: self.fee_increase_count + 1,
        }
    }
}

#[async_trait]
#[cfg_attr(test, automock)]
trait Trigger {
    // Wait for the next trigger to send a bundle
    // Depending on the mode this will either wait for the next block, a timer tick, or a manual trigger
    async fn wait_for_trigger(
        &mut self,
    ) -> anyhow::Result<Option<oneshot::Sender<SendBundleResult>>>;

    // Wait for the next block
    async fn wait_for_block(&mut self) -> anyhow::Result<NewHead>;

    // Whether the builder must wait for a trigger to send a bundle
    //
    // When in auto mode the builder doesn't need to wait for a trigger to send a bundle
    fn builder_must_wait_for_trigger(&self) -> bool;

    // Get the last block processed by the trigger
    fn last_block(&self) -> &NewHead;
}

struct BundleSenderTrigger {
    bundling_mode: BundlingMode,
    block_rx: UnboundedReceiver<NewHead>,
    bundle_action_receiver: mpsc::Receiver<BundleSenderAction>,
    timer: tokio::time::Interval,
    last_block: NewHead,
}

#[async_trait]
impl Trigger for BundleSenderTrigger {
    async fn wait_for_trigger(
        &mut self,
    ) -> anyhow::Result<Option<oneshot::Sender<SendBundleResult>>> {
        let mut send_bundle_response: Option<oneshot::Sender<SendBundleResult>> = None;
        self.timer.reset();

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
                            info!("changing bundling mode to {mode:?}");
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

    fn builder_must_wait_for_trigger(&self) -> bool {
        match self.bundling_mode {
            BundlingMode::Manual => true,
            BundlingMode::Auto => false,
        }
    }

    fn last_block(&self) -> &NewHead {
        &self.last_block
    }
}

impl BundleSenderTrigger {
    async fn new<P: Pool, T: TaskSpawner>(
        task_spawner: &T,
        pool_client: &P,
        bundle_action_receiver: mpsc::Receiver<BundleSenderAction>,
        timer_interval: Duration,
        sender_eoa: Address,
    ) -> anyhow::Result<Self> {
        let Ok(new_heads) = pool_client.subscribe_new_heads(vec![sender_eoa]).await else {
            error!("Failed to subscribe to new blocks");
            bail!("failed to subscribe to new blocks");
        };
        let (block_tx, block_rx) = mpsc::unbounded_channel();

        task_spawner.spawn_critical(
            "block stream",
            Box::pin(Self::block_stream_task(new_heads, block_tx)),
        );

        Ok(Self {
            bundling_mode: BundlingMode::Auto,
            block_rx,
            bundle_action_receiver,
            timer: tokio::time::interval(timer_interval),
            last_block: NewHead {
                block_hash: B256::ZERO,
                block_number: 0,
                address_updates: vec![],
            },
        })
    }

    async fn block_stream_task(
        mut new_heads: Pin<Box<dyn Stream<Item = NewHead> + Send>>,
        block_tx: UnboundedSender<NewHead>,
    ) {
        loop {
            match new_heads.next().await {
                Some(b) => {
                    if block_tx.send(b).is_err() {
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
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{U256, address};
    use mockall::Sequence;
    use rundler_provider::LatestFeeEstimate;
    use rundler_types::{
        EntityInfos, GasFees, UserOperationPermissions, ValidTimeRange,
        chain::ChainSpec,
        pool::{AddressUpdate, MockPool, PoolOperation, PoolOperationSummary},
        v0_6::UserOperation,
    };
    use tokio::sync::{broadcast, mpsc};

    use super::*;
    use crate::{
        assigner::{AssignmentResult, EntrypointInfo},
        bundle_proposer::{BundleData, MockBundleProposerT},
        bundle_sender::{BundleSenderImpl, MockTrigger},
        transaction_tracker::MockTransactionTracker,
    };

    struct TestFeeEstimator;

    #[async_trait]
    impl FeeEstimator for TestFeeEstimator {
        async fn required_bundle_fees(
            &self,
            _block_hash: B256,
            min_fees: Option<GasFees>,
        ) -> anyhow::Result<(GasFees, u128)> {
            // Return min_fees if provided (simulates floor from tracker),
            // otherwise return zero fees.
            Ok((min_fees.unwrap_or_default(), 0))
        }

        async fn latest_bundle_fees(&self) -> anyhow::Result<(GasFees, u128)> {
            Ok((GasFees::default(), 0))
        }

        async fn latest_fee_estimate(&self) -> anyhow::Result<LatestFeeEstimate> {
            Ok(LatestFeeEstimate {
                block_number: 0,
                base_fee: 0,
                required_base_fee: 0,
                required_priority_fee: 0,
            })
        }

        fn required_op_fees(&self, bundle_fees: GasFees) -> GasFees {
            bundle_fees
        }
    }

    const ENTRY_POINT_ADDRESS_V0_6: Address = address!("5FF137D4b0FDCD49DcA30c7CF57E578a026d2789");
    const ENTRY_POINT_ADDRESS_V0_7: Address = address!("0000000000000000000000000000000000000007");

    #[tokio::test]
    async fn test_empty_send() {
        let Mocks {
            mut mock_proposer_t,
            mut mock_tracker,
            mut mock_trigger,
            mut mock_pool,
        } = new_mocks();

        // block 0
        add_trigger_no_update_last_block(&mut mock_trigger, &mut Sequence::new(), 0);

        setup_tracker_default(&mut mock_tracker);
        mock_tracker
            .expect_num_pending_transactions()
            .return_const(0_usize);

        mock_pool
            .expect_get_ops_summaries()
            .times(1)
            .returning(|_, _, _| {
                Ok(vec![pool_op_summary(
                    ENTRY_POINT_ADDRESS_V0_6,
                    Address::ZERO,
                )])
            });
        mock_pool
            .expect_get_ops_by_hashes()
            .times(1)
            .returning(|_, _| Ok(vec![demo_pool_op()]));

        mock_make_bundle(&mut mock_proposer_t, 1, vec![]);

        let mut sender = new_sender(mock_proposer_t, mock_pool);

        // start in building state
        let mut state = SenderMachineState::new(mock_trigger, mock_tracker);

        sender.step_state(&mut state).await.unwrap();

        // empty bundle shouldn't move out of building state
        assert!(matches!(
            state.inner,
            InnerState::Building(BuildingState {
                wait_for_trigger: true,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn test_send() {
        let Mocks {
            mut mock_proposer_t,
            mut mock_tracker,
            mut mock_trigger,
            mut mock_pool,
        } = new_mocks();

        // block 0
        add_trigger_no_update_last_block(&mut mock_trigger, &mut Sequence::new(), 0);

        setup_tracker_default(&mut mock_tracker);

        mock_pool
            .expect_get_ops_summaries()
            .times(1)
            .returning(|_, _, _| {
                Ok(vec![pool_op_summary(
                    ENTRY_POINT_ADDRESS_V0_6,
                    Address::ZERO,
                )])
            });
        mock_pool
            .expect_get_ops_by_hashes()
            .times(1)
            .returning(|_, _| Ok(vec![demo_pool_op()]));
        mock_pool
            .expect_notify_pending_bundle()
            .times(1)
            .returning(|_, _, _, _, _| Ok(()));

        mock_make_bundle(&mut mock_proposer_t, 1, vec![(Address::ZERO, B256::ZERO)]);

        // should send the bundle txn
        mock_tracker
            .expect_send_transaction()
            .returning(|_, _, _| Box::pin(async { Ok(B256::ZERO) }));

        let mut sender = new_sender(mock_proposer_t, mock_pool);

        // start in building state
        let mut state = SenderMachineState::new(mock_trigger, mock_tracker);

        sender.step_state(&mut state).await.unwrap();

        // end in the pending state
        assert!(matches!(
            state.inner,
            InnerState::Pending(PendingState {
                until: 3, // block 0 + wait 3 blocks
                ..
            })
        ));
    }

    #[tokio::test]
    async fn test_replacement_pins_entrypoint() {
        let Mocks {
            mut mock_proposer_t,
            mut mock_tracker,
            mut mock_trigger,
            mut mock_pool,
        } = new_mocks();

        let filter_id = Some("filter-a".to_string());

        // Set up trigger to return block info (only need last_block for send_bundle)
        mock_trigger.expect_last_block().return_const(new_head(0));

        mock_tracker.expect_get_state().returning(|| {
            Ok(TrackerState {
                nonce: 1,
                balance: U256::ZERO,
                required_fees: None,
            })
        });
        mock_tracker
            .expect_num_pending_transactions()
            .return_const(0_usize);

        let pinned_entry_point = ENTRY_POINT_ADDRESS_V0_6;
        let other_entry_point = ENTRY_POINT_ADDRESS_V0_7;
        let expected_filter = filter_id.clone();

        // The pinned EP is queried once for the replacement attempt (via assign_work_for_entrypoint).
        // The other EP is never queried since the builder is pinned.
        mock_pool
            .expect_get_ops_summaries()
            .withf(move |entry_point, _, filter| {
                *entry_point == pinned_entry_point
                    && filter.as_deref() == expected_filter.as_deref()
            })
            .times(1)
            .returning(move |_, _, _| Ok(vec![pool_op_summary(pinned_entry_point, Address::ZERO)]));
        mock_pool
            .expect_get_ops_summaries()
            .withf(move |entry_point, _, _| *entry_point == other_entry_point)
            .times(0);

        mock_pool
            .expect_get_ops_by_hashes()
            .times(1)
            .returning(|_, _| Ok(vec![demo_pool_op()]));

        mock_make_bundle(&mut mock_proposer_t, 1, vec![]);

        let mut proposers = HashMap::new();
        proposers.insert(
            (pinned_entry_point, filter_id.clone()),
            Box::new(mock_proposer_t) as Box<dyn BundleProposerT>,
        );

        let entrypoints = vec![
            EntrypointInfo {
                address: pinned_entry_point,
                filter_id: filter_id.clone(),
            },
            EntrypointInfo {
                address: other_entry_point,
                filter_id: None,
            },
        ];

        let mut sender = new_sender_with_entrypoints(mock_pool, entrypoints, proposers);

        // Pre-establish pin by confirming sender locks in the assigner.
        // This simulates a prior successful bundle on the pinned EP.
        sender.assigner.test_establish_pin(
            Address::default(), // matches sender_eoa
            &[Address::ZERO],
            (pinned_entry_point, filter_id),
        );

        let mut state = SenderMachineState::new(mock_trigger, mock_tracker);

        let result = sender.send_bundle(&mut state, 1).await.unwrap();
        assert!(matches!(
            result,
            SendBundleAttemptResult::NoOperationsAfterSimulation
        ));
    }

    #[tokio::test]
    async fn test_no_ops_unpins_entrypoint_and_next_attempt_can_select_other() {
        let mut mock_pool = MockPool::new();
        let mut mock_trigger = MockTrigger::new();
        let mut mock_tracker = MockTransactionTracker::new();

        let pinned_entry_point = ENTRY_POINT_ADDRESS_V0_6;
        let other_entry_point = ENTRY_POINT_ADDRESS_V0_7;
        let filter_id = Some("filter-a".to_string());

        mock_trigger.expect_last_block().return_const(new_head(0));

        mock_tracker.expect_get_state().times(2).returning(|| {
            Ok(TrackerState {
                nonce: 1,
                balance: U256::ZERO,
                required_fees: None,
            })
        });

        let expected_filter = filter_id.clone();
        // Pinned EP queried once (for the pinned attempt), then again for the fresh attempt
        // along with the other EP.
        mock_pool
            .expect_get_ops_summaries()
            .withf(move |entry_point, _, filter| {
                *entry_point == pinned_entry_point
                    && filter.as_deref() == expected_filter.as_deref()
            })
            .times(2)
            .returning(move |_, _, _| Ok(vec![pool_op_summary(pinned_entry_point, Address::ZERO)]));
        mock_pool
            .expect_get_ops_summaries()
            .withf(move |entry_point, _, filter| {
                *entry_point == other_entry_point && filter.is_none()
            })
            .times(1)
            .returning(move |_, _, _| {
                Ok(vec![PoolOperationSummary {
                    hash: B256::from([1; 32]),
                    ..pool_op_summary(other_entry_point, Address::from([1; 20]))
                }])
            });
        mock_pool
            .expect_get_ops_by_hashes()
            .times(2)
            .returning(|_, _| Ok(vec![demo_pool_op()]));

        let mut pinned_proposer = MockBundleProposerT::new();
        mock_make_bundle(&mut pinned_proposer, 1, vec![]);

        let mut other_proposer = MockBundleProposerT::new();
        mock_make_bundle(&mut other_proposer, 1, vec![]);

        let mut proposers: HashMap<ProposerKey, Box<dyn BundleProposerT>> = HashMap::new();
        proposers.insert(
            (pinned_entry_point, filter_id.clone()),
            Box::new(pinned_proposer),
        );
        proposers.insert((other_entry_point, None), Box::new(other_proposer));

        let entrypoints = vec![
            EntrypointInfo {
                address: pinned_entry_point,
                filter_id: filter_id.clone(),
            },
            EntrypointInfo {
                address: other_entry_point,
                filter_id: None,
            },
        ];

        let mut sender = new_sender_with_entrypoints(mock_pool, entrypoints, proposers);

        // Pre-establish pin in the assigner (simulates prior successful bundle)
        sender.assigner.test_establish_pin(
            Address::default(),
            &[Address::ZERO],
            (pinned_entry_point, filter_id),
        );

        let mut state = SenderMachineState::new(mock_trigger, mock_tracker);

        // First attempt: pinned, produces empty bundle after make_bundle.
        // Route through handle_building_state so release_all clears the pin.
        sender
            .handle_building_state(
                &mut state,
                BuildingState {
                    wait_for_trigger: false,
                    fee_increase_count: 0,
                    underpriced_info: None,
                },
            )
            .await
            .unwrap();
        // Pin should be cleared by release_all
        assert_eq!(sender.assigner.pinned_proposer(Address::default()), None);

        // Second attempt: no longer pinned, can select the other entrypoint.
        let second = sender.send_bundle(&mut state, 0).await.unwrap();
        assert!(matches!(
            second,
            SendBundleAttemptResult::NoOperationsAfterSimulation
        ));
    }

    #[tokio::test]
    async fn test_wait_for_mine_success() {
        let Mocks {
            mock_proposer_t,
            mut mock_tracker,
            mut mock_trigger,
            mock_pool,
        } = new_mocks();

        let mut seq = Sequence::new();
        add_trigger_wait_for_block_last_block(&mut mock_trigger, &mut seq, 1);

        let mined = new_head_mined(2);
        let mined_clone = mined.clone();

        mock_trigger
            .expect_wait_for_block()
            .once()
            .in_sequence(&mut seq)
            .returning(move || {
                Box::pin({
                    let mined = mined_clone.clone();
                    async move { Ok(mined) }
                })
            });
        mock_trigger
            .expect_last_block()
            .once()
            .in_sequence(&mut seq)
            .return_const(mined);

        mock_tracker.expect_address().return_const(Address::ZERO);

        mock_tracker.expect_process_update().once().returning(|_| {
            Box::pin(async {
                Ok(Some(TrackerUpdate::Mined {
                    block_number: 2,
                    nonce: 0,
                    gas_limit: None,
                    gas_used: None,
                    gas_price: None,
                    tx_hash: B256::ZERO,
                    attempt_number: 0,
                    is_success: true,
                }))
            })
        });

        let mut sender = new_sender(mock_proposer_t, mock_pool);

        let mut state = new_state_with(
            mock_trigger,
            mock_tracker,
            InnerState::Pending(PendingState {
                until: 3,
                fee_increase_count: 0,
            }),
        );

        // first step has no update
        sender.step_state(&mut state).await.unwrap();
        assert!(matches!(
            state.inner,
            InnerState::Pending(PendingState { until: 3, .. })
        ));

        // second step is mined and moves back to building
        sender.step_state(&mut state).await.unwrap();
        assert!(matches!(
            state.inner,
            InnerState::Building(BuildingState {
                wait_for_trigger: false, // don't wait for trigger in auto mode
                fee_increase_count: 0,
                underpriced_info: None,
            })
        ));
    }

    #[tokio::test]
    async fn test_wait_for_mine_timed_out() {
        let Mocks {
            mock_proposer_t,
            mock_tracker,
            mut mock_trigger,
            mock_pool,
        } = new_mocks();

        let mut seq = Sequence::new();
        for i in 1..=3 {
            add_trigger_wait_for_block_last_block(&mut mock_trigger, &mut seq, i);
        }

        let mut sender = new_sender(mock_proposer_t, mock_pool);

        let mut state = new_state_with(
            mock_trigger,
            mock_tracker,
            InnerState::Pending(PendingState {
                until: 3,
                fee_increase_count: 0,
            }),
        );

        // first and second step has no update
        for _ in 0..2 {
            sender.step_state(&mut state).await.unwrap();
            assert!(matches!(
                state.inner,
                InnerState::Pending(PendingState { until: 3, .. })
            ));
        }

        // third step times out and moves back to building with a fee increase
        sender.step_state(&mut state).await.unwrap();
        assert!(matches!(
            state.inner,
            InnerState::Building(BuildingState {
                wait_for_trigger: false,
                fee_increase_count: 1,
                underpriced_info: None,
            })
        ));
    }

    #[tokio::test]
    async fn test_transition_to_cancel() {
        let Mocks {
            mock_proposer_t,
            mut mock_tracker,
            mut mock_trigger,
            mut mock_pool,
        } = new_mocks();

        let mut seq = Sequence::new();
        add_trigger_no_update_last_block(&mut mock_trigger, &mut seq, 3);

        mock_tracker.expect_get_state().returning(|| {
            Ok(TrackerState {
                nonce: 0,
                balance: U256::ZERO,
                required_fees: Some(GasFees {
                    max_fee_per_gas: 100,
                    max_priority_fee_per_gas: 50,
                }),
            })
        });
        mock_tracker.expect_address().return_const(Address::ZERO);
        mock_tracker
            .expect_num_pending_transactions()
            .return_const(0_usize);

        mock_pool
            .expect_get_ops_summaries()
            .times(1)
            .returning(|_, _, _| {
                Ok(vec![PoolOperationSummary {
                    max_fee_per_gas: 10,
                    max_priority_fee_per_gas: 2,
                    ..pool_op_summary(ENTRY_POINT_ADDRESS_V0_6, Address::ZERO)
                }])
            });
        mock_pool.expect_get_ops_by_hashes().times(0);

        let mut sender = new_sender(mock_proposer_t, mock_pool);

        // start in underpriced meta-state
        let mut state = new_state_with(
            mock_trigger,
            mock_tracker,
            InnerState::Building(BuildingState {
                wait_for_trigger: true,
                fee_increase_count: 0,
                underpriced_info: Some(UnderpricedInfo {
                    since_block: 0,
                    rounds: 1,
                }),
            }),
        );

        // step state, block number should trigger move to cancellation
        sender.step_state(&mut state).await.unwrap();
        assert!(matches!(
            state.inner,
            InnerState::Cancelling(CancellingState {
                fee_increase_count: 0,
            })
        ));
    }

    #[tokio::test]
    async fn test_send_cancel() {
        let Mocks {
            mock_proposer_t,
            mut mock_tracker,
            mut mock_trigger,
            mock_pool,
        } = new_mocks();

        mock_tracker.expect_get_state().returning(|| {
            Ok(TrackerState {
                nonce: 0,
                balance: U256::ZERO,
                required_fees: None,
            })
        });

        mock_tracker
            .expect_cancel_transaction()
            .once()
            .returning(|_| Box::pin(async { Ok(Some(B256::ZERO)) }));

        mock_trigger.expect_last_block().return_const(new_head(0));

        let mut state = new_state_with(
            mock_trigger,
            mock_tracker,
            InnerState::Cancelling(CancellingState {
                fee_increase_count: 0,
            }),
        );

        let mut sender = new_sender(mock_proposer_t, mock_pool);

        // Establish pin for metrics (cancellation doesn't need it functionally)
        sender.assigner.test_establish_pin(
            Address::default(),
            &[Address::ZERO],
            (ENTRY_POINT_ADDRESS_V0_6, None),
        );

        sender.step_state(&mut state).await.unwrap();
        assert!(matches!(
            state.inner,
            InnerState::CancelPending(CancelPendingState {
                until: 3,
                fee_increase_count: 0,
            })
        ));
    }

    #[tokio::test]
    async fn test_send_cancel_uses_sender_fee_estimator() {
        let Mocks {
            mock_proposer_t,
            mut mock_tracker,
            mut mock_trigger,
            mock_pool,
        } = new_mocks();

        mock_tracker.expect_get_state().returning(|| {
            Ok(TrackerState {
                nonce: 0,
                balance: U256::ZERO,
                required_fees: None,
            })
        });

        mock_tracker
            .expect_cancel_transaction()
            .once()
            .returning(|_| Box::pin(async { Ok(Some(B256::ZERO)) }));

        mock_trigger.expect_last_block().return_const(new_head(0));

        let mut state = new_state_with(
            mock_trigger,
            mock_tracker,
            InnerState::Cancelling(CancellingState {
                fee_increase_count: 0,
            }),
        );

        let mut sender = new_sender(mock_proposer_t, mock_pool);
        // No pin established — cancellation still works (uses pinned_proposer for metrics only)
        sender.step_state(&mut state).await.unwrap();

        assert!(matches!(
            state.inner,
            InnerState::CancelPending(CancelPendingState {
                until: 3,
                fee_increase_count: 0,
            })
        ));
    }

    #[tokio::test]
    async fn test_send_bundle_unknown_proposer_releases_assignments() {
        let mut mock_pool = MockPool::new();
        let mut mock_trigger = MockTrigger::new();
        let mut mock_tracker = MockTransactionTracker::new();

        mock_trigger.expect_last_block().return_const(new_head(0));

        mock_tracker.expect_get_state().times(1).returning(|| {
            Ok(TrackerState {
                nonce: 1,
                balance: U256::ZERO,
                required_fees: None,
            })
        });

        mock_pool
            .expect_get_ops_summaries()
            .times(2)
            .returning(|_, _, _| {
                Ok(vec![pool_op_summary(
                    ENTRY_POINT_ADDRESS_V0_6,
                    Address::from([9; 20]),
                )])
            });
        mock_pool
            .expect_get_ops_by_hashes()
            .times(2)
            .returning(|_, _| Ok(vec![demo_pool_op()]));

        let entrypoints = vec![EntrypointInfo {
            address: ENTRY_POINT_ADDRESS_V0_6,
            filter_id: None,
        }];
        let proposers: HashMap<ProposerKey, Box<dyn BundleProposerT>> = HashMap::new();

        let mut sender = new_sender_with_entrypoints(mock_pool, entrypoints, proposers);

        let mut state = SenderMachineState::new(mock_trigger, mock_tracker);
        let err = sender
            .send_bundle(&mut state, 0)
            .await
            .expect_err("should fail");
        assert!(
            err.to_string().contains("Unknown entrypoint config"),
            "unexpected error: {err:#}"
        );

        // If assignment cleanup ran on error, another builder can immediately claim the same sender.
        let next_assignment = sender
            .assigner
            .assign_work(Address::from([0xAA; 20]), u64::MAX, GasFees::default())
            .await
            .unwrap();
        assert!(
            matches!(next_assignment, AssignmentResult::Assigned(_)),
            "assignment lock should be released after proposer lookup error"
        );
    }

    #[tokio::test]
    async fn test_no_ops_after_fee_filter_with_pending_keeps_confirmed_locks() {
        let mut mock_pool = MockPool::new();
        let mut mock_trigger = MockTrigger::new();
        let mut mock_tracker = MockTransactionTracker::new();

        let sender = Address::ZERO;

        mock_trigger.expect_last_block().return_const(new_head(0));

        mock_tracker.expect_get_state().times(1).returning(|| {
            Ok(TrackerState {
                nonce: 1,
                balance: U256::ZERO,
                required_fees: Some(GasFees {
                    max_fee_per_gas: 100,
                    max_priority_fee_per_gas: 50,
                }),
            })
        });

        mock_pool
            .expect_get_ops_summaries()
            .times(3)
            .returning(move |_, _, _| Ok(vec![pool_op_summary(ENTRY_POINT_ADDRESS_V0_6, sender)]));
        mock_pool
            .expect_get_ops_by_hashes()
            .times(1)
            .returning(|_, _| Ok(vec![demo_pool_op()]));

        let mut sender_impl = new_sender(MockBundleProposerT::new(), mock_pool);

        // Pre-lock and confirm sender to simulate an existing in-flight bundle.
        let initial_assignment = match sender_impl
            .assigner
            .assign_work(sender, u64::MAX, GasFees::default())
            .await
            .unwrap()
        {
            AssignmentResult::Assigned(assignment) => assignment,
            other => panic!("initial assignment should exist, got {other:?}"),
        };
        assert_eq!(initial_assignment.operations.len(), 1);
        sender_impl
            .assigner
            .confirm_senders_drop_unused(sender, &[sender])
            .unwrap();

        let mut state = SenderMachineState::new(mock_trigger, mock_tracker);
        let result = sender_impl.send_bundle(&mut state, 0).await.unwrap();
        assert!(matches!(
            result,
            SendBundleAttemptResult::NoOperationsAfterFeeFilter
        ));

        // Confirmed sender lock should remain while pending tx exists.
        let reassignment = sender_impl
            .assigner
            .assign_work(Address::from([0xAA; 20]), u64::MAX, GasFees::default())
            .await
            .unwrap();
        assert!(
            matches!(reassignment, AssignmentResult::NoOperations),
            "confirmed lock should be preserved during pending tx"
        );
    }

    #[tokio::test]
    async fn test_resubmit_cancel() {
        let Mocks {
            mock_proposer_t,
            mock_tracker,
            mut mock_trigger,
            mock_pool,
        } = new_mocks();

        let mut seq = Sequence::new();
        for i in 1..=3 {
            add_trigger_wait_for_block_last_block(&mut mock_trigger, &mut seq, i);
        }

        let mut state = new_state_with(
            mock_trigger,
            mock_tracker,
            InnerState::CancelPending(CancelPendingState {
                until: 3,
                fee_increase_count: 0,
            }),
        );

        let mut sender = new_sender(mock_proposer_t, mock_pool);

        for _ in 0..2 {
            sender.step_state(&mut state).await.unwrap();
            assert!(matches!(
                state.inner,
                InnerState::CancelPending(CancelPendingState {
                    until: 3,
                    fee_increase_count: 0,
                })
            ));
        }

        sender.step_state(&mut state).await.unwrap();
        assert!(matches!(
            state.inner,
            InnerState::Cancelling(CancellingState {
                fee_increase_count: 1,
            })
        ));
    }

    #[tokio::test]
    async fn test_condition_not_met() {
        let Mocks {
            mut mock_proposer_t,
            mut mock_tracker,
            mut mock_trigger,
            mut mock_pool,
        } = new_mocks();

        let mut seq = Sequence::new();
        add_trigger_no_update_last_block(&mut mock_trigger, &mut seq, 1);

        setup_tracker_default(&mut mock_tracker);

        mock_pool
            .expect_get_ops_summaries()
            .times(1)
            .returning(|_, _, _| {
                Ok(vec![pool_op_summary(
                    ENTRY_POINT_ADDRESS_V0_6,
                    Address::ZERO,
                )])
            });
        mock_pool
            .expect_get_ops_by_hashes()
            .times(1)
            .returning(|_, _| Ok(vec![demo_pool_op()]));

        mock_make_bundle(&mut mock_proposer_t, 1, vec![(Address::ZERO, B256::ZERO)]);

        // should send the bundle txn, returns condition not met
        mock_tracker
            .expect_send_transaction()
            .returning(|_, _, _| Box::pin(async { Err(TransactionTrackerError::ConditionNotMet) }));

        // Sender will set condition_not_met flag and pass it to next make_bundle call
        // (tested implicitly via state transition to Building with retry)

        let mut state = new_state_with(
            mock_trigger,
            mock_tracker,
            InnerState::Building(BuildingState {
                wait_for_trigger: true,
                fee_increase_count: 0,
                underpriced_info: None,
            }),
        );

        let mut sender = new_sender(mock_proposer_t, mock_pool);

        sender.step_state(&mut state).await.unwrap();

        // end back in the building state without waiting for trigger
        assert!(matches!(
            state.inner,
            InnerState::Building(BuildingState {
                wait_for_trigger: false,
                fee_increase_count: 0,
                underpriced_info: None,
            })
        ));
    }

    #[test]
    fn test_bundle_error_clears_condition_not_met() {
        let mut state = SenderMachineState::new(MockTrigger::new(), MockTransactionTracker::new());
        state.condition_not_met = true;
        state.bundle_error(anyhow::anyhow!("boom"));
        assert!(!state.condition_not_met);
    }

    #[tokio::test]
    async fn test_revert_remove() {
        let Mocks {
            mut mock_proposer_t,
            mut mock_tracker,
            mut mock_trigger,
            mut mock_pool,
        } = new_mocks();

        let mut seq = Sequence::new();
        add_trigger_wait_for_block_last_block(&mut mock_trigger, &mut seq, 1);

        let mined = new_head_mined(2);
        let mined_clone = mined.clone();

        mock_trigger
            .expect_wait_for_block()
            .once()
            .in_sequence(&mut seq)
            .returning(move || {
                Box::pin({
                    let mined = mined_clone.clone();
                    async move { Ok(mined) }
                })
            });
        mock_trigger
            .expect_last_block()
            .once()
            .in_sequence(&mut seq)
            .return_const(mined);

        mock_tracker.expect_address().return_const(Address::ZERO);

        mock_tracker.expect_process_update().once().returning(|_| {
            Box::pin(async {
                Ok(Some(TrackerUpdate::Mined {
                    block_number: 2,
                    nonce: 0,
                    gas_limit: None,
                    gas_used: None,
                    gas_price: None,
                    tx_hash: B256::ZERO,
                    attempt_number: 0,
                    is_success: false, // revert
                }))
            })
        });

        // Mock the proposer's process_revert to return empty (no ops to remove)
        mock_proposer_t
            .expect_process_revert()
            .returning(|_| Box::pin(async { Ok(vec![]) }));

        mock_pool.expect_remove_ops().returning(|_, _| Ok(()));

        let mut sender = new_sender(mock_proposer_t, mock_pool);

        // Establish pin so process_revert can find the proposer
        sender.assigner.test_establish_pin(
            Address::default(),
            &[Address::ZERO],
            (ENTRY_POINT_ADDRESS_V0_6, None),
        );

        let mut state = new_state_with(
            mock_trigger,
            mock_tracker,
            InnerState::Pending(PendingState {
                until: 3,
                fee_increase_count: 0,
            }),
        );

        // first step has no update
        sender.step_state(&mut state).await.unwrap();
        assert!(matches!(
            state.inner,
            InnerState::Pending(PendingState { until: 3, .. })
        ));

        // second step is mined, revert processed, and moves back to building
        sender.step_state(&mut state).await.unwrap();
        assert!(matches!(
            state.inner,
            InnerState::Building(BuildingState {
                wait_for_trigger: false, // don't wait for trigger in auto mode
                fee_increase_count: 0,
                underpriced_info: None,
            })
        ));
    }

    struct Mocks {
        mock_proposer_t: MockBundleProposerT,
        mock_tracker: MockTransactionTracker,
        mock_trigger: MockTrigger,
        mock_pool: MockPool,
    }

    fn new_mocks() -> Mocks {
        let mock_proposer_t = MockBundleProposerT::new();

        Mocks {
            mock_proposer_t,
            mock_tracker: MockTransactionTracker::new(),
            mock_trigger: MockTrigger::new(),
            mock_pool: MockPool::new(),
        }
    }

    fn new_sender(
        mock_proposer_t: MockBundleProposerT,
        mock_pool: MockPool,
    ) -> BundleSenderImpl<MockTransactionTracker, Arc<MockPool>> {
        let pool = Arc::new(mock_pool);
        let ep_address = ENTRY_POINT_ADDRESS_V0_6;

        let mut proposers: HashMap<ProposerKey, Box<dyn BundleProposerT>> = HashMap::new();
        proposers.insert((ep_address, None), Box::new(mock_proposer_t));

        // Create assigner with entrypoint info
        let entrypoints = vec![EntrypointInfo {
            address: ep_address,
            filter_id: None,
        }];

        BundleSenderImpl::new(
            "test-builder".to_string(),
            mpsc::channel(1000).1,
            ChainSpec::default(),
            Address::default(),
            MockTransactionTracker::new(),
            Box::new(TestFeeEstimator),
            Arc::new(Assigner::new(
                Box::new(pool.clone()),
                entrypoints,
                4, // num_signers
                1024,
                1024,
                0.50,
            )),
            Arc::new(proposers),
            pool,
            Settings {
                max_cancellation_fee_increases: 3,
                max_blocks_to_wait_for_mine: 3,
                max_replacement_underpriced_blocks: 3,
            },
            broadcast::channel(1000).0,
        )
    }

    fn new_sender_with_entrypoints(
        mock_pool: MockPool,
        entrypoints: Vec<EntrypointInfo>,
        proposers: HashMap<ProposerKey, Box<dyn BundleProposerT>>,
    ) -> BundleSenderImpl<MockTransactionTracker, Arc<MockPool>> {
        let pool = Arc::new(mock_pool);

        BundleSenderImpl::new(
            "test-builder".to_string(),
            mpsc::channel(1000).1,
            ChainSpec::default(),
            Address::default(),
            MockTransactionTracker::new(),
            Box::new(TestFeeEstimator),
            Arc::new(Assigner::new(
                Box::new(pool.clone()),
                entrypoints,
                4, // num_signers
                1024,
                1024,
                0.50,
            )),
            Arc::new(proposers),
            pool,
            Settings {
                max_cancellation_fee_increases: 3,
                max_blocks_to_wait_for_mine: 3,
                max_replacement_underpriced_blocks: 3,
            },
            broadcast::channel(1000).0,
        )
    }

    fn add_trigger_no_update_last_block(
        mock_trigger: &mut MockTrigger,
        seq: &mut Sequence,
        block_number: u64,
    ) {
        mock_trigger
            .expect_wait_for_trigger()
            .once()
            .in_sequence(seq)
            .returning(move || Box::pin(async move { Ok(None) }));
        mock_trigger
            .expect_last_block()
            .return_const(new_head(block_number));
    }

    fn add_trigger_wait_for_block_last_block(
        mock_trigger: &mut MockTrigger,
        seq: &mut Sequence,
        block_number: u64,
    ) {
        mock_trigger
            .expect_wait_for_block()
            .once()
            .in_sequence(seq)
            .returning(move || Box::pin(async move { Ok(new_head(block_number)) }));

        // this gets called twice after a trigger
        for _ in 0..2 {
            mock_trigger
                .expect_last_block()
                .once()
                .in_sequence(seq)
                .return_const(new_head(block_number));
        }

        mock_trigger
            .expect_builder_must_wait_for_trigger()
            .return_const(false);
    }

    fn new_head(block_number: u64) -> NewHead {
        NewHead {
            block_number,
            block_hash: B256::ZERO,
            address_updates: vec![],
        }
    }

    fn new_head_mined(block_number: u64) -> NewHead {
        NewHead {
            block_number,
            block_hash: B256::ZERO,
            address_updates: vec![AddressUpdate {
                address: Address::ZERO,
                nonce: Some(0),
                balance: U256::ZERO,
                mined_tx_hashes: vec![B256::ZERO],
            }],
        }
    }

    fn bundle_data(ops: Vec<(Address, B256)>) -> BundleData {
        BundleData {
            tx: rundler_provider::TransactionRequest::default(),
            expected_storage: Default::default(),
            gas_fees: GasFees::default(),
            ops,
            rejected_op_hashes: vec![],
            entity_updates: vec![],
        }
    }

    fn pool_op_summary(entry_point: Address, sender: Address) -> PoolOperationSummary {
        PoolOperationSummary {
            hash: B256::ZERO,
            sender,
            entry_point,
            sim_block_number: 0,
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: 0,
            gas_limit: 0,
            bundler_sponsorship_max_cost: None,
        }
    }

    fn mock_make_bundle(
        proposer: &mut MockBundleProposerT,
        times: usize,
        ops: Vec<(Address, B256)>,
    ) {
        proposer
            .expect_make_bundle()
            .times(times)
            .returning(move |_, _, _, _, _, _, _, _, _| {
                let ops = ops.clone();
                Box::pin(async { Ok(bundle_data(ops)) })
            });
    }

    fn setup_tracker_default(mock_tracker: &mut MockTransactionTracker) {
        mock_tracker.expect_get_state().returning(|| {
            Ok(TrackerState {
                nonce: 0,
                balance: U256::ZERO,
                required_fees: None,
            })
        });
        mock_tracker.expect_address().return_const(Address::ZERO);
        mock_tracker
            .expect_num_pending_transactions()
            .return_const(0_usize);
    }

    fn new_state_with(
        trigger: MockTrigger,
        tracker: MockTransactionTracker,
        inner: InnerState,
    ) -> SenderMachineState<MockTransactionTracker, MockTrigger> {
        SenderMachineState {
            trigger,
            transaction_tracker: tracker,
            send_bundle_response: None,
            inner,
            requires_reset: false,
            condition_not_met: false,
        }
    }

    fn demo_pool_op() -> PoolOperation {
        PoolOperation {
            uo: UserOperation::default().into(),
            entry_point: Address::random(),
            aggregator: None,
            valid_time_range: ValidTimeRange::all_time(),
            expected_code_hash: B256::random(),
            sim_block_hash: B256::random(),
            sim_block_number: 0,
            account_is_staked: true,
            entity_infos: EntityInfos::default(),
            da_gas_data: rundler_types::da::DAGasData::Empty,
            filter_id: None,
            perms: UserOperationPermissions::default(),
            sender_is_7702: false,
        }
    }
}
