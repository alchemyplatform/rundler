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

use std::{marker::PhantomData, pin::Pin, sync::Arc, time::Duration};

use alloy_primitives::{Address, B256};
use anyhow::{bail, Context};
use async_trait::async_trait;
use futures::Stream;
use futures_util::StreamExt;
use metrics::{Counter, Histogram};
use metrics_derive::Metrics;
#[cfg(test)]
use mockall::automock;
use rundler_provider::{BundleHandler, EntryPoint, TransactionRequest};
use rundler_sim::ExpectedStorage;
use rundler_task::TaskSpawner;
use rundler_types::{
    builder::BundlingMode,
    chain::ChainSpec,
    pool::{NewHead, Pool},
    EntityUpdate, UserOperation,
};
use rundler_utils::emit::WithEntryPoint;
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
    bundle_proposer::{Bundle, BundleProposer, BundleProposerError},
    emit::{BuilderEvent, BundleTxDetails},
    transaction_tracker::{TrackerUpdate, TransactionTracker, TransactionTrackerError},
};

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

#[derive(Debug)]
pub(crate) struct BundleSenderImpl<UO, P, E, T, C> {
    builder_index: u64,
    bundle_action_receiver: Option<mpsc::Receiver<BundleSenderAction>>,
    chain_spec: ChainSpec,
    beneficiary: Address,
    proposer: P,
    entry_point: E,
    transaction_tracker: Option<T>,
    pool: C,
    settings: Settings,
    event_sender: broadcast::Sender<WithEntryPoint<BuilderEvent>>,
    metrics: BuilderMetric,
    _uo_type: PhantomData<UO>,
}

#[derive(Debug)]
struct BundleTx {
    tx: TransactionRequest,
    expected_storage: ExpectedStorage,
    op_hashes: Vec<B256>,
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
    StalledAtMaxFeeIncreases,
    Error(anyhow::Error),
}

// Internal result of attempting to send a bundle.
enum SendBundleAttemptResult {
    // The bundle was successfully sent
    Success,
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
    async fn send_bundles_in_loop<TS: TaskSpawner>(mut self, task_spawner: TS) {
        // trigger for sending bundles
        let sender_trigger = BundleSenderTrigger::new(
            &task_spawner,
            &self.pool,
            self.bundle_action_receiver.take().unwrap(),
            Duration::from_millis(self.chain_spec.bundle_max_send_interval_millis),
        )
        .await
        .expect("Failed to create bundle sender trigger");

        // initial state
        let mut state =
            SenderMachineState::new(sender_trigger, self.transaction_tracker.take().unwrap());

        loop {
            if let Err(e) = self.step_state(&mut state).await {
                error!("Error in bundle sender loop: {e:#?}");
                self.metrics.state_machine_errors.increment(1);
                state.reset();
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
            transaction_tracker: Some(transaction_tracker),
            pool,
            settings,
            event_sender,
            metrics: BuilderMetric::new_with_labels(&[
                ("entry_point", entry_point.address().to_string()),
                ("builder_index", builder_index.to_string()),
            ]),
            entry_point,
            _uo_type: PhantomData,
        }
    }

    async fn step_state<TRIG: Trigger>(
        &mut self,
        state: &mut SenderMachineState<T, TRIG>,
    ) -> anyhow::Result<()> {
        let tracker_update = state.wait_for_trigger().await?;

        match state.inner {
            InnerState::Building(building_state) => {
                self.handle_building_state(state, building_state).await?;
            }
            InnerState::Pending(pending_state) => {
                self.handle_pending_state(state, pending_state, tracker_update)
                    .await?;
            }
            InnerState::Cancelling(cancelling_state) => {
                self.handle_cancelling_state(state, cancelling_state)
                    .await?;
            }
            InnerState::CancelPending(cancel_pending_state) => {
                self.handle_cancel_pending_state(state, cancel_pending_state, tracker_update)
                    .await?;
            }
        }

        Ok(())
    }

    async fn handle_building_state<TRIG: Trigger>(
        &mut self,
        state: &mut SenderMachineState<T, TRIG>,
        inner: BuildingState,
    ) -> anyhow::Result<()> {
        // send bundle
        let block_number = state.block_number();
        debug!("Building bundle on block {}", block_number);
        let result = self.send_bundle(state, inner.fee_increase_count).await;

        // handle result
        match result {
            Ok(SendBundleAttemptResult::Success) => {
                // sent the bundle
                info!("Bundle sent successfully");
                state.update(InnerState::Pending(inner.to_pending(
                    block_number + self.settings.max_blocks_to_wait_for_mine,
                )));
            }
            Ok(SendBundleAttemptResult::NoOperationsInitially) => {
                debug!("No operations available initially");
                state.no_operations();
            }
            Ok(SendBundleAttemptResult::NoOperationsAfterSimulation) => {
                debug!("No operations available after simulation");
                state.no_operations();
            }
            Ok(SendBundleAttemptResult::NoOperationsAfterFeeFilter) => {
                debug!("No operations to bundle after fee filtering");
                if let Some(underpriced_info) = inner.underpriced_info {
                    // If we are here, there are UOs in the pool that may be correctly priced, but are being blocked by an underpriced replacement
                    // after a fee increase. If we repeatedly get into this state, initiate a cancellation.
                    if block_number - underpriced_info.since_block
                        >= self.settings.max_replacement_underpriced_blocks
                    {
                        warn!("No operations available, but last replacement underpriced, moving to cancelling state. Round: {}. Since block {}. Current block {}. Max underpriced blocks: {}", underpriced_info.rounds, underpriced_info.since_block, block_number, self.settings.max_replacement_underpriced_blocks);
                        state.update(InnerState::Cancelling(inner.to_cancelling()));
                    } else {
                        info!("No operations available, but last replacement underpriced, starting over and waiting for next trigger. Round: {}. Since block {}. Current block {}", underpriced_info.rounds, underpriced_info.since_block, block_number);
                        // Abandon the transaction tracker when we start the next bundle attempt fresh, may cause a `ReplacementUnderpriced` in next round
                        state.transaction_tracker.abandon();
                        state.update(InnerState::Building(inner.underpriced_round()));
                    }
                } else if inner.fee_increase_count > 0 {
                    warn!(
                        "Abandoning bundle after {} fee increases, no operations available after fee increase",
                        inner.fee_increase_count
                    );
                    self.metrics.bundle_txns_abandoned.increment(1);

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
                // reset the transaction tracker and try again
                info!("Nonce too low, starting new bundle attempt");
                state.reset();
            }
            Ok(SendBundleAttemptResult::Underpriced) => {
                info!(
                    "Bundle underpriced, marking as underpriced. Num fee increases {:?}",
                    inner.fee_increase_count
                );
                state.update(InnerState::Building(inner.underpriced(block_number)));
            }
            Ok(SendBundleAttemptResult::ReplacementUnderpriced) => {
                info!("Replacement transaction underpriced, marking as underpriced. Num fee increases {:?}", inner.fee_increase_count);
                // unabandon to allow fee estimation to consider any submitted transactions, wait for next trigger
                state.transaction_tracker.unabandon();
                state.update(InnerState::Building(inner.underpriced(block_number)));
            }
            Ok(SendBundleAttemptResult::ConditionNotMet) => {
                info!("Condition not met, notifying proposer and starting new bundle attempt");
                self.proposer.notify_condition_not_met();
                state.update(InnerState::Building(inner.retry()));
            }
            Ok(SendBundleAttemptResult::Rejected) => {
                // Bundle was rejected, try with a higher price
                // May want to consider a simple retry instead of increasing fees, but this should be rare
                info!(
                    "Bundle rejected, assuming underpriced. Num fee increases {:?}",
                    inner.fee_increase_count
                );
                state.update(InnerState::Building(inner.underpriced(block_number)));
            }
            Err(error) => {
                error!("Bundle send error {error:?}");
                self.metrics.bundle_txns_failed.increment(1);
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
        if let Some(update) = tracker_update {
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
                    info!("Bundle transaction mined");

                    self.metrics.process_bundle_txn_success(gas_limit, gas_used);
                    self.emit(BuilderEvent::transaction_mined(
                        self.builder_index,
                        tx_hash,
                        nonce,
                        block_number,
                    ));
                    state.bundle_mined(block_number, attempt_number, tx_hash);
                }
                TrackerUpdate::LatestTxDropped { nonce } => {
                    info!("Latest transaction dropped, starting new bundle attempt");
                    self.emit(BuilderEvent::latest_transaction_dropped(
                        self.builder_index,
                        nonce,
                    ));
                    self.metrics.bundle_txns_dropped.increment(1);
                    // try again, increasing fees
                    state.update(InnerState::Building(inner.to_building()));
                }
                TrackerUpdate::NonceUsedForOtherTx { nonce } => {
                    info!("Nonce used externally, starting new bundle attempt");
                    self.emit(BuilderEvent::nonce_used_for_other_transaction(
                        self.builder_index,
                        nonce,
                    ));
                    self.metrics.bundle_txns_nonce_used.increment(1);
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
            self.metrics.bundle_txn_fee_increases.increment(1);
            state.update(InnerState::Building(inner.to_building()))
        }

        Ok(())
    }

    async fn handle_cancelling_state<TRIG: Trigger>(
        &mut self,
        state: &mut SenderMachineState<T, TRIG>,
        inner: CancellingState,
    ) -> anyhow::Result<()> {
        info!(
            "Cancelling last transaction, attempt {}",
            inner.fee_increase_count
        );

        let (estimated_fees, _) = self
            .proposer
            .estimate_gas_fees(None)
            .await
            .unwrap_or_default();

        let cancel_res = state
            .transaction_tracker
            .cancel_transaction(*self.entry_point.address(), estimated_fees)
            .await;

        match cancel_res {
            Ok(Some(_)) => {
                info!("Cancellation transaction sent, waiting for confirmation");
                self.metrics.cancellation_txns_sent.increment(1);

                state.update(InnerState::CancelPending(inner.to_cancel_pending(
                    state.block_number() + self.settings.max_blocks_to_wait_for_mine,
                )));
            }
            Ok(None) => {
                info!("Soft cancellation or no transaction to cancel, starting new bundle attempt");
                self.metrics.soft_cancellations.increment(1);
                state.reset();
            }
            Err(TransactionTrackerError::Rejected)
            | Err(TransactionTrackerError::Underpriced)
            | Err(TransactionTrackerError::ReplacementUnderpriced) => {
                info!("Transaction underpriced/rejected during cancellation, trying again. {cancel_res:?}");
                if inner.fee_increase_count >= self.settings.max_cancellation_fee_increases {
                    // abandon the cancellation
                    warn!("Abandoning cancellation after max fee increases {}, starting new bundle attempt", inner.fee_increase_count);
                    self.metrics.cancellations_abandoned.increment(1);
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
                state.reset();
            }
            Err(TransactionTrackerError::ConditionNotMet) => {
                error!(
                    "Unexpected condition not met during cancellation, starting new bundle attempt"
                );
                self.metrics.cancellation_txns_failed.increment(1);
                state.reset();
            }
            Err(TransactionTrackerError::Other(e)) => {
                error!("Failed to cancel transaction, moving back to building state: {e:#?}");
                self.metrics.cancellation_txns_failed.increment(1);
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
        // check for transaction update
        if let Some(update) = tracker_update {
            match update {
                TrackerUpdate::Mined {
                    gas_used,
                    gas_price,
                    ..
                } => {
                    // mined
                    let fee = gas_used.zip(gas_price).map(|(used, price)| used * price);
                    info!("Cancellation transaction mined. Price (wei) {fee:?}");
                    self.metrics.cancellation_txns_mined.increment(1);
                    if let Some(fee) = fee {
                        self.metrics
                            .cancellation_txns_total_fee
                            .increment(fee as u64);
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
                warn!("Abandoning cancellation after max fee increases {}, starting new bundle attempt", inner.fee_increase_count);
                self.metrics.cancellations_abandoned.increment(1);
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

    /// Constructs a bundle and sends it to the entry point as a transaction.
    ///
    /// Returns empty if:
    ///  - There are no ops available to bundle initially.
    ///  - The gas fees are high enough that the bundle is empty because there
    ///    are no ops that meet the fee requirements.
    async fn send_bundle<TRIG: Trigger>(
        &mut self,
        state: &mut SenderMachineState<T, TRIG>,
        fee_increase_count: u64,
    ) -> anyhow::Result<SendBundleAttemptResult> {
        let (nonce, required_fees) = state.transaction_tracker.get_nonce_and_required_fees()?;
        let _timer_guard = rundler_utils::guard_timer::CustomTimerGuard::new(
            self.metrics.bundle_build_time_ms.clone(),
        );

        let bundle = match self
            .proposer
            .make_bundle(required_fees, fee_increase_count > 0)
            .await
        {
            Ok(bundle) => bundle,
            Err(BundleProposerError::NoOperationsInitially) => {
                return Ok(SendBundleAttemptResult::NoOperationsInitially);
            }
            Err(BundleProposerError::NoOperationsAfterFeeFilter) => {
                return Ok(SendBundleAttemptResult::NoOperationsAfterFeeFilter);
            }
            Err(e) => bail!("Failed to make bundle: {e:?}"),
        };

        let Some(bundle_tx) = self.get_bundle_tx(nonce, bundle).await? else {
            self.emit(BuilderEvent::formed_bundle(
                self.builder_index,
                None,
                nonce,
                fee_increase_count,
                required_fees,
            ));
            return Ok(SendBundleAttemptResult::NoOperationsAfterSimulation);
        };
        let BundleTx {
            tx,
            expected_storage,
            op_hashes,
        } = bundle_tx;

        self.metrics.bundle_txns_sent.increment(1);

        let send_result = state
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
                    nonce,
                    fee_increase_count,
                    required_fees,
                ));

                Ok(SendBundleAttemptResult::Success)
            }
            Err(TransactionTrackerError::NonceTooLow) => {
                self.metrics.bundle_txn_nonce_too_low.increment(1);
                warn!("Bundle attempt nonce too low");
                Ok(SendBundleAttemptResult::NonceTooLow)
            }
            Err(TransactionTrackerError::Underpriced) => {
                self.metrics.bundle_txn_underpriced.increment(1);
                warn!("Bundle attempt underpriced");
                Ok(SendBundleAttemptResult::Underpriced)
            }
            Err(TransactionTrackerError::ReplacementUnderpriced) => {
                self.metrics.bundle_replacement_underpriced.increment(1);
                warn!("Bundle attempt replacement transaction underpriced");
                Ok(SendBundleAttemptResult::ReplacementUnderpriced)
            }
            Err(TransactionTrackerError::ConditionNotMet) => {
                self.metrics.bundle_txn_condition_not_met.increment(1);
                warn!("Bundle attempt condition not met");
                Ok(SendBundleAttemptResult::ConditionNotMet)
            }
            Err(TransactionTrackerError::Rejected) => {
                self.metrics.bundle_txn_rejected.increment(1);
                warn!("Bundle attempt rejected");
                Ok(SendBundleAttemptResult::Rejected)
            }
            Err(TransactionTrackerError::Other(e)) => {
                error!("Failed to send bundle with unexpected error: {e:?}");
                Err(e)
            }
        }
    }

    /// Builds a bundle and returns some metadata and the transaction to send
    /// it, or `None` if there are no valid operations available.
    async fn get_bundle_tx(
        &mut self,
        nonce: u64,
        bundle: Bundle<UO>,
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
        tx = tx.nonce(nonce);
        Ok(Some(BundleTx {
            tx,
            expected_storage: bundle.expected_storage,
            op_hashes,
        }))
    }

    async fn remove_ops_from_pool(&self, ops: &[UO]) -> anyhow::Result<()> {
        self.pool
            .remove_ops(
                *self.entry_point.address(),
                ops.iter()
                    .map(|op| op.hash(*self.entry_point.address(), self.chain_spec.id))
                    .collect(),
            )
            .await
            .context("builder should remove rejected ops from pool")
    }

    async fn update_entities_in_pool(&self, entity_updates: &[EntityUpdate]) -> anyhow::Result<()> {
        self.pool
            .update_entities(*self.entry_point.address(), entity_updates.to_vec())
            .await
            .context("builder should remove update entities in the pool")
    }

    fn emit(&self, event: BuilderEvent) {
        let _ = self.event_sender.send(WithEntryPoint {
            entry_point: *self.entry_point.address(),
            event,
        });
    }

    fn op_hash(&self, op: &UO) -> B256 {
        op.hash(*self.entry_point.address(), self.chain_spec.id)
    }
}

struct SenderMachineState<T, TRIG> {
    trigger: TRIG,
    pub transaction_tracker: T,
    send_bundle_response: Option<oneshot::Sender<SendBundleResult>>,
    inner: InnerState,
    requires_reset: bool,
}

impl<T: TransactionTracker, TRIG: Trigger> SenderMachineState<T, TRIG> {
    fn new(trigger: TRIG, transaction_tracker: T) -> Self {
        Self {
            trigger,
            transaction_tracker,
            send_bundle_response: None,
            inner: InnerState::new(),
            requires_reset: false,
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
        self.inner = InnerState::new();
    }

    // Resets the state and transaction tracker, doesn't wait for next trigger
    fn reset(&mut self) {
        self.requires_reset = true;
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
                self.transaction_tracker
                    .check_for_update()
                    .await
                    .map_err(|e| anyhow::anyhow!("transaction tracker update error {e:?}"))
            }
            InnerState::Pending(..) | InnerState::CancelPending(..) => {
                self.trigger.wait_for_block().await?;
                self.transaction_tracker
                    .check_for_update()
                    .await
                    .map_err(|e| anyhow::anyhow!("transaction tracker update error {e:?}"))
            }
            InnerState::Cancelling(..) => Ok(None),
        }
    }

    fn block_number(&self) -> u64 {
        self.trigger.last_block().block_number
    }

    fn send_result(&mut self, result: SendBundleResult) {
        if let Some(r) = self.send_bundle_response.take() {
            if r.send(result).is_err() {
                error!("Failed to send bundle result to manual caller");
            }
        }
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
    ) -> anyhow::Result<Self> {
        let Ok(new_heads) = pool_client.subscribe_new_heads().await else {
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

#[derive(Metrics)]
#[metrics(scope = "builder")]
struct BuilderMetric {
    #[metric(describe = "the count of bundle transactions already sent.")]
    bundle_txns_sent: Counter,
    #[metric(describe = "the count of bundle transactions successed.")]
    bundle_txns_success: Counter,
    #[metric(describe = "the count of bundle gas limit.")]
    bundle_gas_limit: Counter,
    #[metric(describe = "the count of bundle gas used.")]
    bundle_gas_used: Counter,
    #[metric(describe = "the count of dropped bundle transactions.")]
    bundle_txns_dropped: Counter,
    #[metric(describe = "the count of anabdoned bundle transactions.")]
    bundle_txns_abandoned: Counter,
    #[metric(describe = "the count of failed bundle transactions.")]
    bundle_txns_failed: Counter,
    #[metric(describe = "the count of bundle transaction nonce used events.")]
    bundle_txns_nonce_used: Counter,
    #[metric(describe = "the count of bundle transactions fee increase events.")]
    bundle_txn_fee_increases: Counter,
    #[metric(describe = "the count of bundle transactions underpriced events.")]
    bundle_txn_underpriced: Counter,
    #[metric(describe = "the count of bundle transactions underpriced replacement events.")]
    bundle_replacement_underpriced: Counter,
    #[metric(describe = "the count of bundle transactions nonce too low events.")]
    bundle_txn_nonce_too_low: Counter,
    #[metric(describe = "the count of bundle transactions condition not met events.")]
    bundle_txn_condition_not_met: Counter,
    #[metric(describe = "the count of bundle transactions rejected.")]
    bundle_txn_rejected: Counter,
    #[metric(describe = "the count of cancellation bundle transactions sent events.")]
    cancellation_txns_sent: Counter,
    #[metric(describe = "the count of cancellation bundle transactions mined events.")]
    cancellation_txns_mined: Counter,
    #[metric(describe = "the total fee of cancellation bundle transactions.")]
    cancellation_txns_total_fee: Counter,
    #[metric(describe = "the count of cancellation bundle transactions abandon events.")]
    cancellations_abandoned: Counter,
    #[metric(describe = "the count of soft cancellation bundle transactions events.")]
    soft_cancellations: Counter,
    #[metric(describe = "the count of cancellation bundle transactions failed events.")]
    cancellation_txns_failed: Counter,
    #[metric(describe = "the count of state machine errors.")]
    state_machine_errors: Counter,
    #[metric(describe = "the timespan a bundle is build.")]
    bundle_build_time_ms: Histogram,
}

impl BuilderMetric {
    fn process_bundle_txn_success(&self, gas_limit: Option<u64>, gas_used: Option<u128>) {
        self.bundle_txns_success.increment(1);
        if let Some(limit) = gas_limit {
            self.bundle_gas_limit.increment(limit);
        }
        if let Some(used) = gas_used {
            self.bundle_gas_used
                .increment(used.try_into().unwrap_or(u64::MAX));
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::Bytes;
    use mockall::Sequence;
    use rundler_provider::MockEntryPointV0_6;
    use rundler_types::{
        chain::ChainSpec, pool::MockPool, v0_6::UserOperation, GasFees, UserOpsPerAggregator,
    };
    use tokio::sync::{broadcast, mpsc};

    use super::*;
    use crate::{
        bundle_proposer::{Bundle, MockBundleProposer},
        bundle_sender::{BundleSenderImpl, MockTrigger},
        transaction_tracker::MockTransactionTracker,
    };

    #[tokio::test]
    async fn test_empty_send() {
        let Mocks {
            mut mock_proposer,
            mock_entry_point,
            mut mock_tracker,
            mut mock_trigger,
        } = new_mocks();

        // block 0
        add_trigger_no_update_last_block(
            &mut mock_trigger,
            &mut mock_tracker,
            &mut Sequence::new(),
            0,
        );

        // zero nonce
        mock_tracker
            .expect_get_nonce_and_required_fees()
            .returning(|| Ok((0, None)));

        // empty bundle
        mock_proposer
            .expect_make_bundle()
            .times(1)
            .returning(|_, _| Box::pin(async { Ok(Bundle::<UserOperation>::default()) }));

        let mut sender = new_sender(mock_proposer, mock_entry_point);

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
            mut mock_proposer,
            mut mock_entry_point,
            mut mock_tracker,
            mut mock_trigger,
        } = new_mocks();

        // block 0
        add_trigger_no_update_last_block(
            &mut mock_trigger,
            &mut mock_tracker,
            &mut Sequence::new(),
            0,
        );

        // zero nonce
        mock_tracker
            .expect_get_nonce_and_required_fees()
            .returning(|| Ok((0, None)));

        // bundle with one op
        mock_proposer
            .expect_make_bundle()
            .times(1)
            .returning(|_, _| Box::pin(async { Ok(bundle()) }));

        // should create the bundle txn
        mock_entry_point
            .expect_get_send_bundle_transaction()
            .returning(|_, _, _, _| TransactionRequest::default());

        // should send the bundle txn
        mock_tracker
            .expect_send_transaction()
            .returning(|_, _| Box::pin(async { Ok(B256::ZERO) }));

        let mut sender = new_sender(mock_proposer, mock_entry_point);

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
    async fn test_wait_for_mine_success() {
        let Mocks {
            mock_proposer,
            mock_entry_point,
            mut mock_tracker,
            mut mock_trigger,
        } = new_mocks();

        let mut seq = Sequence::new();
        add_trigger_wait_for_block_last_block(&mut mock_trigger, &mut seq, 1);
        mock_trigger
            .expect_wait_for_block()
            .once()
            .in_sequence(&mut seq)
            .returning(|| {
                Box::pin(async {
                    Ok(NewHead {
                        block_number: 2,
                        block_hash: B256::ZERO,
                    })
                })
            });
        // no call to last_block after mine

        let mut seq = Sequence::new();
        mock_tracker
            .expect_check_for_update()
            .once()
            .in_sequence(&mut seq)
            .returning(|| Box::pin(async { Ok(None) }));
        mock_tracker
            .expect_check_for_update()
            .once()
            .in_sequence(&mut seq)
            .returning(|| {
                Box::pin(async {
                    Ok(Some(TrackerUpdate::Mined {
                        block_number: 2,
                        nonce: 0,
                        gas_limit: None,
                        gas_used: None,
                        gas_price: None,
                        tx_hash: B256::ZERO,
                        attempt_number: 0,
                    }))
                })
            });

        let mut sender = new_sender(mock_proposer, mock_entry_point);

        // start in pending state
        let mut state = SenderMachineState {
            trigger: mock_trigger,
            transaction_tracker: mock_tracker,
            send_bundle_response: None,
            inner: InnerState::Pending(PendingState {
                until: 3,
                fee_increase_count: 0,
            }),
            requires_reset: false,
        };

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
            mock_proposer,
            mock_entry_point,
            mut mock_tracker,
            mut mock_trigger,
        } = new_mocks();

        let mut seq = Sequence::new();
        for i in 1..=3 {
            add_trigger_wait_for_block_last_block(&mut mock_trigger, &mut seq, i);
        }

        mock_tracker
            .expect_check_for_update()
            .times(3)
            .returning(|| Box::pin(async { Ok(None) }));

        let mut sender = new_sender(mock_proposer, mock_entry_point);

        // start in pending state
        let mut state = SenderMachineState {
            trigger: mock_trigger,
            transaction_tracker: mock_tracker,
            send_bundle_response: None,
            inner: InnerState::Pending(PendingState {
                until: 3,
                fee_increase_count: 0,
            }),
            requires_reset: false,
        };

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
            mut mock_proposer,
            mock_entry_point,
            mut mock_tracker,
            mut mock_trigger,
        } = new_mocks();

        let mut seq = Sequence::new();
        add_trigger_no_update_last_block(&mut mock_trigger, &mut mock_tracker, &mut seq, 3);

        // zero nonce
        mock_tracker
            .expect_get_nonce_and_required_fees()
            .returning(|| Ok((0, None)));

        // fee filter error
        mock_proposer
            .expect_make_bundle()
            .times(1)
            .returning(|_, _| {
                Box::pin(async { Err(BundleProposerError::NoOperationsAfterFeeFilter) })
            });

        let mut sender = new_sender(mock_proposer, mock_entry_point);

        // start in underpriced meta-state
        let mut state = SenderMachineState {
            trigger: mock_trigger,
            transaction_tracker: mock_tracker,
            send_bundle_response: None,
            inner: InnerState::Building(BuildingState {
                wait_for_trigger: true,
                fee_increase_count: 0,
                underpriced_info: Some(UnderpricedInfo {
                    since_block: 0,
                    rounds: 1,
                }),
            }),
            requires_reset: false,
        };

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
            mut mock_proposer,
            mock_entry_point,
            mut mock_tracker,
            mut mock_trigger,
        } = new_mocks();

        mock_proposer
            .expect_estimate_gas_fees()
            .once()
            .returning(|_| Box::pin(async { Ok((GasFees::default(), 0)) }));

        mock_tracker
            .expect_cancel_transaction()
            .once()
            .returning(|_, _| Box::pin(async { Ok(Some(B256::ZERO)) }));

        mock_trigger.expect_last_block().return_const(NewHead {
            block_number: 0,
            block_hash: B256::ZERO,
        });

        let mut state = SenderMachineState {
            trigger: mock_trigger,
            transaction_tracker: mock_tracker,
            send_bundle_response: None,
            inner: InnerState::Cancelling(CancellingState {
                fee_increase_count: 0,
            }),
            requires_reset: false,
        };

        let mut sender = new_sender(mock_proposer, mock_entry_point);

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
    async fn test_resubmit_cancel() {
        let Mocks {
            mock_proposer,
            mock_entry_point,
            mut mock_tracker,
            mut mock_trigger,
        } = new_mocks();

        let mut seq = Sequence::new();
        for i in 1..=3 {
            add_trigger_wait_for_block_last_block(&mut mock_trigger, &mut seq, i);
        }

        mock_tracker
            .expect_check_for_update()
            .times(3)
            .returning(|| Box::pin(async { Ok(None) }));

        let mut state = SenderMachineState {
            trigger: mock_trigger,
            transaction_tracker: mock_tracker,
            send_bundle_response: None,
            inner: InnerState::CancelPending(CancelPendingState {
                until: 3,
                fee_increase_count: 0,
            }),
            requires_reset: false,
        };

        let mut sender = new_sender(mock_proposer, mock_entry_point);

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
            mut mock_proposer,
            mut mock_entry_point,
            mut mock_tracker,
            mut mock_trigger,
        } = new_mocks();

        let mut seq = Sequence::new();
        add_trigger_no_update_last_block(&mut mock_trigger, &mut mock_tracker, &mut seq, 1);

        // zero nonce
        mock_tracker
            .expect_get_nonce_and_required_fees()
            .returning(|| Ok((0, None)));

        // bundle with one op
        mock_proposer
            .expect_make_bundle()
            .times(1)
            .returning(|_, _| Box::pin(async { Ok(bundle()) }));

        // should create the bundle txn
        mock_entry_point
            .expect_get_send_bundle_transaction()
            .returning(|_, _, _, _| TransactionRequest::default());

        // should send the bundle txn, returns condition not met
        mock_tracker
            .expect_send_transaction()
            .returning(|_, _| Box::pin(async { Err(TransactionTrackerError::ConditionNotMet) }));

        // should notify proposer that condition was not met
        mock_proposer
            .expect_notify_condition_not_met()
            .times(1)
            .return_const(());

        let mut state = SenderMachineState {
            trigger: mock_trigger,
            transaction_tracker: mock_tracker,
            send_bundle_response: None,
            inner: InnerState::Building(BuildingState {
                wait_for_trigger: true,
                fee_increase_count: 0,
                underpriced_info: None,
            }),
            requires_reset: false,
        };

        let mut sender = new_sender(mock_proposer, mock_entry_point);

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

    struct Mocks {
        mock_proposer: MockBundleProposer,
        mock_entry_point: MockEntryPointV0_6,
        mock_tracker: MockTransactionTracker,
        mock_trigger: MockTrigger,
    }

    fn new_mocks() -> Mocks {
        let mut mock_entry_point = MockEntryPointV0_6::new();
        mock_entry_point
            .expect_address()
            .return_const(Address::default());

        Mocks {
            mock_proposer: MockBundleProposer::new(),
            mock_entry_point,
            mock_tracker: MockTransactionTracker::new(),
            mock_trigger: MockTrigger::new(),
        }
    }

    fn new_sender(
        mock_proposer: MockBundleProposer,
        mock_entry_point: MockEntryPointV0_6,
    ) -> BundleSenderImpl<
        UserOperation,
        MockBundleProposer,
        MockEntryPointV0_6,
        MockTransactionTracker,
        MockPool,
    > {
        BundleSenderImpl::new(
            0,
            mpsc::channel(1000).1,
            ChainSpec::default(),
            Address::default(),
            mock_proposer,
            mock_entry_point,
            MockTransactionTracker::new(),
            MockPool::new(),
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
        mock_tracker: &mut MockTransactionTracker,
        seq: &mut Sequence,
        block_number: u64,
    ) {
        mock_trigger
            .expect_wait_for_trigger()
            .once()
            .in_sequence(seq)
            .returning(move || Box::pin(async move { Ok(None) }));
        mock_tracker
            .expect_check_for_update()
            .returning(|| Box::pin(async { Ok(None) }));
        mock_trigger
            .expect_last_block()
            .once()
            .in_sequence(seq)
            .return_const(NewHead {
                block_number,
                block_hash: B256::ZERO,
            });
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
            .returning(move || {
                Box::pin(async move {
                    Ok(NewHead {
                        block_number,
                        block_hash: B256::ZERO,
                    })
                })
            });
        mock_trigger
            .expect_last_block()
            .once()
            .in_sequence(seq)
            .return_const(NewHead {
                block_number,
                block_hash: B256::ZERO,
            });
        mock_trigger
            .expect_builder_must_wait_for_trigger()
            .return_const(false);
    }

    fn bundle() -> Bundle<UserOperation> {
        Bundle {
            gas_estimate: 100_000,
            gas_fees: GasFees::default(),
            expected_storage: Default::default(),
            rejected_ops: vec![],
            entity_updates: vec![],
            ops_per_aggregator: vec![UserOpsPerAggregator {
                aggregator: Address::ZERO,
                signature: Bytes::new(),
                user_ops: vec![UserOperation::default()],
            }],
        }
    }
}
