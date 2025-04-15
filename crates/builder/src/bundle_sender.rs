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

use std::sync::Arc;

use alloy_primitives::{Address, B256, U256};
use anyhow::{bail, Context};
use metrics::Counter;
use metrics_derive::Metrics;
use rundler_provider::{
    BundleHandler, EntryPoint, EvmProvider, GethDebugBuiltInTracerType, GethDebugTracerCallConfig,
    GethDebugTracerType, GethDebugTracingOptions, HandleOpsOut, ProvidersWithEntryPointT,
    TransactionRequest,
};
use rundler_types::{
    chain::ChainSpec,
    pool::{AddressUpdate, NewHead, Pool, PoolOperation},
    proxy::SubmissionProxy,
    EntityUpdate, ExpectedStorage, UserOperation,
};
use rundler_utils::emit::WithEntryPoint;
use tokio::{join, sync::broadcast};
use tracing::{debug, error, info, instrument, warn};

use crate::{
    assigner::Assigner,
    bundle_proposer::{Bundle, BundleProposer, BundleProposerError},
    emit::{BuilderEvent, BundleTxDetails},
    transaction_tracker::{TrackerUpdate, TransactionTracker, TransactionTrackerError},
};

#[derive(Debug, Clone)]
pub(crate) struct Settings {
    pub(crate) max_replacement_underpriced_blocks: u64,
    pub(crate) max_cancellation_fee_increases: u64,
    pub(crate) max_blocks_to_wait_for_mine: u64,
}

pub(crate) struct BundleSenderTask<P, EP, C> {
    builder_tag: String,
    chain_spec: ChainSpec,
    // Optional submission proxy - bundles are sent through this contract
    submission_proxy: Option<Arc<dyn SubmissionProxy>>,
    proposer: P,
    ep_providers: EP,
    transaction_tracker: Box<dyn TransactionTracker>,
    pool: C,
    settings: Settings,
    event_sender: broadcast::Sender<WithEntryPoint<BuilderEvent>>,
    metrics: BuilderMetric,
    ep_address: Address,

    balance: U256,
    block_number: u64,
    state: State,
    block_receiver: broadcast::Receiver<NewHead>,
    filter_id: Option<String>,
    assigner: Assigner,
}

#[derive(Debug)]
struct BundleTx {
    tx: TransactionRequest,
    expected_storage: ExpectedStorage,
    op_hashes: Vec<B256>,
}

/// Response to a `SendBundleRequest` after
/// going through a full cycle of bundling, sending,
/// and waiting for the transaction to be mined.
#[derive(Debug)]
pub(crate) enum SendBundleResult {
    Success { block_number: u64, tx_hash: B256 },
    NoOperationsInitially,
    Cancelled,
    CancelFailed,
    Error(anyhow::Error),
}

pub(crate) struct BundleSenderTaskArgs<P, EP, C> {
    pub(crate) builder_tag: String,
    pub(crate) chain_spec: ChainSpec,
    pub(crate) submission_proxy: Option<Arc<dyn SubmissionProxy>>,
    pub(crate) proposer: P,
    pub(crate) ep_providers: EP,
    pub(crate) transaction_tracker: Box<dyn TransactionTracker>,
    pub(crate) pool: C,
    pub(crate) settings: Settings,
    pub(crate) event_sender: broadcast::Sender<WithEntryPoint<BuilderEvent>>,
    pub(crate) balance: U256,
    pub(crate) block_number: u64,
    pub(crate) block_receiver: broadcast::Receiver<NewHead>,
    pub(crate) assigner: Assigner,
    pub(crate) filter_id: Option<String>,
}

#[async_trait::async_trait]
pub(crate) trait BundleSenderTaskT: Send + Sync {
    async fn run(&mut self) -> SendBundleResult;
}

#[async_trait::async_trait]
impl<P, EP, C> BundleSenderTaskT for BundleSenderTask<P, EP, C>
where
    EP: ProvidersWithEntryPointT,
    P: BundleProposer<UO = EP::UO>,
    C: Pool,
{
    async fn run(&mut self) -> SendBundleResult {
        loop {
            if let State::Complete(result) = &mut self.state {
                return result
                    .take()
                    .unwrap_or_else(|| SendBundleResult::Error(anyhow::anyhow!("no result")));
            }

            if let Err(e) = self.step_state().await {
                error!("Error in bundle sender loop: {e:#?}");
                self.metrics.state_machine_errors.increment(1);
                return SendBundleResult::Error(e);
            }
        }
    }
}

impl<P, EP, C> BundleSenderTask<P, EP, C>
where
    EP: ProvidersWithEntryPointT,
    P: BundleProposer<UO = EP::UO>,
    C: Pool,
{
    pub(crate) fn new(args: BundleSenderTaskArgs<P, EP, C>) -> Self {
        let metrics = BuilderMetric::new_with_labels(&[
            (
                "entry_point",
                args.ep_providers.entry_point().address().to_string(),
            ),
            ("builder_tag", args.builder_tag.clone()),
        ]);

        Self {
            builder_tag: args.builder_tag,
            chain_spec: args.chain_spec,
            submission_proxy: args.submission_proxy,
            proposer: args.proposer,
            ep_address: *args.ep_providers.entry_point().address(),
            ep_providers: args.ep_providers,
            transaction_tracker: args.transaction_tracker,
            pool: args.pool,
            settings: args.settings,
            event_sender: args.event_sender,
            metrics,
            balance: args.balance,
            state: State::new(),
            block_number: args.block_number,
            block_receiver: args.block_receiver,
            filter_id: args.filter_id,
            assigner: args.assigner,
        }
    }

    #[instrument(skip_all, fields(tag = self.builder_tag))]
    async fn step_state(&mut self) -> anyhow::Result<()> {
        match self.state {
            State::Building(building_state) => {
                self.state = self.handle_building_state(building_state).await?;
            }
            State::Pending(pending_state) => {
                self.state = self.handle_pending_state(pending_state).await?;
            }
            State::Cancelling(cancelling_state) => {
                self.state = self.handle_cancelling_state(cancelling_state).await?;
            }
            State::CancelPending(cancel_pending_state) => {
                self.state = self
                    .handle_cancel_pending_state(cancel_pending_state)
                    .await?;
            }
            State::Complete(_) => {
                bail!("step called on complete state");
            }
        }

        Ok(())
    }

    async fn handle_building_state(&mut self, state: BuildingState) -> anyhow::Result<State> {
        debug!("Building bundle on block {}", self.block_number);
        let result = self.send_bundle(state.fee_increase_count).await;

        // handle result
        let state = match result {
            Ok(SendBundleAttemptResult::Success) => {
                // sent the bundle
                debug!("Bundle sent successfully");
                State::Pending(PendingState {
                    until: self.block_number + self.settings.max_blocks_to_wait_for_mine,
                    fee_increase_count: state.fee_increase_count,
                })
            }
            Ok(SendBundleAttemptResult::NoOperationsInitially) => {
                debug!("No operations available initially");
                State::Complete(Some(SendBundleResult::NoOperationsInitially))
            }
            Ok(SendBundleAttemptResult::NoOperationsAfterSimulation) => {
                debug!("No operations available after simulation");
                State::Complete(Some(SendBundleResult::NoOperationsInitially))
            }
            Ok(SendBundleAttemptResult::NoOperationsAfterFeeFilter) => {
                debug!("No operations to bundle after fee filtering");
                if let Some(underpriced_info) = state.underpriced_info {
                    // If we are here, there are UOs in the pool that may be correctly priced, but are being blocked by an underpriced replacement
                    // after a fee increase. If we repeatedly get into this state, initiate a cancellation.
                    if self
                        .block_number
                        .saturating_sub(underpriced_info.since_block)
                        >= self.settings.max_replacement_underpriced_blocks
                    {
                        warn!("No operations available, but last replacement underpriced, moving to cancelling state. Round: {}. Since block {}. Current block {}. Max underpriced blocks: {}", underpriced_info.rounds, underpriced_info.since_block, self.block_number, self.settings.max_replacement_underpriced_blocks);
                        State::Cancelling(state.to_cancelling())
                    } else {
                        info!("No operations available, but last replacement underpriced, starting over and waiting for next trigger. Round: {}. Since block {}. Current block {}", underpriced_info.rounds, underpriced_info.since_block, self.block_number);
                        // Abandon the transaction tracker when we start the next bundle attempt fresh, may cause a `ReplacementUnderpriced` in next round
                        self.transaction_tracker.abandon();

                        State::Building(state.underpriced_round())
                    }
                } else if state.fee_increase_count > 0 {
                    warn!(
                        "Abandoning bundle after {} fee increases, no operations available after fee increase",
                        state.fee_increase_count
                    );
                    self.metrics.bundle_txns_abandoned.increment(1);

                    // abandon the bundle by starting a new bundle process
                    // If the node we are using still has the transaction in the mempool, its
                    // possible we will get a `ReplacementUnderpriced` on the next iteration
                    // and will start a cancellation.
                    self.transaction_tracker.abandon();
                    State::new()
                } else {
                    debug!("No operations available, waiting for next trigger");
                    State::Complete(Some(SendBundleResult::NoOperationsInitially))
                }
            }
            Ok(SendBundleAttemptResult::NonceTooLow) => {
                // reset the transaction tracker and try again
                info!("Nonce too low, starting new bundle attempt");
                self.transaction_tracker.reset().await;
                State::new()
            }
            Ok(SendBundleAttemptResult::Underpriced) => {
                info!(
                    "Bundle underpriced, marking as underpriced. Num fee increases {:?}",
                    state.fee_increase_count
                );
                State::Building(state.underpriced(self.block_number))
            }
            Ok(SendBundleAttemptResult::ReplacementUnderpriced) => {
                info!("Replacement transaction underpriced, marking as underpriced. Num fee increases {:?}", state.fee_increase_count);
                // unabandon to allow fee estimation to consider any submitted transactions, wait for next trigger
                self.transaction_tracker.unabandon();
                State::Building(state.underpriced(self.block_number))
            }
            Ok(SendBundleAttemptResult::ConditionNotMet) => {
                info!("Condition not met, notifying proposer and starting new bundle attempt");
                self.proposer.notify_condition_not_met();
                State::Building(state)
            }
            Ok(SendBundleAttemptResult::InsufficientFunds) => {
                // Insufficient funds
                info!("Insufficient funds sending bundle, resetting state and starting new bundle attempt");
                State::Complete(Some(SendBundleResult::Error(anyhow::anyhow!(
                    "Insufficient funds"
                ))))
            }
            Ok(SendBundleAttemptResult::Rejected) => {
                // Bundle was rejected, try with a higher price
                // May want to consider a simple retry instead of increasing fees, but this should be rare
                info!(
                    "Bundle rejected, assuming underpriced. Num fee increases {:?}",
                    state.fee_increase_count
                );
                State::Building(state.underpriced(self.block_number))
            }
            Err(error) => {
                error!("Bundle send error {error:?}");
                self.metrics.bundle_txns_failed.increment(1);
                State::Complete(Some(SendBundleResult::Error(error)))
            }
        };

        Ok(state)
    }

    async fn handle_pending_state(&mut self, state: PendingState) -> anyhow::Result<State> {
        let tracker_update = self.wait_for_update().await?;

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
                    info!("Bundle transaction mined: block number {block_number}, attempt number {attempt_number}, gas limit {gas_limit:?}, gas used {gas_used:?}, tx hash {tx_hash}, nonce {nonce}, success {is_success}");

                    self.metrics
                        .process_bundle_txn_mined(gas_limit, gas_used, is_success);

                    if !is_success {
                        if let Err(e) = self.process_revert(tx_hash).await {
                            warn!("Failed to process revert for bundle transaction {tx_hash:?}: {e:#?}");
                        }
                    }

                    self.emit(BuilderEvent::transaction_mined(
                        self.builder_tag.clone(),
                        tx_hash,
                        nonce,
                        block_number,
                    ));

                    Ok(State::Complete(Some(SendBundleResult::Success {
                        block_number,
                        tx_hash,
                    })))
                }
                TrackerUpdate::NonceUsedForOtherTx { nonce } => {
                    info!("Nonce used externally, starting new bundle attempt");
                    self.emit(BuilderEvent::nonce_used_for_other_transaction(
                        self.builder_tag.clone(),
                        nonce,
                    ));
                    self.metrics.bundle_txns_nonce_used.increment(1);
                    Ok(State::new())
                }
            }
        } else if self.block_number >= state.until {
            // start replacement, don't wait for trigger. Continue
            // to attempt until there are no longer any UOs priced high enough
            // to bundle.
            info!(
                "Not mined after {} blocks, increasing fees, attempt: {}",
                self.settings.max_blocks_to_wait_for_mine,
                state.fee_increase_count + 1
            );
            self.metrics.bundle_txn_fee_increases.increment(1);
            Ok(State::Building(state.to_building()))
        } else {
            Ok(State::Pending(state))
        }
    }

    async fn handle_cancelling_state(&mut self, state: CancellingState) -> anyhow::Result<State> {
        info!(
            "Cancelling last transaction, attempt {}",
            state.fee_increase_count
        );

        let (estimated_fees, _) = self
            .proposer
            .estimate_gas_fees(None)
            .await
            .unwrap_or_default();

        let cancel_res = self
            .transaction_tracker
            .cancel_transaction(estimated_fees)
            .await;

        match cancel_res {
            Ok(Some(_)) => {
                info!("Cancellation transaction sent, waiting for confirmation");
                self.metrics.cancellation_txns_sent.increment(1);

                Ok(State::CancelPending(state.to_cancel_pending(
                    self.block_number + self.settings.max_blocks_to_wait_for_mine,
                )))
            }
            Ok(None) => {
                info!("Soft cancellation or no transaction to cancel, starting new bundle attempt");
                self.metrics.soft_cancellations.increment(1);
                Ok(State::Complete(Some(SendBundleResult::Cancelled)))
            }
            Err(TransactionTrackerError::Rejected)
            | Err(TransactionTrackerError::Underpriced)
            | Err(TransactionTrackerError::ReplacementUnderpriced) => {
                info!("Transaction underpriced/rejected during cancellation, trying again. {cancel_res:?}");
                if state.fee_increase_count >= self.settings.max_cancellation_fee_increases {
                    // abandon the cancellation
                    warn!("Abandoning cancellation after max fee increases {}, starting new bundle attempt", state.fee_increase_count);
                    self.metrics.cancellations_abandoned.increment(1);
                    Ok(State::Complete(Some(SendBundleResult::CancelFailed)))
                } else {
                    // Increase fees again
                    info!(
                        "Cancellation increasing fees, attempt: {}",
                        state.fee_increase_count + 1
                    );
                    Ok(State::Cancelling(state.increase_fees()))
                }
            }
            Err(TransactionTrackerError::NonceTooLow) => {
                // reset the transaction tracker and try again
                info!("Nonce too low during cancellation, starting new bundle attempt");
                Ok(State::Complete(Some(SendBundleResult::CancelFailed)))
            }
            Err(TransactionTrackerError::InsufficientFunds) => {
                error!("Insufficient funds during cancellation, starting new bundle attempt");
                self.metrics.cancellation_txns_failed.increment(1);
                Ok(State::Complete(Some(SendBundleResult::CancelFailed)))
            }
            Err(TransactionTrackerError::ConditionNotMet) => {
                error!(
                    "Unexpected condition not met during cancellation, starting new bundle attempt"
                );
                self.metrics.cancellation_txns_failed.increment(1);
                Ok(State::Complete(Some(SendBundleResult::CancelFailed)))
            }
            Err(TransactionTrackerError::Other(e)) => {
                error!("Failed to cancel transaction, moving back to building state: {e:#?}");
                self.metrics.cancellation_txns_failed.increment(1);
                Ok(State::Complete(Some(SendBundleResult::CancelFailed)))
            }
        }
    }

    async fn handle_cancel_pending_state(
        &mut self,
        state: CancelPendingState,
    ) -> anyhow::Result<State> {
        let tracker_update = self.wait_for_update().await?;

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
                TrackerUpdate::NonceUsedForOtherTx { .. } => {
                    // If a nonce is used externally, move to bundling state as there is no longer
                    // a pending transaction
                    info!("Nonce used externally while cancelling, starting new bundle attempt");
                }
            }
            Ok(State::Complete(Some(SendBundleResult::Cancelled)))
        } else if self.block_number >= state.until {
            if state.fee_increase_count >= self.settings.max_cancellation_fee_increases {
                // abandon the cancellation
                warn!("Abandoning cancellation after max fee increases {}, starting new bundle attempt", state.fee_increase_count);
                self.metrics.cancellations_abandoned.increment(1);
                Ok(State::Complete(Some(SendBundleResult::CancelFailed)))
            } else {
                // start replacement, don't wait for trigger
                info!(
                    "Cancellation not mined after {} blocks, increasing fees, attempt: {}",
                    self.settings.max_blocks_to_wait_for_mine,
                    state.fee_increase_count + 1
                );
                Ok(State::Cancelling(state.to_cancelling()))
            }
        } else {
            Ok(State::CancelPending(state))
        }
    }

    async fn wait_for_update(&mut self) -> anyhow::Result<Option<TrackerUpdate>> {
        let mut blocks = vec![];

        loop {
            match self.block_receiver.recv().await {
                Ok(block) => {
                    blocks.push(block);
                    break;
                }
                Err(broadcast::error::RecvError::Closed) => {
                    tracing::error!("Block stream closed");
                    anyhow::bail!("Block stream closed");
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    // Missed block updates, reset the transaction tracker
                    // and retry
                    self.transaction_tracker.reset().await;
                }
            }
        }

        loop {
            match self.block_receiver.try_recv() {
                Ok(block) => {
                    blocks.push(block);
                }
                Err(broadcast::error::TryRecvError::Empty) => {
                    break;
                }
                Err(broadcast::error::TryRecvError::Closed) => {
                    tracing::error!("Block stream closed");
                    anyhow::bail!("Block stream closed");
                }
                Err(broadcast::error::TryRecvError::Lagged(_)) => {
                    // Missed block updates, reset the transaction tracker
                    // and retry
                    self.transaction_tracker.reset().await;
                }
            }
        }

        let mut address_update: Option<AddressUpdate> = None;
        for block in blocks {
            if let Some(u) = block
                .address_updates
                .iter()
                .find(|u| u.address == self.transaction_tracker.address())
            {
                if let Some(update) = &mut address_update {
                    update.balance = u.balance;
                    update.nonce = u.nonce;
                    update.mined_tx_hashes.extend(u.mined_tx_hashes.clone());
                } else {
                    address_update = Some(u.clone());
                }
            }

            self.block_number = block.block_number;
        }

        if let Some(address_update) = address_update {
            Ok(self
                .transaction_tracker
                .process_update(&address_update)
                .await?)
        } else {
            Ok(None)
        }
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

        let ops = self
            .assigner
            .get_operations(
                self.transaction_tracker.address(),
                self.ep_address,
                self.filter_id.clone(),
            )
            .await?;

        if ops.is_empty() {
            return Ok(SendBundleAttemptResult::NoOperationsInitially);
        }

        let bundle = match self
            .proposer
            .make_bundle(ops, self.balance, required_fees, fee_increase_count > 0)
            .await
        {
            Ok(bundle) => bundle,
            Err(BundleProposerError::NoOperationsAfterFeeFilter) => {
                return Ok(SendBundleAttemptResult::NoOperationsAfterFeeFilter);
            }
            Err(e) => bail!("Failed to make bundle: {e:?}"),
        };

        let Some(bundle_tx) = self.process_proposed_bundle(nonce, bundle).await? else {
            self.emit(BuilderEvent::formed_bundle(
                self.builder_tag.clone(),
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

        let send_result = self
            .transaction_tracker
            .send_transaction(tx.clone(), &expected_storage, self.block_number)
            .await;
        self.metrics.bundle_txns_sent.increment(1);

        match send_result {
            Ok(tx_hash) => {
                self.emit(BuilderEvent::formed_bundle(
                    self.builder_tag.clone(),
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
            Err(TransactionTrackerError::InsufficientFunds) => {
                self.metrics.bundle_txn_insufficient_funds.increment(1);
                error!("Bundle attempt insufficient funds");
                Ok(SendBundleAttemptResult::InsufficientFunds)
            }
            Err(TransactionTrackerError::Other(e)) => {
                error!("Failed to send bundle with unexpected error: {e:?}");
                Err(e)
            }
        }
    }

    /// Builds a bundle and returns some metadata and the transaction to send
    /// it, or `None` if there are no valid operations available.
    async fn process_proposed_bundle(
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
        info!(
            "Selected bundle with {} op(s), with {} rejected op(s) and {} updated entities",
            bundle.len(),
            bundle.rejected_ops.len(),
            bundle.entity_updates.len()
        );
        let op_hashes: Vec<_> = bundle.iter_ops().map(|op| op.hash()).collect();

        let mut tx = self.ep_providers.entry_point().get_send_bundle_transaction(
            bundle.ops_per_aggregator,
            self.transaction_tracker.address(),
            bundle.gas_estimate,
            bundle.gas_fees,
            self.submission_proxy.as_ref().map(|p| p.address()),
        );

        let to_unlock = bundle
            .skipped_ops
            .into_iter()
            .chain(bundle.rejected_ops.into_iter())
            .collect();
        self.assigner
            .return_operations(self.transaction_tracker.address(), to_unlock);

        tx = tx.nonce(nonce);
        Ok(Some(BundleTx {
            tx,
            expected_storage: bundle.expected_storage,
            op_hashes,
        }))
    }

    async fn remove_ops_from_pool(&self, ops: &[PoolOperation]) -> anyhow::Result<()> {
        self.pool
            .remove_ops(self.ep_address, ops.iter().map(|op| op.uo.hash()).collect())
            .await
            .context("builder should remove rejected ops from pool")
    }

    async fn remove_ops_from_pool_by_hash(&self, hashes: Vec<B256>) -> anyhow::Result<()> {
        self.pool
            .remove_ops(self.ep_address, hashes)
            .await
            .context("builder should remove rejected ops from pool")
    }

    async fn update_entities_in_pool(&self, entity_updates: &[EntityUpdate]) -> anyhow::Result<()> {
        self.pool
            .update_entities(self.ep_address, entity_updates.to_vec())
            .await
            .context("builder should remove update entities in the pool")
    }

    async fn process_revert(&self, tx_hash: B256) -> anyhow::Result<()> {
        warn!("Bundle transaction {tx_hash:?} reverted onchain");

        let trace_options = GethDebugTracingOptions::new_tracer(
            GethDebugTracerType::BuiltInTracer(GethDebugBuiltInTracerType::CallTracer),
        )
        .with_call_config(GethDebugTracerCallConfig::default().only_top_call());

        let trace = self
            .ep_providers
            .evm()
            .debug_trace_transaction(tx_hash, trace_options)
            .await
            .context("should have fetched trace from provider")?;

        let frame = trace
            .try_into_call_frame()
            .context("trace is not a call tracer")?;

        let ops = EP::EntryPoint::decode_ops_from_calldata(&self.chain_spec, &frame.input);

        let Some(revert_data) = frame.output else {
            tracing::error!("revert has not output, removing all ops from bundle from pool");
            let to_remove = ops
                .iter()
                .flat_map(|ops| ops.user_ops.iter().map(|op| op.hash()))
                .collect();
            return self.remove_ops_from_pool_by_hash(to_remove).await;
        };
        tracing::warn!("Onchain revert data for {tx_hash:?}: {revert_data:?}");

        // If we have a submission proxy, use it to process the revert first
        if let Some(proxy) = &self.submission_proxy {
            let ops = ops
                .clone()
                .into_iter()
                .map(|uo| uo.into_uo_variants())
                .collect::<Vec<_>>();
            let to_remove = proxy.process_revert(&revert_data, &ops).await;
            if !to_remove.is_empty() {
                return self.remove_ops_from_pool_by_hash(to_remove).await;
            }
        }

        let handle_ops_out = EP::EntryPoint::decode_handle_ops_revert(
            frame.error.as_ref().map_or("", |e| e),
            &Some(revert_data),
        );
        tracing::warn!(
            "reverted transaction {tx_hash:?} decoded handle ops out: {handle_ops_out:?}"
        );

        let to_remove = match handle_ops_out {
            Some(HandleOpsOut::Success) => {
                bail!("handle ops returned success");
            }
            Some(HandleOpsOut::FailedOp(index, _)) => {
                tracing::warn!("removing op from pool for reverted bundle op index {index:?}",);
                ops.iter()
                    .flat_map(|ops| ops.user_ops.iter())
                    .nth(index)
                    .map(|op| vec![op.hash()])
                    .unwrap_or_default()
            }
            Some(HandleOpsOut::SignatureValidationFailed(aggregator)) => {
                tracing::warn!(
                    "removing all ops from pool for reverted bundle for aggregator {aggregator:?}",
                );
                ops.iter()
                    .find(|op| op.aggregator == aggregator)
                    .map(|ops| ops.user_ops.iter().map(|op| op.hash()).collect())
                    .unwrap_or_default()
            }
            None | Some(HandleOpsOut::Revert(_)) | Some(HandleOpsOut::PostOpRevert) => {
                tracing::warn!("removing all ops from pool for reverted bundle");
                ops.iter()
                    .flat_map(|ops| ops.user_ops.iter().map(|op| op.hash()))
                    .collect()
            }
        };

        self.remove_ops_from_pool_by_hash(to_remove).await
    }

    fn emit(&self, event: BuilderEvent) {
        let _ = self.event_sender.send(WithEntryPoint {
            entry_point: self.ep_address,
            event,
        });
    }
}

// Internal result of attempting to send a bundle.
#[derive(Debug)]
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
    // Insufficient Funds
    InsufficientFunds,
    // Nonce too low
    NonceTooLow,
}

// State of the sender loop
#[derive(Debug)]
enum State {
    // Building a bundle, optionally waiting for a trigger to send it
    Building(BuildingState),
    // Waiting for a bundle to be mined
    Pending(PendingState),
    // Cancelling the last transaction
    Cancelling(CancellingState),
    // Waiting for a cancellation transaction to be mined
    CancelPending(CancelPendingState),
    // Complete
    Complete(Option<SendBundleResult>),
}

impl State {
    fn new() -> Self {
        State::Building(BuildingState {
            fee_increase_count: 0,
            underpriced_info: None,
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct BuildingState {
    fee_increase_count: u64,
    underpriced_info: Option<UnderpricedInfo>,
}

#[derive(Debug, Clone, Copy)]
struct UnderpricedInfo {
    since_block: u64,
    rounds: u64,
}

impl BuildingState {
    // Transition to cancelling state
    fn to_cancelling(self) -> CancellingState {
        CancellingState {
            fee_increase_count: 0,
        }
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
    fn increase_fees(mut self) -> Self {
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

#[derive(Metrics)]
#[metrics(scope = "builder")]
struct BuilderMetric {
    #[metric(describe = "the count of bundle transactions already sent.")]
    bundle_txns_sent: Counter,
    #[metric(describe = "the count of successful bundle transactions.")]
    bundle_txns_success: Counter,
    #[metric(describe = "the count of reverted bundle transactions.")]
    bundle_txns_reverted: Counter,
    #[metric(describe = "the count of bundle gas limit.")]
    bundle_gas_limit: Counter,
    #[metric(describe = "the count of bundle gas used.")]
    bundle_gas_used: Counter,
    #[metric(describe = "the count of abandoned bundle transactions.")]
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
    #[metric(describe = "the count of bundle transactions with insufficient funds")]
    bundle_txn_insufficient_funds: Counter,
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
}

impl BuilderMetric {
    fn process_bundle_txn_mined(
        &self,
        gas_limit: Option<u64>,
        gas_used: Option<u128>,
        is_success: bool,
    ) {
        if is_success {
            self.bundle_txns_success.increment(1);
        } else {
            self.bundle_txns_reverted.increment(1);
        }

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
    use alloy_primitives::{bytes, Bytes, U256};
    use mockall::Sequence;
    use rundler_provider::{
        GethDebugTracerCallFrame, MockDAGasOracleSync, MockEntryPointV0_6, MockEvmProvider,
        ProvidersWithEntryPoint,
    };
    use rundler_types::{
        chain::ChainSpec,
        pool::{AddressUpdate, MockPool},
        v0_6::UserOperation,
        GasFees, UserOperation as _, UserOpsPerAggregator,
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
            mut mock_evm,
        } = new_mocks();

        // block 0
        add_trigger_no_update_last_block(&mut mock_trigger, &mut Sequence::new(), 0);

        // zero nonce
        mock_tracker
            .expect_get_nonce_and_required_fees()
            .returning(|| Ok((0, None)));
        mock_tracker.expect_address().return_const(Address::ZERO);

        mock_evm
            .expect_get_balance()
            .returning(|_, _| Ok(U256::MAX));

        // empty bundle
        mock_proposer
            .expect_make_bundle()
            .times(1)
            .returning(|_, _, _| Box::pin(async { Ok(Bundle::<UserOperation>::default()) }));

        let mut sender = new_sender(mock_proposer, mock_entry_point, mock_evm, MockPool::new());

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
            mut mock_evm,
        } = new_mocks();

        // block 0
        add_trigger_no_update_last_block(&mut mock_trigger, &mut Sequence::new(), 0);

        // zero nonce
        mock_tracker
            .expect_get_nonce_and_required_fees()
            .returning(|| Ok((0, None)));
        mock_tracker.expect_address().return_const(Address::ZERO);

        mock_evm
            .expect_get_balance()
            .returning(|_, _| Ok(U256::MAX));

        // bundle with one op
        mock_proposer
            .expect_make_bundle()
            .times(1)
            .returning(|_, _, _| Box::pin(async { Ok(bundle()) }));

        // should create the bundle txn
        mock_entry_point
            .expect_get_send_bundle_transaction()
            .returning(|_, _, _, _, _| TransactionRequest::default());

        // should send the bundle txn
        mock_tracker
            .expect_send_transaction()
            .returning(|_, _, _| Box::pin(async { Ok(B256::ZERO) }));

        let mut sender = new_sender(mock_proposer, mock_entry_point, mock_evm, MockPool::new());

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
            mock_evm,
        } = new_mocks();

        let mut seq = Sequence::new();
        add_trigger_wait_for_block_last_block(&mut mock_trigger, &mut seq, 1);

        let new_head = NewHead {
            block_number: 2,
            block_hash: B256::ZERO,
            address_updates: vec![AddressUpdate {
                address: Address::ZERO,
                nonce: 0,
                balance: U256::ZERO,
                mined_tx_hashes: vec![B256::ZERO],
            }],
        };
        let new_head_clone = new_head.clone();

        mock_trigger
            .expect_wait_for_block()
            .once()
            .in_sequence(&mut seq)
            .returning(move || {
                Box::pin({
                    let new_head = new_head_clone.clone();
                    async move { Ok(new_head) }
                })
            });
        mock_trigger
            .expect_last_block()
            .once()
            .in_sequence(&mut seq)
            .return_const(new_head);

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

        let mut sender = new_sender(mock_proposer, mock_entry_point, mock_evm, MockPool::new());

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
            last_idle_block: None,
            balance: None,
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
            mock_tracker,
            mut mock_trigger,
            mock_evm,
        } = new_mocks();

        let mut seq = Sequence::new();
        for i in 1..=3 {
            add_trigger_wait_for_block_last_block(&mut mock_trigger, &mut seq, i);
        }

        let mut sender = new_sender(mock_proposer, mock_entry_point, mock_evm, MockPool::new());

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
            last_idle_block: None,
            balance: None,
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
            mut mock_evm,
        } = new_mocks();

        let mut seq = Sequence::new();
        add_trigger_no_update_last_block(&mut mock_trigger, &mut seq, 3);

        // zero nonce
        mock_tracker
            .expect_get_nonce_and_required_fees()
            .returning(|| Ok((0, None)));
        mock_tracker.expect_address().return_const(Address::ZERO);

        mock_evm
            .expect_get_balance()
            .returning(|_, _| Ok(U256::MAX));

        // fee filter error
        mock_proposer
            .expect_make_bundle()
            .times(1)
            .returning(|_, _, _| {
                Box::pin(async { Err(BundleProposerError::NoOperationsAfterFeeFilter) })
            });

        let mut sender = new_sender(mock_proposer, mock_entry_point, mock_evm, MockPool::new());

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
            last_idle_block: None,
            balance: None,
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
            mock_evm,
        } = new_mocks();

        mock_proposer
            .expect_estimate_gas_fees()
            .once()
            .returning(|_| Box::pin(async { Ok((GasFees::default(), 0)) }));

        mock_tracker
            .expect_cancel_transaction()
            .once()
            .returning(|_| Box::pin(async { Ok(Some(B256::ZERO)) }));

        mock_trigger.expect_last_block().return_const(NewHead {
            block_number: 0,
            block_hash: B256::ZERO,
            address_updates: vec![],
        });

        let mut state = SenderMachineState {
            trigger: mock_trigger,
            transaction_tracker: mock_tracker,
            send_bundle_response: None,
            inner: InnerState::Cancelling(CancellingState {
                fee_increase_count: 0,
            }),
            requires_reset: false,
            last_idle_block: None,
            balance: None,
        };

        let mut sender = new_sender(mock_proposer, mock_entry_point, mock_evm, MockPool::new());

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
            mock_tracker,
            mut mock_trigger,
            mock_evm,
        } = new_mocks();

        let mut seq = Sequence::new();
        for i in 1..=3 {
            add_trigger_wait_for_block_last_block(&mut mock_trigger, &mut seq, i);
        }

        let mut state = SenderMachineState {
            trigger: mock_trigger,
            transaction_tracker: mock_tracker,
            send_bundle_response: None,
            inner: InnerState::CancelPending(CancelPendingState {
                until: 3,
                fee_increase_count: 0,
            }),
            requires_reset: false,
            last_idle_block: None,
            balance: None,
        };

        let mut sender = new_sender(mock_proposer, mock_entry_point, mock_evm, MockPool::new());

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
            mut mock_evm,
        } = new_mocks();

        let mut seq = Sequence::new();
        add_trigger_no_update_last_block(&mut mock_trigger, &mut seq, 1);

        // zero nonce
        mock_tracker
            .expect_get_nonce_and_required_fees()
            .returning(|| Ok((0, None)));
        mock_tracker.expect_address().return_const(Address::ZERO);

        // bundle with one op
        mock_proposer
            .expect_make_bundle()
            .times(1)
            .returning(|_, _, _| Box::pin(async { Ok(bundle()) }));

        // should get balance of sender
        mock_evm
            .expect_get_balance()
            .returning(|_, _| Ok(U256::MAX));

        // should create the bundle txn
        mock_entry_point
            .expect_get_send_bundle_transaction()
            .returning(|_, _, _, _, _| TransactionRequest::default());

        // should send the bundle txn, returns condition not met
        mock_tracker
            .expect_send_transaction()
            .returning(|_, _, _| Box::pin(async { Err(TransactionTrackerError::ConditionNotMet) }));

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
            last_idle_block: None,
            balance: None,
        };

        let mut sender = new_sender(mock_proposer, mock_entry_point, mock_evm, MockPool::new());

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

    #[tokio::test]
    async fn test_revert_remove() {
        let Mocks {
            mock_proposer,
            mock_entry_point,
            mut mock_tracker,
            mut mock_trigger,
            mut mock_evm,
        } = new_mocks();

        let mut seq = Sequence::new();
        add_trigger_wait_for_block_last_block(&mut mock_trigger, &mut seq, 1);

        let new_head = NewHead {
            block_number: 2,
            block_hash: B256::ZERO,
            address_updates: vec![AddressUpdate {
                address: Address::ZERO,
                nonce: 0,
                balance: U256::ZERO,
                mined_tx_hashes: vec![B256::ZERO],
            }],
        };
        let new_head_clone = new_head.clone();

        mock_trigger
            .expect_wait_for_block()
            .once()
            .in_sequence(&mut seq)
            .returning(move || {
                Box::pin({
                    let new_head = new_head_clone.clone();
                    async move { Ok(new_head) }
                })
            });
        mock_trigger
            .expect_last_block()
            .once()
            .in_sequence(&mut seq)
            .return_const(new_head);

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

        let input = bytes!("1234");
        let input_clone = input.clone();
        let output = bytes!("5678");
        let output_clone = output.clone();
        let op = UserOperation::default();
        let op_hash = op.hash();

        mock_evm
            .expect_debug_trace_transaction()
            .returning(move |_, _| {
                Ok(GethDebugTracerCallFrame {
                    input: input.clone(),
                    output: Some(output.clone()),
                    ..Default::default()
                }
                .into())
            });

        let ctx = MockEntryPointV0_6::decode_ops_from_calldata_context();
        ctx.expect()
            .withf(move |_, data| *data == input_clone)
            .returning(move |_, _| {
                vec![UserOpsPerAggregator {
                    user_ops: vec![op.clone()],
                    ..Default::default()
                }]
            });

        let ctx = MockEntryPointV0_6::decode_handle_ops_revert_context();
        ctx.expect()
            .withf(move |_, data| *data == Some(output_clone.clone()))
            .returning(|_, _| Some(HandleOpsOut::FailedOp(0, "revert".to_string())));

        let mut mock_pool = MockPool::new();
        mock_pool
            .expect_remove_ops()
            .once()
            .withf(move |_, hashes| hashes.len() == 1 && hashes[0] == op_hash)
            .returning(|_, _| Ok(()));

        let mut sender = new_sender(mock_proposer, mock_entry_point, mock_evm, mock_pool);

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
            last_idle_block: None,
            balance: None,
        };

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
        mock_proposer: MockBundleProposer,
        mock_entry_point: MockEntryPointV0_6,
        mock_tracker: MockTransactionTracker,
        mock_trigger: MockTrigger,
        mock_evm: MockEvmProvider,
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
            mock_evm: MockEvmProvider::new(),
        }
    }

    #[allow(clippy::type_complexity)]
    fn new_sender(
        mock_proposer: MockBundleProposer,
        mock_entry_point: MockEntryPointV0_6,
        mock_evm: MockEvmProvider,
        mock_pool: MockPool,
    ) -> BundleSenderImpl<
        MockBundleProposer,
        ProvidersWithEntryPoint<
            UserOperation,
            Arc<MockEvmProvider>,
            Arc<MockEntryPointV0_6>,
            Arc<MockDAGasOracleSync>,
        >,
        MockTransactionTracker,
        MockPool,
    > {
        BundleSenderImpl::new(
            "any:0".to_string(),
            mpsc::channel(1000).1,
            ChainSpec::default(),
            Address::default(),
            None,
            mock_proposer,
            ProvidersWithEntryPoint::new(Arc::new(mock_evm), Arc::new(mock_entry_point), None),
            MockTransactionTracker::new(),
            mock_pool,
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
        mock_trigger.expect_last_block().return_const(NewHead {
            block_number,
            block_hash: B256::ZERO,
            address_updates: vec![],
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
                        address_updates: vec![],
                    })
                })
            });

        // this gets called twice after a trigger
        for _ in 0..2 {
            mock_trigger
                .expect_last_block()
                .once()
                .in_sequence(seq)
                .return_const(NewHead {
                    block_number,
                    block_hash: B256::ZERO,
                    address_updates: vec![],
                });
        }

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
