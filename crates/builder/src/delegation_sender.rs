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

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
};

use alloy_network::TransactionBuilder7702;
use alloy_primitives::B256;
use anyhow::Context;
use rundler_provider::{EvmProvider, FeeEstimator, TransactionRequest};
use rundler_signer::SignerManager;
use rundler_task::GracefulShutdown;
use rundler_types::{
    GasFees,
    authorization::Eip7702Auth,
    builder::{BuilderError, BuilderResult, DelegationId, DelegationStatus},
    pool::NewHead,
};
use tokio::sync::{broadcast, mpsc, oneshot};
use tracing::{info, warn};

/// EIP-4337 intrinsic gas for a type-4 transaction.
const DELEGATION_BASE_GAS: u64 = 21_000;
/// Per-authorization gas cost (EIP-7702).
const DELEGATION_GAS_PER_AUTH: u64 = 25_000;
/// Extra buffer added on top of the calculated cost.
const DELEGATION_GAS_BUFFER: u64 = 50_000;

/// Number of blocks to retain mined delegation records before pruning.
const MINED_RETENTION_BLOCKS: u64 = 100;

fn delegation_gas_limit(n_auths: usize) -> u64 {
    DELEGATION_BASE_GAS + n_auths as u64 * DELEGATION_GAS_PER_AUTH + DELEGATION_GAS_BUFFER
}

/// Settings for the delegation sender.
#[derive(Debug, Clone)]
pub(crate) struct Settings {
    /// Number of blocks to wait before considering a tx stuck and bumping fees.
    pub max_blocks_to_wait_for_mine: u64,
    /// Maximum number of fee bumps before giving up entirely.
    pub max_fee_bumps: u64,
    /// Percentage to increase fees on each bump (e.g. 10 = 10 %).
    pub fee_bump_percent: u32,
    /// Maximum gas per delegation tx — used to cap the number of auths per batch.
    pub max_delegation_gas: u64,
}

/// Actions that can be sent to the delegation sender task.
pub(crate) enum DelegationSenderAction {
    /// Submit a new delegation. The responder receives the [`DelegationId`] immediately;
    /// use [`DelegationSenderAction::GetStatus`] to poll for the mined tx hash.
    Send {
        auth: Eip7702Auth,
        responder: oneshot::Sender<DelegationId>,
    },
    /// Query the current status of a previously submitted delegation.
    GetStatus {
        id: DelegationId,
        responder: oneshot::Sender<DelegationStatus>,
    },
}

/// Handle to the long-running delegation sender task.
///
/// Cheap to clone; all methods communicate through an internal channel.
#[derive(Clone)]
pub struct DelegationSenderHandle {
    action_tx: mpsc::Sender<DelegationSenderAction>,
}

impl DelegationSenderHandle {
    pub(crate) async fn send_delegation(&self, auth: Eip7702Auth) -> BuilderResult<DelegationId> {
        let (tx, rx) = oneshot::channel();
        self.action_tx
            .send(DelegationSenderAction::Send {
                auth,
                responder: tx,
            })
            .await
            .map_err(|_| anyhow::anyhow!("delegation sender task closed"))?;
        rx.await
            .map_err(|_| BuilderError::Other(anyhow::anyhow!("delegation sender task closed")))
    }

    pub(crate) async fn get_delegation_status(
        &self,
        id: DelegationId,
    ) -> BuilderResult<DelegationStatus> {
        let (tx, rx) = oneshot::channel();
        self.action_tx
            .send(DelegationSenderAction::GetStatus { id, responder: tx })
            .await
            .map_err(|_| anyhow::anyhow!("delegation sender task closed"))?;
        rx.await
            .map_err(|_| BuilderError::Other(anyhow::anyhow!("delegation sender task closed")))
    }
}

/// Internal completion event sent from a per-batch sub-task back to the main loop.
struct CompletionEvent {
    ids: Vec<DelegationId>,
    result: anyhow::Result<B256>,
}

/// Long-running task that owns delegation state and processes requests.
///
/// Mirrors the `BundleSender` pattern: callers communicate through a channel
/// ([`DelegationSenderHandle`]) and this task serialises state updates, so no
/// shared-memory locks are needed.
///
/// Incoming delegations are buffered in a queue. On each new block (and
/// immediately on receipt) the task attempts to drain the queue by acquiring
/// a free signer and spawning a [`DelegationSenderCore`] for each batch of up
/// to [`MAX_BATCH_SIZE`] authorizations.  Multiple authorizations are packed
/// into a single type-4 transaction, reducing signer contention and cutting
/// the per-delegation tx-overhead when the system is under load.
pub(crate) struct DelegationSenderTask<E, F> {
    action_rx: mpsc::Receiver<DelegationSenderAction>,
    completion_tx: mpsc::Sender<CompletionEvent>,
    completion_rx: mpsc::Receiver<CompletionEvent>,
    /// Incoming delegations waiting for a free signer.
    queue: VecDeque<(DelegationId, Eip7702Auth)>,
    /// Delegations that have been submitted and are waiting to mine.
    pending: HashSet<DelegationId>,
    /// Delegations that have mined, with their (tx_hash, block_number).
    /// Entries are pruned after MINED_RETENTION_BLOCKS.
    mined: HashMap<DelegationId, (B256, u64)>,
    current_block: u64,
    /// Shared broadcast sender — used to subscribe a fresh receiver for each delegation sub-task.
    heads_tx: broadcast::Sender<Arc<NewHead>>,
    // Core sender dependencies
    signer_manager: Arc<dyn SignerManager>,
    provider: E,
    fee_estimator: F,
    settings: Settings,
}

impl<E, F> DelegationSenderTask<E, F>
where
    E: EvmProvider + Clone + Send + Sync + 'static,
    F: FeeEstimator + Clone + Send + Sync + 'static,
{
    /// Create the task and its associated handle.
    pub(crate) fn new(
        signer_manager: Arc<dyn SignerManager>,
        provider: E,
        fee_estimator: F,
        settings: Settings,
        heads_tx: broadcast::Sender<Arc<NewHead>>,
    ) -> (Self, DelegationSenderHandle) {
        let (action_tx, action_rx) = mpsc::channel(1024);
        let (completion_tx, completion_rx) = mpsc::channel(1024);
        let task = Self {
            action_rx,
            completion_tx,
            completion_rx,
            queue: VecDeque::new(),
            pending: HashSet::new(),
            mined: HashMap::new(),
            current_block: 0,
            heads_tx,
            signer_manager,
            provider,
            fee_estimator,
            settings,
        };
        let handle = DelegationSenderHandle { action_tx };
        (task, handle)
    }

    /// Drain as many queued delegations as possible, one signer per batch.
    ///
    /// Each call to `lease_signer` is non-blocking; if no signer is free the
    /// loop stops and the remaining entries stay in the queue for the next
    /// drain attempt (on the next block or the next `Send` action).
    fn try_drain_queue(&mut self) {
        while !self.queue.is_empty() {
            let Some(signer) = self.signer_manager.lease_signer() else {
                break;
            };

            let max_auths = ((self
                .settings
                .max_delegation_gas
                .saturating_sub(DELEGATION_BASE_GAS)
                .saturating_sub(DELEGATION_GAS_BUFFER))
                / DELEGATION_GAS_PER_AUTH) as usize;
            let batch_size = self.queue.len().min(max_auths.max(1));
            let batch: Vec<(DelegationId, Eip7702Auth)> = self.queue.drain(..batch_size).collect();
            let ids: Vec<DelegationId> = batch.iter().map(|(id, _)| id.clone()).collect();
            let auths: Vec<Eip7702Auth> = batch.into_iter().map(|(_, auth)| auth).collect();

            tracing::debug!(
                "delegation sender: draining batch of {} (queue remaining: {})",
                ids.len(),
                self.queue.len(),
            );

            let core = DelegationSenderCore {
                signer_manager: self.signer_manager.clone(),
                provider: self.provider.clone(),
                fee_estimator: self.fee_estimator.clone(),
                settings: self.settings.clone(),
            };
            let heads_rx = self.heads_tx.subscribe();
            let completion_tx = self.completion_tx.clone();
            tokio::spawn(async move {
                let result = core.send(signer, auths, heads_rx).await;
                let _ = completion_tx.send(CompletionEvent { ids, result }).await;
            });
        }
    }

    /// Run the delegation sender task until shutdown.
    pub(crate) async fn run(mut self, shutdown: GracefulShutdown) {
        let mut heads_rx = self.heads_tx.subscribe();

        loop {
            tokio::select! {
                _ = shutdown.clone() => return,

                head = heads_rx.recv() => {
                    match head {
                        Ok(h) => {
                            self.current_block = h.block_number;
                            tracing::debug!("delegation sender: new block {}", h.block_number);
                            let cutoff = self.current_block.saturating_sub(MINED_RETENTION_BLOCKS);
                            self.mined.retain(|_, (_, mined_block)| *mined_block >= cutoff);
                            self.try_drain_queue();
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!("delegation sender heads receiver lagged by {n} blocks");
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            tracing::error!("heads broadcast closed in delegation sender task");
                            return;
                        }
                    }
                }

                Some(event) = self.completion_rx.recv() => {
                    for id in &event.ids {
                        self.pending.remove(id);
                    }
                    if let Ok(tx_hash) = event.result {
                        for id in event.ids {
                            self.mined.insert(id, (tx_hash, self.current_block));
                        }
                    }
                }

                Some(action) = self.action_rx.recv() => {
                    match action {
                        DelegationSenderAction::Send { auth, responder } => {
                            let id = DelegationId::from_auth(&auth);
                            self.pending.insert(id.clone());
                            let _ = responder.send(id.clone());
                            self.queue.push_back((id, auth));
                            self.try_drain_queue();
                        }

                        DelegationSenderAction::GetStatus { id, responder } => {
                            let status = if self.pending.contains(&id) {
                                DelegationStatus::Pending
                            } else if let Some(&(tx_hash, _)) = self.mined.get(&id) {
                                DelegationStatus::Mined { tx_hash }
                            } else {
                                DelegationStatus::Unknown
                            };
                            let _ = responder.send(status);
                        }
                    }
                }
            }
        }
    }
}

/// Core send logic: submits a batch of delegations as a single type-4 tx and
/// waits for it to mine, with fee-bump retries.
struct DelegationSenderCore<E, F> {
    signer_manager: Arc<dyn SignerManager>,
    provider: E,
    fee_estimator: F,
    settings: Settings,
}

impl<E, F> DelegationSenderCore<E, F>
where
    E: EvmProvider,
    F: FeeEstimator,
{
    async fn send(
        &self,
        signer: rundler_signer::SignerLease,
        auths: Vec<Eip7702Auth>,
        heads_rx: broadcast::Receiver<Arc<NewHead>>,
    ) -> anyhow::Result<B256> {
        let result = self.run(&signer, auths, heads_rx).await;
        self.signer_manager.return_lease(signer);
        result
    }

    async fn run(
        &self,
        signer: &rundler_signer::SignerLease,
        auths: Vec<Eip7702Auth>,
        mut heads_rx: broadcast::Receiver<Arc<NewHead>>,
    ) -> anyhow::Result<B256> {
        // Nonce the tx will use. Held constant across fee-bump retries so each
        // replacement supersedes the previous pending tx rather than queuing behind it.
        let nonce = self
            .provider
            .get_transaction_count(signer.address())
            .await
            .context("failed to get signer nonce")?;

        let (initial_fees, _) = self
            .fee_estimator
            .latest_bundle_fees()
            .await
            .context("failed to get bundle fees")?;

        let mut current_fees = initial_fees;

        for attempt in 0..=self.settings.max_fee_bumps {
            if attempt > 0 {
                current_fees = current_fees.increase_by_percent(self.settings.fee_bump_percent);
                info!(
                    "bumping delegation fees (attempt {attempt}): \
                     max_fee={}, priority_fee={}",
                    current_fees.max_fee_per_gas, current_fees.max_priority_fee_per_gas,
                );
            }

            let tx_hash = self.submit_tx(signer, &auths, nonce, current_fees).await?;
            info!(
                "delegation batch of {} submitted (attempt {attempt}): {tx_hash}",
                auths.len(),
            );

            // `until_block` is set lazily on the first head event so the timeout
            // is relative to the block that arrives after submission rather than
            // requiring an extra RPC call.
            let mut until_block: Option<u64> = None;

            let timed_out = loop {
                let head = match heads_rx.recv().await {
                    Ok(h) => h,
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("delegation sender heads receiver lagged by {n} blocks");
                        // We may have missed the mining event. Check the receipt
                        // before continuing to wait.
                        if self.receipt_exists(tx_hash).await {
                            info!("delegation batch {tx_hash} confirmed (after lag)");
                            return Ok(tx_hash);
                        }
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        anyhow::bail!("new-heads broadcast channel closed unexpectedly");
                    }
                };

                let block_number = head.block_number;
                let until = *until_block
                    .get_or_insert(block_number + self.settings.max_blocks_to_wait_for_mine);

                if let Some(update) = head
                    .address_updates
                    .iter()
                    .find(|u| u.address == signer.address())
                {
                    // Happy path: pool reported our tx hash in this block's update.
                    if update.mined_tx_hashes.contains(&tx_hash) {
                        info!("delegation batch {tx_hash} mined at block {block_number}");
                        return Ok(tx_hash);
                    }

                    // A tx at or above our nonce mined but it wasn't ours according
                    // to this block's update. Two possibilities:
                    //   1. We lagged earlier and our tx mined in a previous block.
                    //   2. Another tx consumed our nonce (replacement or external).
                    // Fetch the receipt to disambiguate before bailing.
                    if update.nonce.is_some_and(|n| n >= nonce) {
                        if self.receipt_exists(tx_hash).await {
                            info!("delegation batch {tx_hash} confirmed (via receipt)");
                            return Ok(tx_hash);
                        }
                        anyhow::bail!(
                            "signer nonce {nonce} was consumed by another transaction \
                             while awaiting delegation batch"
                        );
                    }
                }

                if block_number >= until {
                    break true;
                }
            };

            if timed_out {
                warn!(
                    "delegation batch {tx_hash} not mined after {} blocks (attempt {attempt})",
                    self.settings.max_blocks_to_wait_for_mine,
                );
                // One last receipt check: the tx may have mined in the window
                // just before the timeout fired without triggering an update.
                if self.receipt_exists(tx_hash).await {
                    info!("delegation batch {tx_hash} confirmed (receipt at timeout)");
                    return Ok(tx_hash);
                }
            }
        }

        anyhow::bail!(
            "delegation batch not mined after {} fee bump attempts",
            self.settings.max_fee_bumps,
        )
    }

    async fn submit_tx(
        &self,
        signer: &rundler_signer::SignerLease,
        auths: &[Eip7702Auth],
        nonce: u64,
        fees: GasFees,
    ) -> anyhow::Result<B256> {
        // Send to the bundler's own signer address to avoid executing any fallback
        // code the EOA may have acquired from the delegation.
        let tx = TransactionRequest::default()
            .to(signer.address())
            .nonce(nonce)
            .gas_limit(delegation_gas_limit(auths.len()))
            .max_fee_per_gas(fees.max_fee_per_gas)
            .max_priority_fee_per_gas(fees.max_priority_fee_per_gas)
            .with_authorization_list(auths.iter().map(|a| a.clone().into()).collect());

        let raw_tx = signer
            .sign_tx_raw(tx)
            .await
            .context("failed to sign delegation transaction")?;

        self.provider
            .send_raw_transaction(raw_tx)
            .await
            .context("failed to submit delegation transaction")
    }

    /// Returns `true` if a transaction receipt exists for `tx_hash`.
    async fn receipt_exists(&self, tx_hash: B256) -> bool {
        matches!(
            self.provider.get_transaction_receipt(tx_hash).await,
            Ok(Some(_))
        )
    }
}
