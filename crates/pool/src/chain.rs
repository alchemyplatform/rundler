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
    result::Result::Ok,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use alloy_network_primitives::TransactionResponse;
use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::SolEvent;
use anyhow::{bail, ensure, Context};
use futures::future;
use itertools::Itertools;
use metrics::{Counter, Gauge, Histogram};
use metrics_derive::Metrics;
use parking_lot::RwLock;
use rundler_contracts::{
    v0_6::IEntryPoint::{
        Deposited as DepositedV06, UserOperationEvent as UserOperationEventV06,
        Withdrawn as WithdrawnV06,
    },
    v0_7::IEntryPoint::{
        Deposited as DepositedV07, UserOperationEvent as UserOperationEventV07,
        Withdrawn as WithdrawnV07,
    },
};
use rundler_provider::{Block, BlockId, EvmProvider, Filter, Log, TransactionTrait};
use rundler_task::{block_watcher, GracefulShutdown};
use rundler_types::{pool::AddressUpdate, EntryPointVersion, Timestamp, UserOperationId};
use tokio::{
    select,
    sync::{broadcast, Semaphore},
    time,
};
use tracing::{info, instrument, warn};

const MAX_LOAD_OPS_CONCURRENCY: usize = 64;
const SYNC_ERROR_COUNT_MAX: usize = 50;

/// A data structure that holds the currently known recent state of the chain,
/// with logic for updating itself and returning what has changed.
///
/// Will update itself when `.sync_to_block_number` is called, at which point it
/// will query a node to determine the new state of the chain.
#[derive(Debug)]
pub(crate) struct Chain<P: EvmProvider> {
    provider: P,
    settings: Settings,
    /// Blocks are stored from earliest to latest, so the oldest block is at the
    /// front of this deque and the newest at the back.
    blocks: VecDeque<BlockSummary>,

    /// Pending block summary, for preconfirmation blocks.
    pending_block: Option<BlockSummary>,
    /// Semaphore to limit the number of concurrent `eth_getLogs` calls.
    load_ops_semaphore: Semaphore,
    sync_error_count: usize,
    /// Filter template.
    filter_template: Filter,
    /// Metrics of chain events.
    metrics: ChainMetrics,

    sender: Arc<broadcast::Sender<Arc<ChainUpdate>>>,
    to_track: Arc<RwLock<HashSet<Address>>>,
}

#[derive(Clone)]
pub(crate) struct ChainSubscriber {
    pub(crate) sender: Arc<broadcast::Sender<Arc<ChainUpdate>>>,
    pub(crate) to_track: Arc<RwLock<HashSet<Address>>>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub(crate) enum UpdateType {
    // Include at least one full block
    #[default]
    Confirmed,
    // only include pending block
    Preconfirmed,
}

#[derive(Default, Debug, Eq, PartialEq)]
pub(crate) struct ChainUpdate {
    pub latest_block_number: u64,
    pub latest_block_hash: B256,
    pub latest_block_timestamp: Timestamp,
    /// Blocks before this number are no longer tracked in this `Chain`, so no
    /// further updates related to them will be sent.
    pub earliest_remembered_block_number: u64,
    pub reorg_depth: u64,
    pub mined_ops: Vec<MinedOp>,
    pub unmined_ops: Vec<MinedOp>,
    pub preconfirmed_txns: Vec<(B256, Vec<B256>)>,
    pub preconfirmed_block_number: Option<u64>,
    /// List of on-chain entity balance updates made in the most recent block
    pub entity_balance_updates: Vec<BalanceUpdate>,
    /// List of entity balance updates that have been unmined due to a reorg
    pub unmined_entity_balance_updates: Vec<BalanceUpdate>,
    /// List of address updates
    pub address_updates: Vec<AddressUpdate>,
    /// Boolean to state if the most recent chain update had a reorg
    /// that was larger than the existing history that has been tracked
    pub reorg_larger_than_history: bool,
    pub update_type: UpdateType,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MinedOp {
    pub hash: B256,
    pub entry_point: Address,
    pub sender: Address,
    pub nonce: U256,
    pub actual_gas_cost: U256,
    pub paymaster: Option<Address>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BalanceUpdate {
    pub address: Address,
    pub entrypoint: Address,
    pub amount: U256,
    pub is_addition: bool,
}

impl MinedOp {
    pub(crate) fn id(&self) -> UserOperationId {
        UserOperationId {
            sender: self.sender,
            nonce: self.nonce,
        }
    }
}

#[derive(Debug)]
pub(crate) struct Settings {
    pub(crate) history_size: u64,
    pub(crate) poll_interval: Duration,
    pub(crate) entry_point_addresses: HashMap<Address, EntryPointVersion>,
    pub(crate) max_sync_retries: u64,
    pub(crate) channel_capacity: usize,
    pub(crate) flashblocks: bool,
}

#[derive(Debug)]
struct BlockSummary {
    number: u64,
    hash: B256,
    timestamp: Timestamp,
    ops: Vec<MinedOp>,
    transactions: Vec<(B256, Vec<B256>)>,
    entity_balance_updates: Vec<BalanceUpdate>,
    address_updates: Vec<AddressUpdate>,
}

impl ChainSubscriber {
    pub(crate) fn subscribe(&self) -> broadcast::Receiver<Arc<ChainUpdate>> {
        self.sender.subscribe()
    }

    pub(crate) fn track_addresses(&self, address: Vec<Address>) {
        self.to_track.write().extend(address);
    }
}

impl<P: EvmProvider> Chain<P> {
    pub(crate) fn new(provider: P, settings: Settings) -> Self {
        let history_size = settings.history_size as usize;
        assert!(history_size > 0, "history size should be positive");

        let mut events = vec![];

        if settings
            .entry_point_addresses
            .values()
            .any(|v| *v == EntryPointVersion::V0_6)
        {
            events.push(UserOperationEventV06::SIGNATURE_HASH);
            events.push(DepositedV06::SIGNATURE_HASH);
            events.push(WithdrawnV06::SIGNATURE_HASH);
        }
        if settings
            .entry_point_addresses
            .values()
            .any(|v| *v == EntryPointVersion::V0_7)
        {
            events.push(UserOperationEventV07::SIGNATURE_HASH);
            events.push(DepositedV07::SIGNATURE_HASH);
            events.push(WithdrawnV07::SIGNATURE_HASH);
        }

        let filter_template = Filter::new()
            .address(
                settings
                    .entry_point_addresses
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>(),
            )
            .event_signature(events);

        let (update_sender, _) = broadcast::channel(settings.channel_capacity);
        let to_track = Arc::new(RwLock::new(HashSet::new()));

        Self {
            provider,
            settings,
            blocks: VecDeque::new(),
            pending_block: None,
            sync_error_count: 0,
            load_ops_semaphore: Semaphore::new(MAX_LOAD_OPS_CONCURRENCY),
            filter_template,
            metrics: ChainMetrics::default(),
            sender: Arc::new(update_sender),
            to_track,
        }
    }

    pub(crate) fn subscriber(&self) -> ChainSubscriber {
        ChainSubscriber {
            sender: self.sender.clone(),
            to_track: self.to_track.clone(),
        }
    }

    pub(crate) async fn watch(mut self, shutdown: GracefulShutdown) {
        loop {
            select! {
                update = self.wait_for_update() => {
                    let _ = self.sender.send(Arc::new(update));
                }
                _ = shutdown.clone() => {
                    info!("Shutting down chain watcher");
                    break;
                }
            }
        }
    }

    #[instrument(skip_all)]
    async fn wait_for_update(&mut self) -> ChainUpdate {
        if self.settings.flashblocks && !self.blocks.is_empty() {
            self.wait_for_update_flashblocks().await
        } else {
            self.wait_for_update_full_block().await
        }
    }

    #[instrument(skip_all)]
    async fn wait_for_update_flashblocks(&mut self) -> ChainUpdate {
        let full_block_hash = self.blocks.back().map(|m| m.hash).unwrap_or_default();

        loop {
            // TODO: parallelize the two block watcher calls. one for pending block and one for latest block.
            let pending_block_fut = block_watcher::wait_for_new_block(
                &self.provider,
                B256::ZERO,
                self.settings.poll_interval,
                BlockId::pending(),
            );
            let latest_block_fut = block_watcher::wait_for_new_block(
                &self.provider,
                // force it always get the latest block hash.
                B256::ZERO,
                self.settings.poll_interval,
                BlockId::latest(),
            );
            let (pending_block_res, latest_block_res) =
                future::join(pending_block_fut, latest_block_fut).await;
            let (_, pending_block) = pending_block_res;
            let (latest_block_hash, latest_block) = latest_block_res;

            let summary = match self.load_flash_block_summary(&pending_block).await {
                Ok(summary) => summary,
                Err(err) => {
                    warn!("failed to load block summary: {err:?}");
                    continue;
                }
            };
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis();
            let block_timestamp_ms = (pending_block.header.timestamp * 1000) as u128;

            let chain_update = self
                .process_pending_block(&summary, pending_block.header.number)
                .await;
            let header = &pending_block.inner.header;
            if let Some(pending_block) = &self.pending_block {
                if pending_block.hash == header.hash && latest_block_hash == full_block_hash {
                    continue; // same block
                }
            }
            self.metrics
                .flashblock_discovery_delay_ms
                .record(now_ms.saturating_sub(block_timestamp_ms) as f64);

            self.pending_block = Some(summary);
            // this means the latest block is the same as the full block, so we can return the chain update.
            if latest_block_hash == full_block_hash {
                return chain_update;
            }

            let preconfirmed_txns = chain_update.preconfirmed_txns;
            let preconfirmed_block_number = chain_update.preconfirmed_block_number;

            for attempt in 0..=self.settings.max_sync_retries {
                if attempt > 0 {
                    self.metrics.sync_retries.increment(1);
                }

                let start = Instant::now();

                let result = self.sync_to_block(latest_block.clone()).await;

                match result {
                    Ok(mut update) => {
                        self.metrics
                            .block_sync_time_ms
                            .record(start.elapsed().as_millis() as f64);
                        update.preconfirmed_txns = preconfirmed_txns;
                        update.preconfirmed_block_number = preconfirmed_block_number;
                        return update;
                    }
                    Err(error) => {
                        warn!("Failed to update chain at block {latest_block_hash:?}: {error:?}");
                    }
                }

                time::sleep(self.settings.poll_interval).await;
            }

            warn!(
                "Failed to update chain at block {:?} after {} retries. Abandoning sync and resetting history.",
                latest_block_hash, self.settings.max_sync_retries
            );
            self.metrics.sync_abandoned.increment(1);
            self.blocks.clear();
        }
    }

    #[instrument(skip_all)]
    async fn wait_for_update_full_block(&mut self) -> ChainUpdate {
        let full_block_hash = self.blocks.back().map(|m| m.hash).unwrap_or_default();
        let mut latest_block_hash = full_block_hash;

        loop {
            let (hash, block) = block_watcher::wait_for_new_block(
                &self.provider,
                latest_block_hash,
                self.settings.poll_interval,
                BlockId::latest(),
            )
            .await;
            latest_block_hash = hash;

            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis();
            let block_timestamp_ms = (block.header.timestamp * 1000) as u128;
            self.metrics
                .block_discovery_delay_ms
                .record(now_ms.saturating_sub(block_timestamp_ms) as f64);

            for attempt in 0..=self.settings.max_sync_retries {
                if attempt > 0 {
                    self.metrics.sync_retries.increment(1);
                }

                let start = Instant::now();
                let result = self.sync_to_block(block.clone()).await;

                match result {
                    Ok(update) => {
                        self.metrics
                            .block_sync_time_ms
                            .record(start.elapsed().as_millis() as f64);
                        return update;
                    }
                    Err(error) => {
                        warn!("Failed to update chain at block {latest_block_hash:?}: {error:?}");
                    }
                }

                time::sleep(self.settings.poll_interval).await;
            }

            warn!(
                "Failed to update chain at block {:?} after {} retries. Abandoning sync and resetting history.",
                latest_block_hash, self.settings.max_sync_retries
            );
            self.metrics.sync_abandoned.increment(1);
            self.blocks.clear();
        }
    }

    #[instrument(skip_all)]
    // get all 4337 txns
    async fn get_user_operations_from_pending_block(&self, pending_block: &Block) -> Vec<B256> {
        pending_block
            .transactions
            .txns()
            .filter(|tx| match tx.inner.to() {
                Some(tx_inner) => self
                    .settings
                    .entry_point_addresses
                    .keys()
                    .contains(&tx_inner),
                None => false,
            })
            .map(|tx| tx.inner.tx_hash())
            .collect()
    }

    #[instrument(skip_all)]
    async fn get_user_operation_hash_from_txn(&self, txn: B256) -> Option<(B256, Vec<B256>)> {
        let receipt = self.provider.get_transaction_receipt(txn).await;
        let receipt = receipt.ok()??;

        let logs = receipt
            .inner
            .inner
            .logs()
            .iter()
            .filter(|l| {
                self.settings
                    .entry_point_addresses
                    .keys()
                    .contains(&l.address())
                    && l.topics().len() >= 2
                    && (l.topics()[0] == UserOperationEventV06::SIGNATURE_HASH
                        || l.topics()[0] == UserOperationEventV07::SIGNATURE_HASH)
            })
            .map(|l| l.topics()[1])
            .collect::<Vec<_>>();

        Some((txn, logs))
    }
    #[instrument(skip_all)]
    pub(crate) async fn process_pending_block(
        &mut self,
        pending_block: &BlockSummary,
        preconfirmed_block_number: u64,
    ) -> ChainUpdate {
        self.new_pending_update(
            pending_block.transactions.to_vec(),
            preconfirmed_block_number,
        )
    }

    #[instrument(skip_all)]
    pub(crate) async fn sync_to_block(&mut self, new_head: Block) -> anyhow::Result<ChainUpdate> {
        let Some(current_block) = self.blocks.back() else {
            return self.reset_and_initialize(new_head).await;
        };
        let current_block_number = current_block.number;
        let new_block_number = new_head.header.number;

        if current_block_number > new_block_number + self.settings.history_size {
            self.sync_error_count += 1;

            if self.sync_error_count >= SYNC_ERROR_COUNT_MAX {
                return self.reset_and_initialize(new_head).await;
            }

            bail!(
            "new block number {new_block_number} should be greater than start of history (current block: {current_block_number})"
            )
        }

        if current_block_number + self.settings.history_size < new_block_number {
            warn!(
                "New block {new_block_number} number is {} blocks ahead of the previously known head. Chain history will skip ahead.",
                new_block_number - current_block_number,
            );
            return self.reset_and_initialize(new_head).await;
        }

        let added_blocks = self
            .load_added_blocks_connecting_to_existing_chain(current_block_number, new_head)
            .await?;
        Ok(self.update_with_blocks(current_block_number, added_blocks))
    }

    async fn reset_and_initialize(&mut self, head: Block) -> anyhow::Result<ChainUpdate> {
        let min_block_number = head
            .header
            .number
            .saturating_sub(self.settings.history_size - 1);
        let blocks = self
            .load_blocks_back_to_number(head, min_block_number)
            .await
            .context("should load full history when resetting chain")?;
        self.blocks = self.load_block_summaries(&blocks).await?;
        self.sync_error_count = 0;
        let mined_ops: Vec<_> = self
            .blocks
            .iter()
            .flat_map(|block| &block.ops)
            .copied()
            .collect();

        let entity_balance_updates: Vec<_> = self
            .blocks
            .iter()
            .flat_map(|block| &block.entity_balance_updates)
            .copied()
            .collect();

        Ok(self.new_update(
            0,
            mined_ops,
            vec![],
            vec![],
            None,
            entity_balance_updates,
            vec![],
            vec![],
            false,
            UpdateType::Confirmed,
        ))
    }

    /// Given a collection of blocks to add to the chain, whose numbers may
    /// overlap the current numbers in the case of reorgs, update the state of
    /// this data structure and return an update struct.
    fn update_with_blocks(
        &mut self,
        current_block_number: u64,
        added_blocks: VecDeque<BlockSummary>,
    ) -> ChainUpdate {
        let mined_ops: Vec<_> = added_blocks
            .iter()
            .flat_map(|block| &block.ops)
            .copied()
            .collect();

        let entity_balance_updates: Vec<_> = added_blocks
            .iter()
            .flat_map(|block| &block.entity_balance_updates)
            .copied()
            .collect();

        // Only concern with mined address updates using the balance from
        // the highest nonce.
        let mut address_updates = HashMap::new();
        added_blocks
            .iter()
            .flat_map(|block| &block.address_updates)
            .for_each(|update| {
                let latest_update =
                    address_updates
                        .entry(&update.address)
                        .or_insert(AddressUpdate {
                            address: update.address,
                            nonce: update.nonce,
                            balance: update.balance,
                            mined_tx_hashes: vec![],
                        });
                if update.nonce > latest_update.nonce {
                    latest_update.nonce = update.nonce;
                    latest_update.balance = update.balance;
                }
                latest_update
                    .mined_tx_hashes
                    .extend(update.mined_tx_hashes.iter());
            });
        let address_updates = address_updates.into_values().collect();

        let reorg_depth = current_block_number + 1 - added_blocks[0].number;
        let unmined_ops: Vec<_> = self
            .blocks
            .iter()
            .skip(self.blocks.len() - reorg_depth as usize)
            .flat_map(|block| &block.ops)
            .copied()
            .collect();

        let unmined_entity_balance_updates: Vec<_> = self
            .blocks
            .iter()
            .skip(self.blocks.len() - reorg_depth as usize)
            .flat_map(|block| &block.entity_balance_updates)
            .copied()
            .collect();

        let is_reorg_larger_than_history = reorg_depth >= self.settings.history_size;

        for _ in 0..reorg_depth {
            self.blocks.pop_back();
        }
        self.blocks.extend(added_blocks);
        while self.blocks.len() > self.settings.history_size as usize {
            self.blocks.pop_front();
        }

        self.metrics.block_height.set(current_block_number as f64);
        if reorg_depth > 0 {
            self.metrics.reorgs_detected.increment(1);
            self.metrics.total_reorg_depth.increment(reorg_depth);
        }

        self.new_update(
            reorg_depth,
            mined_ops,
            unmined_ops,
            vec![],
            None,
            entity_balance_updates,
            unmined_entity_balance_updates,
            address_updates,
            is_reorg_larger_than_history,
            UpdateType::Confirmed,
        )
    }

    #[instrument(skip_all)]
    async fn load_added_blocks_connecting_to_existing_chain(
        &self,
        current_block_number: u64,
        new_head: Block,
    ) -> anyhow::Result<VecDeque<BlockSummary>> {
        // Load blocks from last known number to current.
        let mut added_blocks = self
            .load_blocks_back_to_number(new_head, current_block_number + 1)
            .await
            .context("chain should load blocks from last processed to latest block")?;
        ensure!(
            !added_blocks.is_empty(),
            "added blocks should never be empty"
        );
        // Continue to load blocks backwards until we connect with the known chain, if necessary.
        loop {
            let earliest_new_block = &added_blocks[0];
            if earliest_new_block.header.number == 0 {
                break;
            }
            let Some(presumed_parent) =
                self.block_with_number(earliest_new_block.header.number - 1)
            else {
                warn!(
                    "Reorg is deeper than chain history size ({})",
                    self.blocks.len()
                );
                break;
            };
            if presumed_parent.hash == earliest_new_block.header.parent_hash {
                break;
            }
            // The earliest newly loaded block's parent does not match the known
            // chain, so continue to load blocks backwards, replacing the known
            // chain, until it does.
            let block = self
                .provider
                .get_full_block(earliest_new_block.header.parent_hash.into())
                .await
                .context("should load parent block when handling reorg")?
                .context("block with parent hash of known block should exist")?;

            if block.header.number != earliest_new_block.header.number - 1 {
                bail!(
                    "block number {} does not match expected block number {}",
                    block.header.number,
                    earliest_new_block.header.number - 1
                );
            }

            added_blocks.push_front(block);
        }
        self.load_block_summaries(&added_blocks).await
    }

    async fn fetch_block_with_retries(&self, block_hash: B256) -> Option<Block> {
        for attempt in 1..=self.settings.max_sync_retries {
            match self.provider.get_full_block(block_hash.into()).await {
                Ok(Some(block)) => return Some(block),
                Ok(None) => warn!(
                    "Block with hash {:?} not found. Retrying... (attempt {}/{})",
                    block_hash, attempt, self.settings.max_sync_retries
                ),
                Err(err) => warn!(
                    "Error fetching block with hash {:?}: {}. Retrying... (attempt {}/{})",
                    block_hash, err, attempt, self.settings.max_sync_retries
                ),
            }
            time::sleep(self.settings.poll_interval).await;
        }

        warn!(
            "Failed to fetch block with hash {:?} after {} attempts.",
            block_hash, self.settings.max_sync_retries
        );
        None
    }

    #[instrument(skip_all)]
    async fn load_blocks_back_to_number(
        &self,
        head: Block,
        min_block_number: u64,
    ) -> anyhow::Result<VecDeque<Block>> {
        let mut blocks = VecDeque::with_capacity(
            head.header.number.saturating_sub(min_block_number) as usize + 1,
        );
        blocks.push_front(head);
        while blocks[0].header.number > min_block_number {
            let parent_hash = blocks[0].header.parent_hash;
            let parent = self.fetch_block_with_retries(parent_hash).await;

            if let Some(parent) = parent {
                if parent.header.number != blocks[0].header.number - 1 {
                    bail!(
                        "block number {} does not match expected block number {}",
                        parent.header.number,
                        blocks[0].header.number - 1
                    );
                }
                blocks.push_front(parent);
            } else {
                bail!(
                    "Unable to backtrack chain history beyond block number {} due to missing parent block.",
                    blocks[0].header.number
                );
            }
        }
        Ok(blocks)
    }

    #[instrument(skip_all)]
    async fn load_block_summaries(
        &self,
        blocks: &VecDeque<Block>,
    ) -> anyhow::Result<VecDeque<BlockSummary>> {
        // As when loading blocks, load op events block-by-block, specifying
        // block hash. Don't load with a single call by block number range
        // because if the network is in the middle of a reorg, then we can't
        // tell which branch we read events from.
        future::try_join_all(blocks.iter().map(|block| self.load_block_summary(block)))
            .await
            .context("should load ops for new blocks")
            .map(VecDeque::from)
    }

    #[instrument(skip_all)]
    // flash block doesn't support eth_getLogs, so we need to load the block summary manually.
    async fn load_flash_block_summary(&self, block: &Block) -> anyhow::Result<BlockSummary> {
        let _permit = self
            .load_ops_semaphore
            .acquire()
            .await
            .expect("semaphore should not be closed");

        let txn_to_uos_fut = self
            .get_user_operations_from_pending_block(block)
            .await
            .iter()
            .map(|txn| self.get_user_operation_hash_from_txn(*txn))
            .collect::<Vec<_>>();

        let txn_to_uos = future::join_all(txn_to_uos_fut)
            .await
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        Ok(BlockSummary {
            number: block.header.number,
            hash: block.header.hash,
            timestamp: block.header.timestamp.into(),
            ops: vec![],
            transactions: txn_to_uos,
            entity_balance_updates: vec![],
            address_updates: vec![],
        })
    }

    #[instrument(skip_all)]
    async fn load_block_summary(&self, block: &Block) -> anyhow::Result<BlockSummary> {
        let _permit = self
            .load_ops_semaphore
            .acquire()
            .await
            .expect("semaphore should not be closed");

        let ((ops, entity_balance_updates), address_updates) = future::try_join(
            self.load_events_in_block(block),
            self.load_address_updates(block),
        )
        .await?;

        Ok(BlockSummary {
            number: block.header.number,
            hash: block.header.hash,
            timestamp: block.header.timestamp.into(),
            ops,
            transactions: vec![],
            entity_balance_updates,
            address_updates,
        })
    }

    async fn load_address_updates(&self, block: &Block) -> anyhow::Result<Vec<AddressUpdate>> {
        let mut updates: HashMap<Address, AddressUpdate> =
            HashMap::from_iter(self.to_track.read().iter().map(|a| {
                (
                    *a,
                    AddressUpdate {
                        address: *a,
                        nonce: None,
                        balance: U256::ZERO,
                        mined_tx_hashes: vec![],
                    },
                )
            }));

        for tx in block.transactions.txns() {
            if self.to_track.read().contains(&tx.from()) {
                let nonce = tx.nonce();
                let update = updates.get_mut(&tx.from()).unwrap();
                if nonce >= update.nonce.unwrap_or(0) {
                    update.nonce = Some(nonce);
                }
                update.mined_tx_hashes.push(tx.inner.tx_hash());
            }
        }

        let balances = self
            .provider
            .get_balances(updates.keys().cloned().collect())
            .await
            .context("should load balances")?;

        ensure!(
            updates.len() == balances.len(),
            "tracked addresses and balances should have the same length"
        );

        for (address, balance) in balances {
            updates.get_mut(&address).unwrap().balance = balance;
        }

        Ok(updates.into_values().collect())
    }

    async fn load_events_in_block(
        &self,
        block: &Block,
    ) -> anyhow::Result<(Vec<MinedOp>, Vec<BalanceUpdate>)> {
        let filter = self
            .filter_template
            .clone()
            .at_block_hash(block.header.hash);
        let logs = self
            .provider
            .get_logs(&filter)
            .await
            .context("chain state should load user operation events")?;

        let mut mined_ops = vec![];
        let mut entity_balance_updates = vec![];
        for log in logs {
            match self.settings.entry_point_addresses.get(&log.address()) {
                Some(EntryPointVersion::V0_6) => {
                    Self::load_v0_6(log, &mut mined_ops, &mut entity_balance_updates)
                }
                Some(EntryPointVersion::V0_7) => {
                    Self::load_v0_7(log, &mut mined_ops, &mut entity_balance_updates)
                }
                Some(EntryPointVersion::Unspecified) | None => {
                    warn!(
                        "Log with unknown entry point address: {:?}. Ignoring.",
                        log.address()
                    );
                }
            }
        }
        Ok((mined_ops, entity_balance_updates))
    }

    fn load_v0_6(log: Log, mined_ops: &mut Vec<MinedOp>, balance_updates: &mut Vec<BalanceUpdate>) {
        let address = log.address();

        match log.topic0() {
            Some(&UserOperationEventV06::SIGNATURE_HASH) => {
                let Ok(decoded) = log.log_decode::<UserOperationEventV06>() else {
                    warn!("Failed to decode v0.6 UserOperationEvent: {:?}", log);
                    return;
                };
                let event = decoded.data();

                let paymaster = if event.paymaster.is_zero() {
                    None
                } else {
                    Some(event.paymaster)
                };
                let mined = MinedOp {
                    hash: event.userOpHash,
                    entry_point: address,
                    sender: event.sender,
                    nonce: event.nonce,
                    actual_gas_cost: event.actualGasCost,
                    paymaster,
                };
                mined_ops.push(mined);
            }
            Some(&DepositedV06::SIGNATURE_HASH) => {
                let Ok(decoded) = log.log_decode::<DepositedV06>() else {
                    warn!("Failed to decode v0.6 Deposited: {:?}", log);
                    return;
                };
                let event = decoded.data();

                let info = BalanceUpdate {
                    entrypoint: address,
                    address: event.account,
                    amount: event.totalDeposit,
                    is_addition: true,
                };
                balance_updates.push(info);
            }
            Some(&WithdrawnV06::SIGNATURE_HASH) => {
                let Ok(decoded) = log.log_decode::<WithdrawnV06>() else {
                    warn!("Failed to decode v0.6 Withdrawn: {:?}", log);
                    return;
                };
                let event = decoded.data();

                let info = BalanceUpdate {
                    entrypoint: address,
                    address: event.account,
                    amount: event.amount,
                    is_addition: false,
                };
                balance_updates.push(info);
            }
            _ => {
                warn!("Unknown event signature: {:?}", log.topic0());
            }
        }
    }

    fn load_v0_7(log: Log, mined_ops: &mut Vec<MinedOp>, balance_updates: &mut Vec<BalanceUpdate>) {
        let address = log.address();

        match log.topic0() {
            Some(&UserOperationEventV07::SIGNATURE_HASH) => {
                let Ok(decoded) = log.log_decode::<UserOperationEventV07>() else {
                    warn!("Failed to decode v0.7 UserOperationEvent: {:?}", log);
                    return;
                };
                let event = decoded.data();

                let paymaster = if event.paymaster.is_zero() {
                    None
                } else {
                    Some(event.paymaster)
                };
                let mined = MinedOp {
                    hash: event.userOpHash,
                    entry_point: address,
                    sender: event.sender,
                    nonce: event.nonce,
                    actual_gas_cost: event.actualGasCost,
                    paymaster,
                };
                mined_ops.push(mined);
            }
            Some(&DepositedV07::SIGNATURE_HASH) => {
                let Ok(decoded) = log.log_decode::<DepositedV07>() else {
                    warn!("Failed to decode v0.7 Deposited: {:?}", log);
                    return;
                };
                let event = decoded.data();

                let info = BalanceUpdate {
                    entrypoint: address,
                    address: event.account,
                    amount: event.totalDeposit,
                    is_addition: true,
                };
                balance_updates.push(info);
            }
            Some(&WithdrawnV07::SIGNATURE_HASH) => {
                let Ok(decoded) = log.log_decode::<WithdrawnV07>() else {
                    warn!("Failed to decode v0.7 Withdrawn: {:?}", log);
                    return;
                };
                let event = decoded.data();

                let info = BalanceUpdate {
                    entrypoint: address,
                    address: event.account,
                    amount: event.amount,
                    is_addition: false,
                };
                balance_updates.push(info);
            }
            _ => {
                warn!("Unknown event signature: {:?}", log.topic0());
            }
        }
    }

    fn block_with_number(&self, number: u64) -> Option<&BlockSummary> {
        let earliest_number = self.blocks.front()?.number;
        if number < earliest_number {
            return None;
        }
        self.blocks.get((number - earliest_number) as usize)
    }

    fn new_pending_update(
        &self,
        preconfirmed_txns: Vec<(B256, Vec<B256>)>,
        preconfirmed_block_number: u64,
    ) -> ChainUpdate {
        ChainUpdate {
            preconfirmed_txns,
            update_type: UpdateType::Preconfirmed,
            preconfirmed_block_number: Some(preconfirmed_block_number),
            ..Default::default()
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn new_update(
        &self,
        reorg_depth: u64,
        mined_ops: Vec<MinedOp>,
        unmined_ops: Vec<MinedOp>,
        preconfirmed_txns: Vec<(B256, Vec<B256>)>,
        preconfirmed_block_number: Option<u64>,
        entity_balance_updates: Vec<BalanceUpdate>,
        unmined_entity_balance_updates: Vec<BalanceUpdate>,
        address_updates: Vec<AddressUpdate>,
        reorg_larger_than_history: bool,
        update_type: UpdateType,
    ) -> ChainUpdate {
        let latest_block = self
            .blocks
            .back()
            .expect("new_update should not be called when blocks is empty");
        ChainUpdate {
            latest_block_number: latest_block.number,
            latest_block_hash: latest_block.hash,
            latest_block_timestamp: latest_block.timestamp,
            earliest_remembered_block_number: self.blocks[0].number,
            reorg_depth,
            mined_ops,
            preconfirmed_txns,
            preconfirmed_block_number,
            unmined_ops,
            entity_balance_updates,
            unmined_entity_balance_updates,
            address_updates,
            reorg_larger_than_history,
            update_type,
        }
    }
}

#[derive(Debug)]
pub(crate) struct DedupedOps {
    pub mined_ops: Vec<MinedOp>,
    pub unmined_ops: Vec<MinedOp>,
}

impl ChainUpdate {
    /// "Cancels out" ops that appear in both mined and unmined.
    pub(crate) fn deduped_ops(&self) -> DedupedOps {
        let mined_op_hashes: HashSet<_> = self.mined_ops.iter().map(|op| op.hash).collect();
        let unmined_op_hashes: HashSet<_> = self.unmined_ops.iter().map(|op| op.hash).collect();
        let mined_ops = self
            .mined_ops
            .iter()
            .filter(|op| !unmined_op_hashes.contains(&op.hash))
            .copied()
            .collect();
        let unmined_ops = self
            .unmined_ops
            .iter()
            .filter(|op| !mined_op_hashes.contains(&op.hash))
            .copied()
            .collect();
        DedupedOps {
            mined_ops,
            unmined_ops,
        }
    }
}

#[derive(Metrics)]
#[metrics(scope = "op_pool_chain")]
struct ChainMetrics {
    #[metric(describe = "the height of block.")]
    block_height: Gauge,
    #[metric(describe = "the count of reorg event detected.")]
    reorgs_detected: Counter,
    #[metric(describe = "the count of reorg depth.")]
    total_reorg_depth: Counter,
    #[metric(describe = "the count of sync retries.")]
    sync_retries: Counter,
    #[metric(describe = "the count of sync abanded.")]
    sync_abandoned: Counter,
    #[metric(describe = "the delay in milliseconds between block discovery and its timestamp")]
    block_discovery_delay_ms: Histogram,
    #[metric(describe = "the delay in milliseconds between flahblock discovery and its timestamp")]
    flashblock_discovery_delay_ms: Histogram,
    #[metric(describe = "the time in milliseconds it takes to sync to a block")]
    block_sync_time_ms: Histogram,
}

#[cfg(test)]
mod tests {
    use std::ops::DerefMut;

    use alloy_consensus::{transaction::Recovered, SignableTransaction, TypedTransaction};
    use alloy_eips::BlockNumberOrTag;
    use alloy_network_primitives::BlockTransactions;
    use alloy_primitives::{address, Log as PrimitiveLog, LogData, Signature};
    use alloy_rpc_types_eth::{Block as AlloyBlock, Transaction as AlloyTransaction};
    use alloy_serde::WithOtherFields;
    use parking_lot::RwLock;
    use rundler_provider::{
        AnyHeader, AnyTxEnvelope, BlockHeader, BlockId, FilterBlockOption, MockEvmProvider,
        RpcBlockHash, Transaction, TransactionRequest,
    };

    use super::*;

    const HISTORY_SIZE: u64 = 3;
    const ENTRY_POINT_ADDRESS_V0_6: Address = address!("0123456789012345678901234567890123456789");
    const ENTRY_POINT_ADDRESS_V0_7: Address = address!("9876543210987654321098765432109876543210");

    #[derive(Clone, Debug)]
    struct MockBlock {
        hash: B256,
        events: Vec<MockEntryPointEvents>,
        transactions: Vec<Transaction>,
    }

    #[derive(Clone, Debug, Default)]
    struct MockEntryPointEvents {
        address: Address,
        op_hashes: Vec<B256>,
        deposit_addresses: Vec<Address>,
        withdrawal_addresses: Vec<Address>,
    }

    impl MockBlock {
        fn new(hash: B256) -> Self {
            Self {
                hash,
                events: vec![],
                transactions: vec![],
            }
        }

        fn add_ep(
            mut self,
            address: Address,
            op_hashes: Vec<B256>,
            deposit_addresses: Vec<Address>,
            withdrawal_addresses: Vec<Address>,
        ) -> Self {
            self.events.push(MockEntryPointEvents {
                address,
                op_hashes,
                deposit_addresses,
                withdrawal_addresses,
            });
            self
        }

        fn add_txns(mut self, txns: Vec<Transaction>) -> Self {
            self.transactions.extend(txns);
            self
        }
    }

    #[derive(Clone, Debug)]
    struct ProviderController {
        blocks: Arc<RwLock<Vec<MockBlock>>>,
        pending_block: Arc<RwLock<Option<MockBlock>>>,
        balances: Arc<RwLock<HashMap<Address, U256>>>,
    }

    impl ProviderController {
        fn set_blocks(&self, blocks: Vec<MockBlock>) {
            *self.blocks.write() = blocks;
        }

        fn set_balances(&self, balances: HashMap<Address, U256>) {
            *self.balances.write() = balances;
        }

        fn get_balances(&self, addresses: Vec<Address>) -> Vec<(Address, U256)> {
            addresses
                .into_iter()
                .map(|addr| {
                    (
                        addr,
                        self.balances
                            .read()
                            .get(&addr)
                            .copied()
                            .unwrap_or(U256::ZERO),
                    )
                })
                .collect()
        }

        fn get_blocks_mut(&self) -> impl DerefMut<Target = Vec<MockBlock>> + '_ {
            self.blocks.write()
        }

        fn get_head(&self) -> Block {
            let hash = self.blocks.read().last().unwrap().hash;
            self.get_block(hash.into()).unwrap()
        }

        fn get_block(&self, id: BlockId) -> Option<Block> {
            match id {
                BlockId::Number(BlockNumberOrTag::Pending) => {
                    let pending_block = self.pending_block.read();
                    if pending_block.is_none() {
                        return None;
                    }
                    let pending_block_inner = pending_block.clone().unwrap();
                    let blocks = self.blocks.read();
                    let number = blocks.iter().len();

                    let parent_hash = if number > 0 {
                        blocks[number - 1].hash
                    } else {
                        B256::ZERO
                    };
                    Some(Block::new(WithOtherFields::new(AlloyBlock {
                        header: BlockHeader {
                            hash: pending_block_inner.hash,
                            inner: AnyHeader {
                                parent_hash,
                                number: number as u64,
                                ..Default::default()
                            },
                            ..Default::default()
                        },
                        transactions: BlockTransactions::Full(
                            pending_block_inner.transactions.clone(),
                        ),
                        ..Default::default()
                    })))
                }
                BlockId::Hash(RpcBlockHash {
                    block_hash: hash,
                    require_canonical: _,
                }) => {
                    let blocks = self.blocks.read();
                    let number = blocks.iter().position(|block| block.hash == hash)?;
                    let block = &blocks[number];
                    let parent_hash = if number > 0 {
                        blocks[number - 1].hash
                    } else {
                        B256::ZERO
                    };

                    Some(Block::new(WithOtherFields::new(AlloyBlock {
                        header: BlockHeader {
                            hash,
                            inner: AnyHeader {
                                parent_hash,
                                number: number as u64,
                                ..Default::default()
                            },
                            ..Default::default()
                        },
                        transactions: BlockTransactions::Full(block.transactions.clone()),
                        ..Default::default()
                    })))
                }
                _ => panic!("get_block only supports hash ids"),
            }
        }

        fn get_logs_by_block_hash(&self, filter: &Filter, block_hash: B256) -> Vec<Log> {
            let blocks = self.blocks.read();
            let pending_block = self.pending_block.read();
            let block = if let Some(ref pending) = *pending_block {
                if pending.hash == block_hash {
                    pending
                } else {
                    match blocks.iter().find(|block| block.hash == block_hash) {
                        Some(block) => block,
                        None => return vec![],
                    }
                }
            } else {
                match blocks.iter().find(|block| block.hash == block_hash) {
                    Some(block) => block,
                    None => return vec![],
                }
            };

            let mut joined_logs: Vec<Log> = Vec::new();

            for events in &block.events {
                if events.address == ENTRY_POINT_ADDRESS_V0_6 {
                    if filter.topics[0].matches(&UserOperationEventV06::SIGNATURE_HASH) {
                        joined_logs
                            .extend(events.op_hashes.iter().copied().map(fake_mined_log_v0_6));
                    }
                    if filter.topics[0].matches(&DepositedV06::SIGNATURE_HASH) {
                        joined_logs.extend(
                            events
                                .deposit_addresses
                                .iter()
                                .copied()
                                .map(fake_deposit_log_v0_6),
                        );
                    }
                    if filter.topics[0].matches(&WithdrawnV06::SIGNATURE_HASH) {
                        joined_logs.extend(
                            events
                                .withdrawal_addresses
                                .iter()
                                .copied()
                                .map(fake_withdrawal_log_v0_6),
                        );
                    }
                } else if events.address == ENTRY_POINT_ADDRESS_V0_7 {
                    if filter.topics[0].matches(&UserOperationEventV07::SIGNATURE_HASH) {
                        joined_logs
                            .extend(events.op_hashes.iter().copied().map(fake_mined_log_v0_7));
                    }
                    if filter.topics[0].matches(&DepositedV07::SIGNATURE_HASH) {
                        joined_logs.extend(
                            events
                                .deposit_addresses
                                .iter()
                                .copied()
                                .map(fake_deposit_log_v0_7),
                        );
                    }
                    if filter.topics[0].matches(&WithdrawnV07::SIGNATURE_HASH) {
                        joined_logs.extend(
                            events
                                .withdrawal_addresses
                                .iter()
                                .copied()
                                .map(fake_withdrawal_log_v0_7),
                        );
                    }
                } else {
                    panic!("Unknown entry point address: {:?}", events.address);
                }
            }

            joined_logs
        }
    }

    #[tokio::test]
    async fn test_initial_load() {
        let (mut chain, controller) = new_chain();
        controller.set_blocks(vec![
            MockBlock::new(hash(0)).add_ep(
                ENTRY_POINT_ADDRESS_V0_6,
                vec![hash(101), hash(102)],
                vec![],
                vec![],
            ),
            MockBlock::new(hash(1)).add_ep(
                ENTRY_POINT_ADDRESS_V0_6,
                vec![hash(103)],
                vec![],
                vec![],
            ),
            MockBlock::new(hash(2)).add_ep(ENTRY_POINT_ADDRESS_V0_6, vec![], vec![], vec![]),
            MockBlock::new(hash(3)).add_ep(
                ENTRY_POINT_ADDRESS_V0_6,
                vec![hash(104), hash(105)],
                vec![],
                vec![],
            ),
        ]);
        let update = chain.sync_to_block(controller.get_head()).await.unwrap();
        // With a history size of 3, we should get updates from all blocks except the first one.
        assert_eq!(
            update,
            ChainUpdate {
                latest_block_number: 3,
                latest_block_hash: hash(3),
                latest_block_timestamp: 0.into(),
                earliest_remembered_block_number: 1,
                reorg_depth: 0,
                mined_ops: vec![
                    fake_mined_op(103, ENTRY_POINT_ADDRESS_V0_6),
                    fake_mined_op(104, ENTRY_POINT_ADDRESS_V0_6),
                    fake_mined_op(105, ENTRY_POINT_ADDRESS_V0_6),
                ],
                unmined_ops: vec![],
                preconfirmed_txns: vec![],
                preconfirmed_block_number: None,
                entity_balance_updates: vec![],
                unmined_entity_balance_updates: vec![],
                address_updates: vec![],
                reorg_larger_than_history: false,
                update_type: UpdateType::Confirmed,
            }
        );
    }

    #[tokio::test]
    async fn test_simple_advance() {
        let (mut chain, controller) = new_chain();
        controller.set_blocks(vec![
            MockBlock::new(hash(0)).add_ep(
                ENTRY_POINT_ADDRESS_V0_6,
                vec![hash(101), hash(102)],
                vec![],
                vec![],
            ),
            MockBlock::new(hash(1)).add_ep(
                ENTRY_POINT_ADDRESS_V0_6,
                vec![hash(103)],
                vec![],
                vec![],
            ),
            MockBlock::new(hash(2)).add_ep(ENTRY_POINT_ADDRESS_V0_6, vec![], vec![], vec![]),
            MockBlock::new(hash(3)).add_ep(
                ENTRY_POINT_ADDRESS_V0_6,
                vec![hash(104), hash(105)],
                vec![],
                vec![],
            ),
        ]);
        chain.sync_to_block(controller.get_head()).await.unwrap();
        controller
            .get_blocks_mut()
            .push(MockBlock::new(hash(4)).add_ep(
                ENTRY_POINT_ADDRESS_V0_6,
                vec![hash(106)],
                vec![],
                vec![],
            ));
        let update = chain.sync_to_block(controller.get_head()).await.unwrap();
        assert_eq!(
            update,
            ChainUpdate {
                latest_block_number: 4,
                latest_block_hash: hash(4),
                latest_block_timestamp: 0.into(),
                earliest_remembered_block_number: 2,
                reorg_depth: 0,
                mined_ops: vec![fake_mined_op(106, ENTRY_POINT_ADDRESS_V0_6)],
                unmined_ops: vec![],
                preconfirmed_txns: vec![],
                entity_balance_updates: vec![],
                unmined_entity_balance_updates: vec![],
                address_updates: vec![],
                reorg_larger_than_history: false,
                preconfirmed_block_number: None,
                update_type: UpdateType::Confirmed,
            }
        );
    }

    #[tokio::test]
    async fn test_forward_reorg() {
        let (mut chain, controller) = new_chain();
        controller.set_blocks(vec![
            MockBlock::new(hash(0)).add_ep(
                ENTRY_POINT_ADDRESS_V0_6,
                vec![hash(100)],
                vec![],
                vec![],
            ),
            MockBlock::new(hash(1)).add_ep(
                ENTRY_POINT_ADDRESS_V0_6,
                vec![hash(101)],
                vec![],
                vec![],
            ),
            MockBlock::new(hash(2)).add_ep(
                ENTRY_POINT_ADDRESS_V0_6,
                vec![hash(102)],
                vec![Address::ZERO],
                vec![addr(1)],
            ),
        ]);
        chain.sync_to_block(controller.get_head()).await.unwrap();
        {
            // Replaces the head of the chain with three new blocks.
            let mut blocks = controller.get_blocks_mut();
            blocks.pop();
            blocks.extend([
                MockBlock::new(hash(12)).add_ep(
                    ENTRY_POINT_ADDRESS_V0_6,
                    vec![hash(112)],
                    vec![],
                    vec![],
                ),
                MockBlock::new(hash(13)).add_ep(
                    ENTRY_POINT_ADDRESS_V0_6,
                    vec![hash(113)],
                    vec![],
                    vec![],
                ),
                MockBlock::new(hash(14)).add_ep(
                    ENTRY_POINT_ADDRESS_V0_6,
                    vec![hash(114)],
                    vec![],
                    vec![addr(3)],
                ),
            ]);
        }
        let update = chain.sync_to_block(controller.get_head()).await.unwrap();
        assert_eq!(
            update,
            ChainUpdate {
                latest_block_number: 4,
                latest_block_hash: hash(14),
                latest_block_timestamp: 0.into(),
                earliest_remembered_block_number: 2,
                reorg_depth: 1,
                mined_ops: vec![
                    fake_mined_op(112, ENTRY_POINT_ADDRESS_V0_6),
                    fake_mined_op(113, ENTRY_POINT_ADDRESS_V0_6),
                    fake_mined_op(114, ENTRY_POINT_ADDRESS_V0_6)
                ],
                unmined_ops: vec![fake_mined_op(102, ENTRY_POINT_ADDRESS_V0_6)],
                preconfirmed_txns: vec![],
                preconfirmed_block_number: None,
                entity_balance_updates: vec![fake_mined_balance_update(
                    addr(3),
                    0,
                    false,
                    ENTRY_POINT_ADDRESS_V0_6
                )],
                unmined_entity_balance_updates: vec![
                    fake_mined_balance_update(addr(0), 0, true, ENTRY_POINT_ADDRESS_V0_6),
                    fake_mined_balance_update(addr(1), 0, false, ENTRY_POINT_ADDRESS_V0_6),
                ],
                address_updates: vec![],
                reorg_larger_than_history: false,
                update_type: UpdateType::Confirmed,
            }
        );
    }

    #[tokio::test]
    async fn test_sideways_reorg() {
        let (mut chain, controller) = new_chain();
        controller.set_blocks(vec![
            MockBlock::new(hash(0)).add_ep(
                ENTRY_POINT_ADDRESS_V0_6,
                vec![hash(100)],
                vec![],
                vec![],
            ),
            MockBlock::new(hash(1)).add_ep(
                ENTRY_POINT_ADDRESS_V0_6,
                vec![hash(101)],
                vec![addr(1)],
                vec![addr(9)],
            ),
            MockBlock::new(hash(2)).add_ep(
                ENTRY_POINT_ADDRESS_V0_6,
                vec![hash(102)],
                vec![],
                vec![],
            ),
        ]);
        chain.sync_to_block(controller.get_head()).await.unwrap();
        {
            // Replaces the top two blocks with two new ones.
            let mut blocks = controller.get_blocks_mut();
            blocks.pop();
            blocks.pop();
            blocks.extend([
                MockBlock::new(hash(11)).add_ep(
                    ENTRY_POINT_ADDRESS_V0_6,
                    vec![hash(111)],
                    vec![addr(2)],
                    vec![],
                ),
                MockBlock::new(hash(12)).add_ep(
                    ENTRY_POINT_ADDRESS_V0_6,
                    vec![hash(112)],
                    vec![],
                    vec![],
                ),
            ]);
        }
        let update = chain.sync_to_block(controller.get_head()).await.unwrap();
        assert_eq!(
            update,
            ChainUpdate {
                entity_balance_updates: vec![fake_mined_balance_update(
                    addr(2),
                    0,
                    true,
                    ENTRY_POINT_ADDRESS_V0_6
                )],
                latest_block_number: 2,
                latest_block_hash: hash(12),
                latest_block_timestamp: 0.into(),
                earliest_remembered_block_number: 0,
                reorg_depth: 2,
                mined_ops: vec![
                    fake_mined_op(111, ENTRY_POINT_ADDRESS_V0_6),
                    fake_mined_op(112, ENTRY_POINT_ADDRESS_V0_6)
                ],
                unmined_ops: vec![
                    fake_mined_op(101, ENTRY_POINT_ADDRESS_V0_6),
                    fake_mined_op(102, ENTRY_POINT_ADDRESS_V0_6)
                ],
                preconfirmed_txns: vec![],
                preconfirmed_block_number: None,
                unmined_entity_balance_updates: vec![
                    fake_mined_balance_update(addr(1), 0, true, ENTRY_POINT_ADDRESS_V0_6),
                    fake_mined_balance_update(addr(9), 0, false, ENTRY_POINT_ADDRESS_V0_6),
                ],
                address_updates: vec![],
                reorg_larger_than_history: false,
                update_type: UpdateType::Confirmed,
            }
        );
    }

    #[tokio::test]
    async fn test_backwards_reorg() {
        let (mut chain, controller) = new_chain();
        controller.set_blocks(vec![
            MockBlock::new(hash(0)).add_ep(
                ENTRY_POINT_ADDRESS_V0_6,
                vec![hash(100)],
                vec![],
                vec![],
            ),
            MockBlock::new(hash(1)).add_ep(
                ENTRY_POINT_ADDRESS_V0_6,
                vec![hash(101)],
                vec![],
                vec![],
            ),
            MockBlock::new(hash(2)).add_ep(
                ENTRY_POINT_ADDRESS_V0_6,
                vec![hash(102)],
                vec![],
                vec![],
            ),
        ]);
        chain.sync_to_block(controller.get_head()).await.unwrap();
        {
            // Replaces the top two blocks with just one new one.
            let mut blocks = controller.get_blocks_mut();
            blocks.pop();
            blocks.pop();
            blocks.push(MockBlock::new(hash(11)).add_ep(
                ENTRY_POINT_ADDRESS_V0_6,
                vec![hash(111)],
                vec![addr(1)],
                vec![],
            ));
        }
        let update = chain.sync_to_block(controller.get_head()).await.unwrap();
        assert_eq!(
            update,
            ChainUpdate {
                latest_block_number: 1,
                entity_balance_updates: vec![fake_mined_balance_update(
                    addr(1),
                    0,
                    true,
                    ENTRY_POINT_ADDRESS_V0_6
                )],
                latest_block_hash: hash(11),
                latest_block_timestamp: 0.into(),
                earliest_remembered_block_number: 0,
                reorg_depth: 2,
                mined_ops: vec![fake_mined_op(111, ENTRY_POINT_ADDRESS_V0_6)],
                unmined_ops: vec![
                    fake_mined_op(101, ENTRY_POINT_ADDRESS_V0_6),
                    fake_mined_op(102, ENTRY_POINT_ADDRESS_V0_6)
                ],
                preconfirmed_txns: vec![],
                preconfirmed_block_number: None,
                unmined_entity_balance_updates: vec![],
                address_updates: vec![],
                reorg_larger_than_history: false,
                update_type: UpdateType::Confirmed,
            }
        );
    }

    #[tokio::test]
    async fn test_reorg_longer_than_history() {
        let (mut chain, controller) = new_chain();
        controller.set_blocks(vec![
            MockBlock::new(hash(0)).add_ep(
                ENTRY_POINT_ADDRESS_V0_6,
                vec![hash(100)],
                vec![],
                vec![],
            ),
            MockBlock::new(hash(1)).add_ep(
                ENTRY_POINT_ADDRESS_V0_6,
                vec![hash(101)],
                vec![],
                vec![],
            ),
            MockBlock::new(hash(2)).add_ep(
                ENTRY_POINT_ADDRESS_V0_6,
                vec![hash(102)],
                vec![],
                vec![],
            ),
            MockBlock::new(hash(3)).add_ep(
                ENTRY_POINT_ADDRESS_V0_6,
                vec![hash(103)],
                vec![],
                vec![],
            ),
        ]);
        chain.sync_to_block(controller.get_head()).await.unwrap();
        // The history has size 3, so after this update it's completely unrecognizable.
        controller.set_blocks(vec![
            MockBlock::new(hash(0)).add_ep(
                ENTRY_POINT_ADDRESS_V0_6,
                vec![hash(100)],
                vec![],
                vec![],
            ),
            MockBlock::new(hash(11)).add_ep(
                ENTRY_POINT_ADDRESS_V0_6,
                vec![hash(111)],
                vec![],
                vec![],
            ),
            MockBlock::new(hash(12)).add_ep(
                ENTRY_POINT_ADDRESS_V0_6,
                vec![hash(112)],
                vec![],
                vec![],
            ),
            MockBlock::new(hash(13)).add_ep(
                ENTRY_POINT_ADDRESS_V0_6,
                vec![hash(113)],
                vec![],
                vec![],
            ),
        ]);
        let update = chain.sync_to_block(controller.get_head()).await.unwrap();
        assert_eq!(
            update,
            ChainUpdate {
                latest_block_number: 3,
                latest_block_hash: hash(13),
                latest_block_timestamp: 0.into(),
                earliest_remembered_block_number: 1,
                reorg_depth: 3,
                mined_ops: vec![
                    fake_mined_op(111, ENTRY_POINT_ADDRESS_V0_6),
                    fake_mined_op(112, ENTRY_POINT_ADDRESS_V0_6),
                    fake_mined_op(113, ENTRY_POINT_ADDRESS_V0_6)
                ],
                unmined_ops: vec![
                    fake_mined_op(101, ENTRY_POINT_ADDRESS_V0_6),
                    fake_mined_op(102, ENTRY_POINT_ADDRESS_V0_6),
                    fake_mined_op(103, ENTRY_POINT_ADDRESS_V0_6)
                ],
                preconfirmed_txns: vec![],
                preconfirmed_block_number: None,
                entity_balance_updates: vec![],
                unmined_entity_balance_updates: vec![],
                address_updates: vec![],
                reorg_larger_than_history: true,
                update_type: UpdateType::Confirmed,
            }
        );
    }

    #[tokio::test]
    async fn test_advance_larger_than_history_size() {
        let (mut chain, controller) = new_chain();
        controller.set_blocks(vec![
            MockBlock::new(hash(0)).add_ep(
                ENTRY_POINT_ADDRESS_V0_6,
                vec![hash(100)],
                vec![],
                vec![],
            ),
            MockBlock::new(hash(1)).add_ep(
                ENTRY_POINT_ADDRESS_V0_6,
                vec![hash(101)],
                vec![],
                vec![],
            ),
            MockBlock::new(hash(2)).add_ep(
                ENTRY_POINT_ADDRESS_V0_6,
                vec![hash(102)],
                vec![],
                vec![],
            ),
        ]);
        chain.sync_to_block(controller.get_head()).await.unwrap();
        {
            let mut blocks = controller.get_blocks_mut();
            for i in 3..7 {
                blocks.push(MockBlock::new(hash(10 + i)).add_ep(
                    ENTRY_POINT_ADDRESS_V0_6,
                    vec![hash(100 + i)],
                    vec![],
                    vec![],
                ));
            }
        }
        let update = chain.sync_to_block(controller.get_head()).await.unwrap();
        assert_eq!(
            update,
            ChainUpdate {
                latest_block_number: 6,
                latest_block_hash: hash(16),
                latest_block_timestamp: 0.into(),
                earliest_remembered_block_number: 4,
                reorg_depth: 0,
                entity_balance_updates: vec![],
                unmined_entity_balance_updates: vec![],
                mined_ops: vec![
                    fake_mined_op(104, ENTRY_POINT_ADDRESS_V0_6),
                    fake_mined_op(105, ENTRY_POINT_ADDRESS_V0_6),
                    fake_mined_op(106, ENTRY_POINT_ADDRESS_V0_6)
                ],
                unmined_ops: vec![],
                preconfirmed_txns: vec![],
                preconfirmed_block_number: None,
                address_updates: vec![],
                reorg_larger_than_history: false,
                update_type: UpdateType::Confirmed,
            }
        );
    }

    /// This test probably only matters for running against a local chain.
    #[tokio::test]
    async fn test_latest_block_number_smaller_than_history_size() {
        let (mut chain, controller) = new_chain();
        let blocks = vec![
            MockBlock::new(hash(0)).add_ep(
                ENTRY_POINT_ADDRESS_V0_6,
                vec![hash(101), hash(102)],
                vec![],
                vec![],
            ),
            MockBlock::new(hash(1)).add_ep(
                ENTRY_POINT_ADDRESS_V0_6,
                vec![hash(103)],
                vec![],
                vec![],
            ),
        ];
        controller.set_blocks(blocks);
        let update = chain.sync_to_block(controller.get_head()).await.unwrap();
        assert_eq!(
            update,
            ChainUpdate {
                latest_block_number: 1,
                latest_block_hash: hash(1),
                latest_block_timestamp: 0.into(),
                earliest_remembered_block_number: 0,
                reorg_depth: 0,
                mined_ops: vec![
                    fake_mined_op(101, ENTRY_POINT_ADDRESS_V0_6),
                    fake_mined_op(102, ENTRY_POINT_ADDRESS_V0_6),
                    fake_mined_op(103, ENTRY_POINT_ADDRESS_V0_6),
                ],
                unmined_ops: vec![],
                preconfirmed_txns: vec![],
                preconfirmed_block_number: None,
                entity_balance_updates: vec![],
                unmined_entity_balance_updates: vec![],
                address_updates: vec![],
                reorg_larger_than_history: false,
                update_type: UpdateType::Confirmed,
            }
        );
    }

    #[tokio::test]
    async fn test_mixed_event_types() {
        let (mut chain, controller) = new_chain();
        controller.set_blocks(vec![MockBlock::new(hash(0))
            .add_ep(
                ENTRY_POINT_ADDRESS_V0_6,
                vec![hash(101), hash(102)],
                vec![addr(1), addr(2)],
                vec![addr(3), addr(4)],
            )
            .add_ep(
                ENTRY_POINT_ADDRESS_V0_7,
                vec![hash(201), hash(202)],
                vec![addr(5), addr(6)],
                vec![addr(7), addr(8)],
            )]);
        let update = chain.sync_to_block(controller.get_head()).await.unwrap();
        assert_eq!(
            update,
            ChainUpdate {
                latest_block_number: 0,
                latest_block_hash: hash(0),
                latest_block_timestamp: 0.into(),
                earliest_remembered_block_number: 0,
                reorg_depth: 0,
                mined_ops: vec![
                    fake_mined_op(101, ENTRY_POINT_ADDRESS_V0_6),
                    fake_mined_op(102, ENTRY_POINT_ADDRESS_V0_6),
                    fake_mined_op(201, ENTRY_POINT_ADDRESS_V0_7),
                    fake_mined_op(202, ENTRY_POINT_ADDRESS_V0_7),
                ],
                unmined_ops: vec![],
                preconfirmed_txns: vec![],
                preconfirmed_block_number: None,
                entity_balance_updates: vec![
                    fake_mined_balance_update(addr(1), 0, true, ENTRY_POINT_ADDRESS_V0_6),
                    fake_mined_balance_update(addr(2), 0, true, ENTRY_POINT_ADDRESS_V0_6),
                    fake_mined_balance_update(addr(3), 0, false, ENTRY_POINT_ADDRESS_V0_6),
                    fake_mined_balance_update(addr(4), 0, false, ENTRY_POINT_ADDRESS_V0_6),
                    fake_mined_balance_update(addr(5), 0, true, ENTRY_POINT_ADDRESS_V0_7),
                    fake_mined_balance_update(addr(6), 0, true, ENTRY_POINT_ADDRESS_V0_7),
                    fake_mined_balance_update(addr(7), 0, false, ENTRY_POINT_ADDRESS_V0_7),
                    fake_mined_balance_update(addr(8), 0, false, ENTRY_POINT_ADDRESS_V0_7),
                ],
                unmined_entity_balance_updates: vec![],
                address_updates: vec![],
                reorg_larger_than_history: false,
                update_type: UpdateType::Confirmed,
            }
        );
    }

    #[tokio::test]
    async fn test_address_update() {
        let (mut chain, controller) = new_chain();
        chain.to_track.write().insert(addr(0));
        chain.blocks.push_back(BlockSummary {
            number: 0,
            hash: B256::ZERO,
            timestamp: 0.into(),
            ops: vec![],
            transactions: vec![],
            entity_balance_updates: vec![],
            address_updates: vec![],
        });

        let txns = vec![make_transaction(addr(0), 0)];
        let tx_hashes = vec![txns[0].tx_hash()];

        controller.set_blocks(vec![MockBlock::new(hash(0)).add_txns(txns)]);
        controller.set_balances(HashMap::from([(addr(0), U256::from(100))]));

        let update = chain.sync_to_block(controller.get_head()).await.unwrap();
        assert_eq!(
            update,
            ChainUpdate {
                latest_block_number: 0,
                latest_block_hash: hash(0),
                latest_block_timestamp: 0.into(),
                earliest_remembered_block_number: 0,
                reorg_depth: 1,
                mined_ops: vec![],
                unmined_ops: vec![],
                preconfirmed_txns: vec![],
                preconfirmed_block_number: None,
                entity_balance_updates: vec![],
                unmined_entity_balance_updates: vec![],
                address_updates: vec![AddressUpdate {
                    address: addr(0),
                    nonce: Some(0),
                    balance: U256::from(100),
                    mined_tx_hashes: tx_hashes,
                }],
                reorg_larger_than_history: false,
                update_type: UpdateType::Confirmed,
            }
        )
    }

    #[tokio::test]
    async fn test_address_update_multiple_blocks() {
        let (mut chain, controller) = new_chain();
        chain.to_track.write().insert(addr(0));
        chain.blocks.push_back(BlockSummary {
            number: 0,
            hash: B256::ZERO,
            timestamp: 0.into(),
            ops: vec![],
            transactions: vec![],
            entity_balance_updates: vec![],
            address_updates: vec![],
        });

        let txns0 = vec![make_transaction(addr(0), 0)];
        let txns1 = vec![make_transaction(addr(0), 1)];
        let tx_hashes = vec![txns0[0].tx_hash(), txns1[0].tx_hash()];

        controller.set_blocks(vec![
            MockBlock::new(hash(1)).add_txns(txns0), // this is a reorg block
            MockBlock::new(hash(2)).add_txns(txns1),
        ]);
        controller.set_balances(HashMap::from([(addr(0), U256::from(100))]));

        let update = chain.sync_to_block(controller.get_head()).await.unwrap();
        assert_eq!(
            update,
            ChainUpdate {
                latest_block_number: 1,
                latest_block_hash: hash(2),
                latest_block_timestamp: 0.into(),
                earliest_remembered_block_number: 0,
                reorg_depth: 1,
                mined_ops: vec![],
                unmined_ops: vec![],
                preconfirmed_txns: vec![],
                preconfirmed_block_number: None,
                entity_balance_updates: vec![],
                unmined_entity_balance_updates: vec![],
                address_updates: vec![AddressUpdate {
                    address: addr(0),
                    nonce: Some(1),
                    balance: U256::from(100),
                    mined_tx_hashes: tx_hashes,
                }],
                reorg_larger_than_history: false,
                update_type: UpdateType::Confirmed,
            }
        )
    }

    fn new_chain() -> (Chain<impl EvmProvider>, ProviderController) {
        _new_chain(false)
    }

    fn _new_chain(flashblocks: bool) -> (Chain<impl EvmProvider>, ProviderController) {
        let (provider, controller) = new_mock_provider();
        let chain = Chain::new(
            Arc::new(provider),
            Settings {
                history_size: HISTORY_SIZE,
                poll_interval: Duration::from_secs(250), // Not used in tests.
                entry_point_addresses: HashMap::from([
                    (ENTRY_POINT_ADDRESS_V0_6, EntryPointVersion::V0_6),
                    (ENTRY_POINT_ADDRESS_V0_7, EntryPointVersion::V0_7),
                ]),
                max_sync_retries: 1,
                channel_capacity: 100,
                flashblocks,
            },
        );
        (chain, controller)
    }

    fn new_mock_provider() -> (impl EvmProvider, ProviderController) {
        let controller = ProviderController {
            blocks: Arc::new(RwLock::new(vec![])),
            balances: Arc::new(RwLock::new(HashMap::new())),
            pending_block: Arc::new(RwLock::new(None)),
        };
        let mut provider = MockEvmProvider::new();

        provider.expect_get_full_block().returning({
            let controller = controller.clone();
            move |id| Ok(controller.get_block(id))
        });

        provider.expect_get_logs().returning({
            let controller = controller.clone();
            move |filter| {
                let FilterBlockOption::AtBlockHash(block_hash) = filter.block_option else {
                    panic!("mock provider only supports getLogs at specific block hashes");
                };
                Ok(controller.get_logs_by_block_hash(filter, block_hash))
            }
        });

        provider.expect_get_balances().returning({
            let controller = controller.clone();
            move |addresses| Ok(controller.get_balances(addresses))
        });

        (provider, controller)
    }

    fn fake_mined_log_v0_6(op_hash: B256) -> Log {
        let mut log_data = LogData::default();
        log_data.set_topics_unchecked(vec![
            UserOperationEventV06::SIGNATURE_HASH,
            op_hash,
            B256::ZERO, // sender
            B256::ZERO, // paymaster
        ]);
        log_data.data = UserOperationEventV06 {
            userOpHash: op_hash,
            sender: Address::ZERO,
            paymaster: Address::ZERO,
            nonce: U256::ZERO,
            success: true,
            actualGasCost: U256::ZERO,
            actualGasUsed: U256::ZERO,
        }
        .encode_data()
        .into();

        Log {
            inner: PrimitiveLog {
                address: ENTRY_POINT_ADDRESS_V0_6,
                data: log_data,
            },
            ..Default::default()
        }
    }

    fn fake_deposit_log_v0_6(deposit_address: Address) -> Log {
        let mut log_data = LogData::default();
        log_data.set_topics_unchecked(vec![
            DepositedV06::SIGNATURE_HASH,
            deposit_address.into_word(),
        ]);
        log_data.data = DepositedV06 {
            totalDeposit: U256::ZERO,
            account: deposit_address,
        }
        .encode_data()
        .into();

        Log {
            inner: PrimitiveLog {
                address: ENTRY_POINT_ADDRESS_V0_6,
                data: log_data,
            },
            ..Default::default()
        }
    }

    fn fake_withdrawal_log_v0_6(withdrawal_address: Address) -> Log {
        let mut log_data = LogData::default();
        log_data.set_topics_unchecked(vec![
            WithdrawnV06::SIGNATURE_HASH,
            withdrawal_address.into_word(),
        ]);
        log_data.data = WithdrawnV06 {
            amount: U256::ZERO,
            account: withdrawal_address,
            withdrawAddress: Address::ZERO,
        }
        .encode_data()
        .into();

        Log {
            inner: PrimitiveLog {
                address: ENTRY_POINT_ADDRESS_V0_6,
                data: log_data,
            },
            ..Default::default()
        }
    }

    fn fake_mined_log_v0_7(op_hash: B256) -> Log {
        let mut log_data = LogData::default();
        log_data.set_topics_unchecked(vec![
            UserOperationEventV07::SIGNATURE_HASH,
            op_hash,
            B256::ZERO, // sender
            B256::ZERO, // paymaster
        ]);
        log_data.data = UserOperationEventV07 {
            userOpHash: op_hash,
            sender: Address::ZERO,
            paymaster: Address::ZERO,
            nonce: U256::ZERO,
            success: true,
            actualGasCost: U256::ZERO,
            actualGasUsed: U256::ZERO,
        }
        .encode_data()
        .into();

        Log {
            inner: PrimitiveLog {
                address: ENTRY_POINT_ADDRESS_V0_7,
                data: log_data,
            },
            ..Default::default()
        }
    }

    fn fake_deposit_log_v0_7(deposit_address: Address) -> Log {
        let mut log_data = LogData::default();
        log_data.set_topics_unchecked(vec![
            DepositedV07::SIGNATURE_HASH,
            deposit_address.into_word(),
        ]);
        log_data.data = DepositedV07 {
            totalDeposit: U256::ZERO,
            account: deposit_address,
        }
        .encode_data()
        .into();

        Log {
            inner: PrimitiveLog {
                address: ENTRY_POINT_ADDRESS_V0_7,
                data: log_data,
            },
            ..Default::default()
        }
    }

    fn fake_withdrawal_log_v0_7(withdrawal_address: Address) -> Log {
        let mut log_data = LogData::default();
        log_data.set_topics_unchecked(vec![
            WithdrawnV07::SIGNATURE_HASH,
            withdrawal_address.into_word(),
        ]);
        log_data.data = WithdrawnV06 {
            amount: U256::ZERO,
            account: withdrawal_address,
            withdrawAddress: Address::ZERO,
        }
        .encode_data()
        .into();

        Log {
            inner: PrimitiveLog {
                address: ENTRY_POINT_ADDRESS_V0_7,
                data: log_data,
            },
            ..Default::default()
        }
    }

    fn fake_mined_op(n: u8, ep: Address) -> MinedOp {
        MinedOp {
            hash: hash(n),
            entry_point: ep,
            sender: Address::ZERO,
            nonce: U256::ZERO,
            actual_gas_cost: U256::ZERO,
            paymaster: None,
        }
    }

    fn fake_mined_balance_update(
        address: Address,
        amount: u128,
        is_addition: bool,
        ep: Address,
    ) -> BalanceUpdate {
        BalanceUpdate {
            address,
            entrypoint: ep,
            amount: U256::from(amount),
            is_addition,
        }
    }

    // Helper that makes fake hashes.
    fn hash(n: u8) -> B256 {
        let mut hash = B256::ZERO;
        hash.0[0] = n;
        hash
    }

    // Helper that makes fake addresses.
    fn addr(n: u8) -> Address {
        let mut address = Address::ZERO;
        address.0[0] = n;
        address
    }

    fn make_transaction(from: Address, nonce: u64) -> Transaction {
        let typed = TransactionRequest::default()
            .from(from)
            .nonce(nonce)
            .to(Address::ZERO)
            .gas_limit(0)
            .max_fee_per_gas(0)
            .max_priority_fee_per_gas(0)
            .build_typed_tx()
            .unwrap();

        let TypedTransaction::Eip1559(txn) = typed else {
            panic!("expected eip1559 transaction");
        };

        let signed = txn.into_signed(Signature::test_signature());
        WithOtherFields::new(AlloyTransaction {
            inner: Recovered::new_unchecked(AnyTxEnvelope::Ethereum(signed.into()), from),
            block_hash: None,
            block_number: None,
            transaction_index: None,
            effective_gas_price: None,
        })
        .into()
    }
}
