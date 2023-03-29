use std::{collections::HashMap, sync::Arc};

use anyhow::{bail, Context};
use ethers::{
    prelude::{parse_log, StreamExt},
    providers::{Middleware, Provider, Ws},
    types::{Address, Filter, H256, U256, U64},
};
use tokio::sync::broadcast;
use tracing::{debug, error, info};

use crate::common::contracts::i_entry_point::IEntryPointEvents;

/// Event when a new block is mined.
/// Events correspond to a single entry point
#[derive(Debug)]
pub struct NewBlockEvent {
    /// The entry point address
    pub address: Address,
    /// The block hash
    pub hash: H256,
    /// The block number
    pub number: U64,
    /// The next base fee
    pub next_base_fee: U256,
    /// Ordered EntryPoint events
    pub events: Vec<EntryPointEvent>,
}

#[derive(Debug)]
pub struct EntryPointEvent {
    pub contract_event: IEntryPointEvents,
    pub txn_hash: H256,
    pub txn_index: U64,
}

pub struct EventListener {
    provider: Arc<Provider<Ws>>,
    log_filter_base: Filter,
    entrypoint_event_broadcasts: HashMap<Address, broadcast::Sender<Arc<NewBlockEvent>>>,
}

impl EventListener {
    pub async fn connect(
        ws_url: String,
        entry_points: impl IntoIterator<Item = &Address>,
    ) -> anyhow::Result<Self> {
        let provider = Arc::new(Provider::<Ws>::connect(ws_url).await?);

        let mut entry_point_addresses = vec![];
        let mut entrypoint_event_broadcasts = HashMap::new();
        for ep in entry_points {
            entry_point_addresses.push(*ep);
            entrypoint_event_broadcasts.insert(*ep, broadcast::channel(1000).0);
        }

        let log_filter_base = Filter::new().address(entry_point_addresses);

        Ok(Self {
            provider,
            log_filter_base,
            entrypoint_event_broadcasts,
        })
    }

    pub fn subscribe_by_entrypoint(
        &self,
        entry_point: Address,
    ) -> Option<broadcast::Receiver<Arc<NewBlockEvent>>> {
        self.entrypoint_event_broadcasts
            .get(&entry_point)
            .map(|b| b.subscribe())
    }

    pub async fn listen_with_shutdown(
        &self,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) -> anyhow::Result<()> {
        // TODO(danc): Handle initial reconnects
        let blocks = self.provider.watch_blocks().await?;
        let mut block_stream = blocks.stream();

        loop {
            tokio::select! {
                block_event = block_stream.next() => {
                    match block_event {
                        Some(block_hash) => {
                            debug!("Received block hash: {:?}", block_hash);
                            if let Err(e) = self.handle_block_event(block_hash).await {
                                // TODO(danc): Handle errors with retries
                                error!("Error handling block event: {:?}", e);
                            }
                        }
                        None => {
                            // TODO(danc): Handle reconnect retries
                            error!("Block stream ended");
                            break;
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("Shutting down event listener");
                    break;
                }
            }
        }

        Ok(())
    }

    async fn handle_block_event(&self, hash: H256) -> anyhow::Result<()> {
        let block = self.provider.get_block(hash).await?;
        let block = block.context("provider should return block")?;
        let block_hash = block.hash.context("block should have hash")?;
        let block_number = block.number.context("block should have number")?;
        debug!("Received block number/hash {block_number:?}/{block_hash:?}");

        let log_filter = self.log_filter_base.clone().from_block(block_number);
        let mut logs = self.provider.get_logs(&log_filter).await?;
        logs.sort_by(|a, b| a.log_index.cmp(&b.log_index));

        let mut block_events = HashMap::new();
        let next_base_fee = block
            .next_block_base_fee()
            .context("block should calculate next base fee")?;

        for log in logs {
            let ep_address = log.address;
            let txn_hash = log
                .transaction_hash
                .context("log should have transaction hash")?;
            let txn_index = log
                .transaction_index
                .context("log should have transaction index")?;

            let event = EntryPointEvent {
                contract_event: parse_log(log)?,
                txn_hash,
                txn_index,
            };

            let block_event = block_events
                .entry(ep_address)
                .or_insert_with(|| NewBlockEvent {
                    address: ep_address,
                    hash: block_hash,
                    number: block_number,
                    next_base_fee,
                    events: vec![],
                });
            block_event.events.push(event);
        }

        for (ep, block_event) in block_events {
            match self.entrypoint_event_broadcasts.get(&ep) {
                Some(broadcast) => {
                    broadcast.send(Arc::new(block_event))?;
                }
                None => {
                    bail!("No broadcast channel for entry point: {:?}", ep);
                }
            }
        }

        Ok(())
    }
}
