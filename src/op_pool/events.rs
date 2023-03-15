use anyhow::Context;
use ethers::{
    prelude::StreamExt,
    providers::{Middleware, Provider, Ws},
    types::{Address, H256, U256, U64},
};
use std::{sync::Arc, time::Duration};
use tokio::sync::broadcast;
use tracing::{debug, error, info};

use crate::common::contracts::entry_point::{EntryPoint, EntryPointEvents};

/// Event when a new block is mined.
#[derive(Debug)]
pub struct NewBlockEvent {
    /// The block hash
    pub hash: H256,
    /// The block number
    pub number: U64,
    /// The next base fee
    pub next_base_fee: U256,
    /// Ordered entrypoint events
    pub events: Vec<EntryPointEvent>,
}

#[derive(Debug)]
pub struct EntryPointEvent {
    pub contract_event: EntryPointEvents,
    pub txn_hash: H256,
    pub txn_index: U64,
}

pub struct EventListener {
    provider: Arc<Provider<Ws>>,
    entry_point: EntryPoint<Provider<Ws>>,
    new_block_broadcast: broadcast::Sender<Arc<NewBlockEvent>>,
}

impl EventListener {
    pub async fn connect(ws_url: String, entry_point: Address) -> anyhow::Result<Self> {
        let provider = Arc::new(
            Provider::<Ws>::connect(ws_url)
                .await?
                .interval(Duration::from_millis(100)),
        );
        let entry_point = EntryPoint::new(entry_point, provider.clone());
        Ok(Self {
            provider,
            entry_point,
            new_block_broadcast: broadcast::channel(1000).0,
        })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Arc<NewBlockEvent>> {
        self.new_block_broadcast.subscribe()
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

        let event_filter = self.entry_point.events().from_block(block_number);
        let mut logs = self.provider.get_logs(&event_filter.filter).await?;
        logs.sort_by(|a, b| a.log_index.cmp(&b.log_index));

        let events: Vec<EntryPointEvent> = logs
            .into_iter()
            .map(|log| {
                let txn_hash = log
                    .transaction_hash
                    .context("log should have transaction hash")?;
                let txn_index = log
                    .transaction_index
                    .context("log should have transaction index")?;
                Ok(EntryPointEvent {
                    contract_event: self.entry_point.events().parse_log(log)?,
                    txn_hash,
                    txn_index,
                })
            })
            .collect::<Result<Vec<_>, anyhow::Error>>()?;

        let new_block_event = Arc::new(NewBlockEvent {
            hash: block_hash,
            number: block_number,
            next_base_fee: block
                .next_block_base_fee()
                .context("block should calculate next base fee")?,
            events,
        });

        self.new_block_broadcast
            .send(new_block_event)
            .context("should broadcast new block event")?;

        Ok(())
    }
}
