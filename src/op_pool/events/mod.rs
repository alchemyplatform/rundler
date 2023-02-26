use ethers::{
    prelude::{EthLogDecode, StreamExt},
    providers::{Middleware, Provider, Ws},
    types::{Address, Block, H256, U256, U64},
};
use std::{sync::Arc, time::Duration};
use tokio::sync::broadcast::Receiver;
use tracing::{debug, error, info};

use crate::common::{
    contracts::entry_point::{EntryPoint, EntryPointEvents},
    eth::log_to_raw_log,
};

use super::mempool::Mempool;

/// Event when a new block is mined.
#[derive(Debug)]
pub struct NewBlockEvent {
    /// The block hash
    pub block_hash: H256,
    /// The block number
    pub block_number: U64,
    /// The next base fee
    pub next_base_fee: U256,
}

/// Event when a user operation event is received.
#[derive(Debug)]
pub struct UserOperationEvent {
    /// The transaction hash containing this event
    pub txn_hash: H256,
    /// The operation hash
    pub op_hash: H256,
    /// The operation sender
    pub sender: Address,
    /// The operation nonce
    pub nonce: U256,
    /// The paymaster, if any
    pub paymaster: Option<Address>,
}

#[derive(Debug)]
pub struct SignagureAggregatorChangedEvent {
    pub tx_hash: H256,
    /// The new signature aggregator
    /// None if the signature aggregator was removed
    pub aggregator: Option<Address>,
}

#[derive(Debug)]
pub struct AccountDeployedEvent {
    /// The factory address
    pub factory: Address,
}

pub struct EventListener<M: Mempool> {
    provider: Arc<Provider<Ws>>,
    entry_point: EntryPoint<Provider<Ws>>,
    mempool: Arc<M>,
}

impl<M: Mempool> EventListener<M> {
    pub async fn connect(
        ws_url: String,
        entry_point: Address,
        mempool: Arc<M>,
    ) -> anyhow::Result<Self> {
        let provider = Arc::new(
            Provider::<Ws>::connect(ws_url)
                .await?
                .interval(Duration::from_millis(100)),
        );
        let entry_point = EntryPoint::new(entry_point, provider.clone());
        Ok(Self {
            provider,
            entry_point,
            mempool,
        })
    }

    pub async fn listen_with_shutdown(&self, mut shutdown_rx: Receiver<()>) -> anyhow::Result<()> {
        let events_filter = self.entry_point.events();
        let mut event_logs = self.provider.subscribe_logs(&events_filter.filter).await?;

        let blocks = self.provider.watch_blocks().await?;
        let mut block_stream = blocks.stream();

        loop {
            tokio::select! {
                event_log = event_logs.next() => {
                    match event_log {
                        Some(log) => {
                            debug!("Event log: {:?}", log);
                            let txn_hash = log.transaction_hash.unwrap_or_default();
                            match EntryPointEvents::decode_log(&log_to_raw_log(log)) {
                                Ok(event) => {
                                    self.handle_event(event, txn_hash)
                                },
                                Err(err) => {
                                    error!("Error decoding event: {:?}", err);
                                }
                            }
                        }
                        None => {
                            // TODO(danc): Handle reconnect retries
                            error!("Event stream ended");
                            break;
                        }
                    }
                }
                block_event = block_stream.next() => {
                    match block_event {
                        Some(block_hash) => {
                            debug!("Block hash: {:?}", block_hash);

                            let block = self.provider.get_block(block_hash).await;
                            match block {
                                Ok(block) => match block {
                                    Some(block) => {
                                        self.handle_new_block(block);
                                    }
                                    None => {
                                        error!("Block {block_hash:?} not found");
                                    }
                                },
                                Err(err) => {
                                    error!("Error getting block: {:?}", err);
                                }
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

    fn handle_new_block(&self, block: Block<H256>) {
        debug!(
            "Received block number: {:?}",
            block.number.unwrap_or_default()
        );
        self.mempool.on_new_block(NewBlockEvent {
            block_hash: block.hash.unwrap_or_default(),
            block_number: block.number.unwrap_or_default(),
            next_base_fee: block.next_block_base_fee().unwrap_or_default(),
        });
    }

    fn handle_event(&self, event: EntryPointEvents, txn_hash: H256) {
        match event {
            EntryPointEvents::UserOperationEventFilter(event) => {
                let op_hash: H256 = event.user_op_hash.into();
                debug!("Received op hash {op_hash:?} in txn {txn_hash:?}");
                let paymaster = if event.paymaster.is_zero() {
                    None
                } else {
                    Some(event.paymaster)
                };

                self.mempool.on_user_operation_event(UserOperationEvent {
                    txn_hash,
                    op_hash,
                    sender: event.sender,
                    nonce: event.nonce,
                    paymaster,
                })
            }
            // TODO(danc): Handle other events
            _ => {
                debug!("Unhandled event: {:?}", event);
            }
        }
    }
}
