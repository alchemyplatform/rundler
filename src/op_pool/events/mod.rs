use ethers::{
    prelude::StreamExt,
    providers::{Middleware, Provider, Ws},
    types::{Address, Block, H256},
};
use std::{sync::Arc, time::Duration};
use tokio::sync::broadcast::Receiver;
use tracing::{debug, error, info};

use crate::{
    common::contracts::entry_point::{EntryPoint, EntryPointEvents},
    op_pool::mempool::OnNewBlockEvent,
};

use super::mempool::{Mempool, OnUserOperationEvent};

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
        let events = self.entry_point.events();
        let mut event_stream = events.stream().await?;
        let blocks = self.provider.watch_blocks().await?;
        let mut block_stream = blocks.stream();

        loop {
            tokio::select! {
                stream_event = event_stream.next() => {
                    match stream_event {
                        Some(event) => {
                            debug!("Event: {:?}", event);
                            match event {
                                Ok(event) => self.handle_event(&event),
                                Err(err) => error!("Contract error: {:?}", err),
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
        self.mempool.on_new_block(OnNewBlockEvent {
            block_hash: block.hash.unwrap_or_default(),
            block_number: block.number.unwrap_or_default(),
            next_base_fee: block.next_block_base_fee().unwrap_or_default(),
        });
    }

    fn handle_event(&self, event: &EntryPointEvents) {
        match event {
            EntryPointEvents::UserOperationEventFilter(event) => {
                let op_hash: H256 = event.user_op_hash.into();
                debug!("Received op hash: {op_hash:?}");
                self.mempool.on_user_operation_event(OnUserOperationEvent {
                    op_hash,
                    sender: event.sender,
                    nonce: event.nonce,
                })
            }
            // TODO(danc): Handle other events
            _ => {
                debug!("Unhandled event: {:?}", event);
            }
        }
    }
}
