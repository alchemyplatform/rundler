use ethers::{
    providers::{Middleware, Provider, StreamExt, Ws},
    types::{Block, Filter, H256},
};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tonic::async_trait;

use super::{BlockProvider, BlockProviderError, BlockProviderFactory, BlockWithLogs};

/// A block provider factory that uses an ethers websocket provider
/// to stream blocks from a node's websocket endpoint
pub struct WsBlockProviderFactory {
    ws_url: String,
    num_retries: usize,
}

impl WsBlockProviderFactory {
    pub fn new(ws_url: String, num_retries: usize) -> Self {
        Self {
            ws_url,
            num_retries,
        }
    }
}

#[async_trait]
impl BlockProviderFactory for WsBlockProviderFactory {
    type Provider = WsBlockProvider;

    fn new_provider(&self) -> Self::Provider {
        WsBlockProvider::new(self.ws_url.clone(), self.num_retries)
    }
}

/// A block provider that uses an ethers websocket provider
#[derive(Debug)]
pub struct WsBlockProvider {
    ws_url: String,
    num_retries: usize,
    shutdown_sender: Option<oneshot::Sender<()>>,
}

impl WsBlockProvider {
    pub fn new(ws_url: String, num_retries: usize) -> Self {
        Self {
            ws_url,
            num_retries,
            shutdown_sender: None,
        }
    }
}

#[async_trait]
impl BlockProvider for WsBlockProvider {
    type BlockStream = ReceiverStream<Result<BlockWithLogs, BlockProviderError>>;

    async fn subscribe(&mut self, filter: Filter) -> Result<Self::BlockStream, BlockProviderError> {
        if self.shutdown_sender.is_some() {
            return Err(BlockProviderError::ConnectionError(
                "already subscribed".to_string(),
            ));
        }

        let provider =
            Provider::<Ws>::connect_with_reconnects(self.ws_url.clone(), self.num_retries)
                .await
                .map_err(|err| BlockProviderError::ConnectionError(err.to_string()))?;

        let (tx, rx) = mpsc::channel(10_000);
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        self.shutdown_sender = Some(shutdown_tx);

        tokio::spawn(async move {
            let mut block_subscription = match provider.subscribe_blocks().await {
                Ok(sub) => sub,
                Err(err) => {
                    tracing::error!("Error subscribing to blocks: {:?}", err);
                    if tx
                        .send(Err(BlockProviderError::ConnectionError(err.to_string())))
                        .await
                        .is_err()
                    {
                        tracing::error!("Receiver dropped");
                    }
                    return;
                }
            };

            loop {
                tokio::select! {
                    res = block_subscription.next() => {
                        let msg = match res {
                            Some(block) => {
                                Self::process_block(&provider, block, &filter).await
                            }
                            None => {
                                tracing::error!("Block subscription ended");
                                Err(BlockProviderError::ConnectionError("block subscription closed".to_string()))
                            }
                        };
                        let was_err = msg.is_err();
                        if tx.send(msg).await.is_err() {
                            tracing::error!("Receiver dropped");
                            return;
                        }
                        if was_err {
                            return;
                        }
                    },
                    _ = &mut shutdown_rx => {
                        return;
                    }
                }
            }
        });

        Ok(ReceiverStream::new(rx))
    }

    async fn unsubscribe(&mut self) {
        let shutdown_sender = self.shutdown_sender.take();
        if let Some(ss) = shutdown_sender {
            let _ = ss.send(());
        }
    }
}

impl WsBlockProvider {
    async fn process_block(
        provider: &Provider<Ws>,
        block: Block<H256>,
        filter: &Filter,
    ) -> Result<BlockWithLogs, BlockProviderError> {
        let block_hash = block.hash.unwrap_or_default();
        let filter = filter.clone().at_block_hash(block_hash);
        let logs = provider
            .get_logs(&filter)
            .await
            .map_err(|err| BlockProviderError::ConnectionError(err.to_string()))?;
        let block_with_logs = BlockWithLogs { block, logs };
        Ok(block_with_logs)
    }
}
