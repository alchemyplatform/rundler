use std::time::Duration;

use ethers::{
    providers::{
        Http, HttpRateLimitRetryPolicy, Middleware, Provider, RetryClientBuilder, StreamExt,
    },
    types::{Block, Filter, Log, H256},
};
use tokio::{
    select,
    sync::{mpsc, oneshot},
    try_join,
};
use tokio_stream::wrappers::ReceiverStream;
use tonic::async_trait;
use tracing::error;
use url::Url;

use super::{BlockProvider, BlockProviderError, BlockProviderFactory, BlockWithLogs};

/// A block provider factory
#[derive(Debug)]
pub struct HttpBlockProviderFactory {
    http_url: String,
    poll_interval: Duration,
    num_retries: u64,
}

impl HttpBlockProviderFactory {
    pub fn new(http_url: String, poll_interval: Duration, num_retries: u64) -> Self {
        Self {
            http_url,
            poll_interval,
            num_retries,
        }
    }
}

#[async_trait]
impl BlockProviderFactory for HttpBlockProviderFactory {
    type Provider = HttpBlockProvider;

    fn new_provider(&self) -> Self::Provider {
        HttpBlockProvider::new(self.http_url.clone(), self.poll_interval, self.num_retries)
    }
}

/// An http provider that uses ethers to stream blocks from a node's http endpoint
/// Polls the node for new blocks at a given interval
#[derive(Debug)]
pub struct HttpBlockProvider {
    http_url: String,
    poll_interval: Duration,
    num_retries: u64,
    shutdown_sender: Option<oneshot::Sender<()>>,
}

impl HttpBlockProvider {
    pub fn new(http_url: String, poll_interval: Duration, num_retries: u64) -> Self {
        Self {
            http_url,
            poll_interval,
            num_retries,
            shutdown_sender: None,
        }
    }
}

#[async_trait]
impl BlockProvider for HttpBlockProvider {
    type BlockStream = ReceiverStream<Result<BlockWithLogs, BlockProviderError>>;

    async fn subscribe(&mut self, filter: Filter) -> Result<Self::BlockStream, BlockProviderError> {
        if self.shutdown_sender.is_some() {
            return Err(BlockProviderError::ConnectionError(
                "already subscribed".to_string(),
            ));
        }

        let parsed_url = Url::parse(&self.http_url)
            .map_err(|e| BlockProviderError::ConnectionError(e.to_string()))?;
        let num_retries = self.num_retries.try_into().map_err(|_| {
            BlockProviderError::ConnectionError(format!(
                "num_retries {} is too large",
                self.num_retries
            ))
        })?;
        let http = Http::new(parsed_url);
        let client = RetryClientBuilder::default()
            .rate_limit_retries(num_retries)
            .timeout_retries(num_retries)
            .initial_backoff(self.poll_interval)
            .build(http, Box::<HttpRateLimitRetryPolicy>::default());
        let mut provider = Provider::new(client);
        provider.set_interval(self.poll_interval);

        // test the connection
        let _ = provider
            .get_block_number()
            .await
            .map_err(|err| BlockProviderError::ConnectionError(err.to_string()))?;

        let (tx, rx) = mpsc::channel(10_000);
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        self.shutdown_sender = Some(shutdown_tx);

        tokio::spawn(async move {
            let mut block_stream = match provider.watch_blocks().await {
                Ok(stream) => stream,
                Err(err) => {
                    tracing::error!("Error subscribing to blocks: {:?}", err);
                    let _ = tx
                        .send(Err(BlockProviderError::ConnectionError(err.to_string())))
                        .await;
                    return;
                }
            };

            loop {
                select! {
                    block = block_stream.next() => {
                        let msg = match block {
                            Some(block_hash) => {
                                let block_filter = filter.clone().at_block_hash(block_hash);
                                match try_join!(Self::get_block(&provider, block_hash), Self::get_logs(&provider, &block_filter)) {
                                    Ok((block, logs)) => {
                                        Ok(BlockWithLogs { block, logs })
                                    },
                                    Err(err) => {
                                        error!("Error getting block or logs: {:?}", err);
                                        Err(err)
                                    }
                                }
                            },
                            None => {
                                error!("Block stream ended");
                                Err(BlockProviderError::ConnectionError("Block stream ended".to_string()))
                            }
                        };
                        let was_err = msg.is_err();
                        if tx.send(msg).await.is_err() {
                            error!("Receiver dropped");
                            return;
                        }
                        if was_err {
                            error!("Provider error getting block or logs, ending subscription");
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

impl HttpBlockProvider {
    async fn get_block<P: Middleware>(
        provider: &P,
        block_hash: H256,
    ) -> Result<Block<H256>, BlockProviderError> {
        provider
            .get_block(block_hash)
            .await
            .map_err(|err| BlockProviderError::ConnectionError(err.to_string()))?
            .ok_or_else(|| BlockProviderError::RpcError("Block not found".to_string()))
    }

    async fn get_logs<P: Middleware>(
        provider: &P,
        filter: &Filter,
    ) -> Result<Vec<Log>, BlockProviderError> {
        provider
            .get_logs(filter)
            .await
            .map_err(|err| BlockProviderError::ConnectionError(err.to_string()))
    }
}
