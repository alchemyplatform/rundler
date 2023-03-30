use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use ethers::types::Filter;
use tokio::sync::{broadcast, mpsc};
use tokio_stream::{wrappers::BroadcastStream, Stream, StreamExt};
use tonic::async_trait;

use super::{BlockProvider, BlockProviderError, BlockProviderFactory, BlockWithLogs};

pub struct MockBlockProvider {
    rx: broadcast::Receiver<Result<BlockWithLogs, BlockProviderError>>,
    fail_subscription: bool,
    subscription_event: mpsc::Sender<()>,
}

#[async_trait]
impl BlockProvider for MockBlockProvider {
    type BlockStream =
        Box<dyn Stream<Item = Result<BlockWithLogs, BlockProviderError>> + Send + Unpin>;

    async fn subscribe(
        &mut self,
        _filter: Filter,
    ) -> Result<Self::BlockStream, BlockProviderError> {
        let ret = match self.fail_subscription {
            true => Err(BlockProviderError::ConnectionError(
                "forced error".to_string(),
            )),
            false => Ok(Box::new(
                BroadcastStream::new(self.rx.resubscribe()).map(|res| match res {
                    Ok(res) => res,
                    Err(_) => Err(BlockProviderError::ConnectionError(
                        "strem recv error".to_string(),
                    )),
                }),
            ) as Self::BlockStream),
        };
        self.subscription_event
            .send(())
            .await
            .expect("failed to send connection event");
        ret
    }

    async fn unsubscribe(&mut self) {}
}

pub struct MockBlockProviderFactory {
    rx: broadcast::Receiver<Result<BlockWithLogs, BlockProviderError>>,
    connection_event_tx: mpsc::Sender<()>,
    should_fail_connection: Arc<AtomicBool>,
}

impl BlockProviderFactory for MockBlockProviderFactory {
    type Provider = MockBlockProvider;

    fn new_provider(&self) -> Self::Provider {
        MockBlockProvider {
            fail_subscription: self.should_fail_connection.load(Ordering::SeqCst),
            rx: self.rx.resubscribe(),
            subscription_event: self.connection_event_tx.clone(),
        }
    }
}

impl MockBlockProviderFactory {
    pub fn new(
        rx: broadcast::Receiver<Result<BlockWithLogs, BlockProviderError>>,
        connection_event_tx: mpsc::Sender<()>,
        should_fail_connection: Arc<AtomicBool>,
    ) -> Self {
        Self {
            rx,
            connection_event_tx,
            should_fail_connection,
        }
    }
}
