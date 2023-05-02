use std::{
    cmp,
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context;
use ethers::{
    prelude::parse_log,
    types::{Address, Filter},
};
use rand::Rng;
use tokio::{
    select,
    sync::broadcast,
    task::JoinHandle,
    time::{sleep, timeout},
};
use tokio_stream::StreamExt;
use tracing::{error, info};

use super::{
    BlockProvider, BlockProviderFactory, BlockWithLogs, EntryPointEvent, EventProvider,
    NewBlockEvent,
};

const MAX_BACKOFF_SECONDS: u64 = 60;

/// An event listener that listens for new blocks and emits events
/// for each provided entry point
pub struct EventListener<F: BlockProviderFactory> {
    provider_factory: F,
    provider: Option<F::Provider>,
    log_filter_base: Filter,
    entrypoint_event_broadcasts: HashMap<Address, broadcast::Sender<Arc<NewBlockEvent>>>,
    last_reconnect: Option<Instant>,
    backoff_idx: u32,
}

impl<F: BlockProviderFactory> EventProvider for EventListener<F> {
    fn subscribe_by_entrypoint(
        &self,
        entry_point: Address,
    ) -> Option<broadcast::Receiver<Arc<NewBlockEvent>>> {
        self.entrypoint_event_broadcasts
            .get(&entry_point)
            .map(|b| b.subscribe())
    }

    fn spawn(
        self: Box<Self>,
        shutdown_rx: broadcast::Receiver<()>,
    ) -> JoinHandle<Result<(), anyhow::Error>> {
        tokio::spawn(async move { self.listen_with_shutdown(shutdown_rx).await })
    }
}

impl<F: BlockProviderFactory> EventListener<F> {
    /// Create a new event listener from a block provider factory and list entry points
    /// Must call listen_with_shutdown to start listening
    pub fn new<'a>(
        provider_factory: F,
        entry_points: impl IntoIterator<Item = &'a Address>,
    ) -> Self {
        let mut entry_point_addresses = vec![];
        let mut entrypoint_event_broadcasts = HashMap::new();
        for ep in entry_points {
            entry_point_addresses.push(*ep);
            entrypoint_event_broadcasts.insert(*ep, broadcast::channel(1000).0);
        }

        let log_filter_base = Filter::new().address(entry_point_addresses);

        Self {
            provider_factory,
            provider: None,
            log_filter_base,
            entrypoint_event_broadcasts,
            last_reconnect: None,
            backoff_idx: 0,
        }
    }

    /// Consumes the listener and starts listening for new blocks
    /// until the shutdown signal is received
    pub async fn listen_with_shutdown(
        mut self,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) -> anyhow::Result<()> {
        let mut block_stream = self.reconnect(&mut shutdown_rx).await?;
        loop {
            select! {
                block_with_logs = block_stream.next() => {
                    match block_with_logs {
                        Some(Ok(block_with_logs)) => {
                            if let Err(err) = self.handle_block_event(block_with_logs).await {
                                error!("Error handling block event: {err:?}");
                                EventListenerMetrics::increment_block_handler_errors();
                            }
                        }
                        Some(Err(err)) => {
                            error!("Error getting block: {:?}", err);
                            EventListenerMetrics::increment_provider_errors();
                            block_stream = self.reconnect(&mut shutdown_rx).await?;
                        }
                        None => {
                            error!("Block stream ended unexpectedly");
                            EventListenerMetrics::increment_provider_errors();
                            block_stream = self.reconnect(&mut shutdown_rx).await?;
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

    async fn reconnect(
        &mut self,
        shutdown_rx: &mut broadcast::Receiver<()>,
    ) -> anyhow::Result<<F::Provider as BlockProvider>::BlockStream> {
        if let Some(mut provider) = self.provider.take() {
            provider.unsubscribe().await;
        }

        let since_last_recovery = self.last_reconnect.map(|t| Instant::now() - t);
        if let Some(since_last_recovery) = since_last_recovery {
            let expected_backoff = self.backoff_time();
            if since_last_recovery < expected_backoff {
                let sleep_duration = expected_backoff - since_last_recovery;
                info!(
                    "Reconnecting too quickly, sleeping {:?} before reconnecting",
                    sleep_duration
                );
                if self.sleep_or_shutdown(shutdown_rx, sleep_duration).await {
                    return Err(anyhow::anyhow!("Shutdown signal received"));
                }
            } else {
                info!("Reconnecting after {since_last_recovery:?}, expected backoff {expected_backoff:?}");
                self.backoff_idx = 0;
            }
        }

        loop {
            self.provider = Some(self.provider_factory.new_provider());
            match timeout(
                Duration::from_secs(5),
                self.provider
                    .as_mut()
                    .unwrap()
                    .subscribe(self.log_filter_base.clone()),
            )
            .await
            {
                Ok(Ok(block_stream)) => {
                    info!("Connected to event provider");
                    self.last_reconnect = Some(Instant::now());
                    return Ok(block_stream);
                }
                Ok(Err(err)) => {
                    EventListenerMetrics::increment_provider_errors();
                    let sleep_duration = self.backoff_time();
                    error!(
                        "Error connecting to event provider, sleeping {sleep_duration:?}: {err:?}"
                    );
                    if self.sleep_or_shutdown(shutdown_rx, sleep_duration).await {
                        return Err(anyhow::anyhow!("Shutdown signal received"));
                    }
                }
                Err(err) => {
                    EventListenerMetrics::increment_provider_errors();
                    let sleep_duration = self.backoff_time();
                    error!(
                        "Timeout connecting to event provider, sleeping {sleep_duration:?}: {err:?}"
                    );
                    if self.sleep_or_shutdown(shutdown_rx, sleep_duration).await {
                        return Err(anyhow::anyhow!("Shutdown signal received"));
                    }
                }
            }
        }
    }

    async fn handle_block_event(&self, mut block_with_logs: BlockWithLogs) -> anyhow::Result<()> {
        block_with_logs
            .logs
            .sort_by(|a, b| a.log_index.cmp(&b.log_index));
        let block_hash = block_with_logs
            .block
            .hash
            .context("block should have hash")?;
        let block_number = block_with_logs
            .block
            .number
            .context("block should have number")?;
        let mut block_events = HashMap::new();

        EventListenerMetrics::increment_blocks_seen();
        EventListenerMetrics::set_block_height(block_number.as_u64());

        for ep in self.entrypoint_event_broadcasts.keys() {
            block_events.insert(
                *ep,
                NewBlockEvent {
                    address: *ep,
                    hash: block_hash,
                    number: block_number,
                    events: vec![],
                },
            );
        }

        for log in block_with_logs.logs {
            let ep_address = log.address;
            if !block_events.contains_key(&ep_address) {
                error!("Received log for unknown entrypoint {ep_address:?}");
                continue;
            }

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

            block_events.entry(ep_address).and_modify(|e| {
                e.events.push(event);
            });
            EventListenerMetrics::increment_events_seen();
        }

        for (ep, block_event) in block_events {
            match self.entrypoint_event_broadcasts.get(&ep) {
                Some(broadcast) => {
                    // ignore sender errors, which can only happen if there are no receivers
                    let _ = broadcast.send(Arc::new(block_event));
                }
                None => {
                    error!("No broadcast channel for entry point: {:?}", ep);
                }
            }
        }

        Ok(())
    }

    fn backoff_time(&self) -> Duration {
        let mut rng = rand::thread_rng();
        let jitter = rng.gen_range(0..1000);
        let millis = cmp::min(MAX_BACKOFF_SECONDS, 2_u64.pow(self.backoff_idx)) * 1000 + jitter;
        Duration::from_millis(millis)
    }

    async fn sleep_or_shutdown(
        &mut self,
        shutdown_rx: &mut broadcast::Receiver<()>,
        duration: Duration,
    ) -> bool {
        select! {
            _ = sleep(duration) => {
                self.backoff_idx += 1;
                false
            },
            _ = shutdown_rx.recv() => {
                info!("Shutting down event listener");
                true
            }
        }
    }
}

struct EventListenerMetrics {}

impl EventListenerMetrics {
    fn set_block_height(block_height: u64) {
        metrics::gauge!("op_pool_event_listener_block_height", block_height as f64);
    }

    fn increment_blocks_seen() {
        metrics::increment_counter!("op_pool_event_listener_blocks_seen");
    }

    fn increment_provider_errors() {
        metrics::increment_counter!("op_pool_event_listener_provider_errors");
    }

    fn increment_block_handler_errors() {
        metrics::increment_counter!("op_pool_event_listener_block_handler_errors");
    }

    fn increment_events_seen() {
        metrics::increment_counter!("op_pool_event_listener_events_seen");
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use ethers::{
        abi::{encode, Token},
        contract::EthEvent,
        types::{Block, Log, H256, U256, U64},
    };
    use tokio::{
        join,
        sync::{broadcast, mpsc},
        task::JoinHandle,
    };

    use super::*;
    use crate::{
        common::contracts::i_entry_point::{IEntryPointEvents, UserOperationEventFilter},
        op_pool::event::{mock::MockBlockProviderFactory, BlockProviderError},
    };

    #[tokio::test]
    async fn start_stop() {
        let state = setup().await;
        teardown(state).await;
    }

    #[tokio::test]
    async fn single_block_no_logs() {
        let mut state = setup().await;

        // send a block to the listener
        state
            .tx
            .send(Ok(BlockWithLogs {
                block: Block {
                    hash: Some(H256::zero()),
                    number: Some(U64::zero()),
                    ..Default::default()
                },
                logs: vec![],
            }))
            .unwrap();

        // receive the block from the listener
        let block_event = state.events.recv().await.unwrap();
        assert_eq!(block_event.number, U64::zero());

        teardown(state).await;
    }

    #[tokio::test]
    async fn single_block_with_log() {
        let mut state = setup().await;
        let (event, log) = make_random_log(state.ep);

        // send a block to the listener
        state
            .tx
            .send(Ok(BlockWithLogs {
                block: Block {
                    hash: Some(H256::zero()),
                    number: Some(U64::zero()),
                    ..Default::default()
                },
                logs: vec![log],
            }))
            .unwrap();

        // receive the block from the listener
        let block_event = state.events.recv().await.unwrap();
        assert_eq!(block_event.number, U64::zero());
        assert_eq!(block_event.events.len(), 1);

        if let IEntryPointEvents::UserOperationEventFilter(block_event) =
            &block_event.events[0].contract_event
        {
            assert_eq!(block_event, &event);
        } else {
            panic!("wrong event type");
        }

        teardown(state).await;
    }

    #[tokio::test]
    async fn multile_blocks_with_log() {
        let mut state = setup().await;

        for n in 0..5 {
            // send a block to the listener
            let (event, log) = make_random_log(state.ep);
            let block_hash = H256::random();
            state
                .tx
                .send(Ok(BlockWithLogs {
                    block: Block {
                        hash: Some(block_hash),
                        number: Some(U64::from(n)),
                        ..Default::default()
                    },
                    logs: vec![log],
                }))
                .unwrap();

            // receive the block from the listener
            let block_event = state.events.recv().await.unwrap();
            assert_eq!(block_event.number, U64::from(n));
            assert_eq!(block_event.events.len(), 1);

            if let IEntryPointEvents::UserOperationEventFilter(block_event) =
                &block_event.events[0].contract_event
            {
                assert_eq!(block_event, &event);
            } else {
                panic!("wrong event type");
            }
        }

        teardown(state).await;
    }

    #[tokio::test]
    async fn reconnect_once() {
        let mut state = setup().await;

        // send an error to the listener
        state
            .tx
            .send(Err(BlockProviderError::ConnectionError(
                "error".to_string(),
            )))
            .unwrap();

        // wait for the listener to reconnect
        state.connection_event_rx.recv().await.unwrap();

        // send a block to the listener
        state
            .tx
            .send(Ok(BlockWithLogs {
                block: Block {
                    hash: Some(H256::zero()),
                    number: Some(U64::zero()),
                    ..Default::default()
                },
                logs: vec![],
            }))
            .unwrap();

        // receive the block from the listener
        let block_event = state.events.recv().await.unwrap();
        assert_eq!(block_event.number, U64::zero());

        teardown(state).await;
    }

    #[tokio::test]
    async fn reconnect_multiple() {
        let mut state = setup().await;

        state.set_fail_connection();
        // send an initial error to the listener, causing reconnect
        state
            .tx
            .send(Err(BlockProviderError::ConnectionError(
                "error".to_string(),
            )))
            .unwrap();

        // wait for the listener to reconnect 2 times, then allow through
        for _ in 0..2 {
            state.connection_event_rx.recv().await.unwrap();
        }
        state.unset_fail_connection();

        // wait for the listener to connect
        state.connection_event_rx.recv().await.unwrap();

        // send a block to the listener
        state
            .tx
            .send(Ok(BlockWithLogs {
                block: Block {
                    hash: Some(H256::zero()),
                    number: Some(U64::zero()),
                    ..Default::default()
                },
                logs: vec![],
            }))
            .unwrap();

        // receive the block from the listener
        let block_event = state.events.recv().await.unwrap();
        assert_eq!(block_event.number, U64::zero());

        teardown(state).await;
    }

    struct TestState {
        ep: Address,
        tx: broadcast::Sender<Result<BlockWithLogs, BlockProviderError>>,
        shutdown_tx: broadcast::Sender<()>,
        handle: JoinHandle<Result<(), anyhow::Error>>,
        events: broadcast::Receiver<Arc<NewBlockEvent>>,
        connection_event_rx: mpsc::Receiver<()>,
        should_fail_connection: Arc<AtomicBool>,
    }

    impl TestState {
        fn set_fail_connection(&self) {
            self.should_fail_connection.store(true, Ordering::SeqCst);
        }

        fn unset_fail_connection(&self) {
            self.should_fail_connection.store(false, Ordering::SeqCst);
        }
    }

    async fn setup() -> TestState {
        let (tx, rx) = broadcast::channel(100);
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let (connection_event_tx, mut connection_event_rx) = mpsc::channel(100);
        let should_fail_connection = Arc::new(AtomicBool::new(false));
        let factory =
            MockBlockProviderFactory::new(rx, connection_event_tx, should_fail_connection.clone());
        let ep = Address::random();
        let listener = EventListener::new(factory, vec![&ep]);
        let events = listener.subscribe_by_entrypoint(ep).unwrap();
        let handle = tokio::spawn(async move { listener.listen_with_shutdown(shutdown_rx).await });

        // wait for the listener to connect
        connection_event_rx.recv().await.unwrap();

        TestState {
            ep,
            tx,
            shutdown_tx,
            handle,
            events,
            connection_event_rx,
            should_fail_connection,
        }
    }

    async fn teardown(state: TestState) {
        // send a shutdown signal
        state.shutdown_tx.send(()).unwrap();
        // wait for the listener to shutdown
        join!(state.handle).0.unwrap().unwrap();
    }

    fn make_random_log(ep: Address) -> (UserOperationEventFilter, Log) {
        let hash = H256::random();
        let sender = Address::random();
        let paymaster = Address::random();

        // UserOperationEvent([INDEXED]bytes32,address,address,[NON_INDEXED]uint256,bool,uint256,uint256)
        let log = Log {
            address: ep,
            topics: vec![
                UserOperationEventFilter::signature(),
                hash,
                address_to_topic(sender),
                address_to_topic(paymaster),
            ],
            data: encode(&[
                Token::Uint(U256::zero()),
                Token::Bool(false),
                Token::Uint(U256::zero()),
                Token::Uint(U256::zero()),
            ])
            .into(),
            block_hash: Some(H256::zero()),
            block_number: Some(U64::zero()),
            transaction_hash: Some(H256::zero()),
            transaction_index: Some(U64::zero()),
            ..Default::default()
        };
        let event: UserOperationEventFilter = parse_log(log.clone()).unwrap();
        (event, log)
    }

    fn address_to_topic(src: Address) -> H256 {
        let mut bytes = [0; 32];
        bytes[12..32].copy_from_slice(src.as_bytes());
        H256::from(bytes)
    }
}
