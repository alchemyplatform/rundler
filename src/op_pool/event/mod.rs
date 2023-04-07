use std::sync::Arc;

use ethers::types::{Address, Block, Filter, Log, H256, U64};
use tokio::{sync::broadcast, task::JoinHandle};
use tonic::async_trait;

use crate::common::contracts::i_entry_point::IEntryPointEvents;

mod listener;
pub use listener::EventListener;
#[cfg(test)]
mod mock;
mod ws;
pub use ws::WsBlockProviderFactory;
mod http;
pub use http::HttpBlockProviderFactory;

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
    /// Ordered EntryPoint events
    pub events: Vec<EntryPointEvent>,
}

/// An event emitted by an entry point with metadata
#[derive(Debug)]
pub struct EntryPointEvent {
    /// The entry point contract event
    pub contract_event: IEntryPointEvents,
    /// The transaction hash that emitted the event
    pub txn_hash: H256,
    /// The transaction index that emitted the event
    pub txn_index: U64,
}

/// A trait that provides a stream of new blocks with thier events by entrypoint
pub trait EventProvider: Send + Sync {
    /// Subscribe to new blocks by entrypoint
    fn subscribe_by_entrypoint(
        &self,
        entry_point: Address,
    ) -> Option<broadcast::Receiver<Arc<NewBlockEvent>>>;

    /// Spawn the event provider
    fn spawn(
        self: Box<Self>,
        shutdown_rx: broadcast::Receiver<()>,
    ) -> JoinHandle<Result<(), anyhow::Error>>;
}

/// A factory that creates a new event provider
#[async_trait]
pub trait BlockProviderFactory: Send + Sync + 'static {
    type Provider: BlockProvider + Send + Sync + 'static;

    /// Create a new block provider
    fn new_provider(&self) -> Self::Provider;
}

/// Block provider errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum BlockProviderError {
    #[error("Connection error: {0}")]
    ConnectionError(String),
    #[error("Rpc error: {0}")]
    RpcError(String),
}

/// A block with its logs correspoinding to a filter
/// given to a block provider
#[derive(Debug, Clone)]
pub struct BlockWithLogs {
    /// The block
    block: Block<H256>,
    /// The logs that correspond to the filter
    logs: Vec<Log>,
}

/// A trait that provides a stream of blocks
#[async_trait]
pub trait BlockProvider {
    type BlockStream: tokio_stream::Stream<Item = Result<BlockWithLogs, BlockProviderError>>
        + Send
        + Unpin;

    /// Subscribe to a block stream
    async fn subscribe(&mut self, filter: Filter) -> Result<Self::BlockStream, BlockProviderError>;

    /// Unsubscribe from a block stream
    async fn unsubscribe(&mut self);
}
