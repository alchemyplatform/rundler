mod error;
mod local;
mod remote;

use std::pin::Pin;

use async_trait::async_trait;
pub use error::PoolServerError;
use ethers::types::{Address, H256};
use futures_util::Stream;
pub use local::{LocalPoolBuilder, LocalPoolHandle};
#[cfg(feature = "test-utils")]
use mockall::automock;
pub(crate) use remote::spawn_remote_mempool_server;
pub use remote::RemotePoolClient;
use rundler_types::{Entity, UserOperation};

use crate::mempool::{PoolOperation, Reputation};

/// Result type for pool server operations.
pub type PoolResult<T> = std::result::Result<T, PoolServerError>;

#[derive(Clone, Debug)]
pub struct NewHead {
    pub block_hash: H256,
    pub block_number: u64,
}

/// Pool server trait
#[cfg_attr(feature = "test-utils", automock)]
#[async_trait]
pub trait PoolServer: Send + Sync + 'static {
    /// Get the supported entry points of the pool
    async fn get_supported_entry_points(&self) -> PoolResult<Vec<Address>>;

    /// Add an operation to the pool
    async fn add_op(&self, entry_point: Address, op: UserOperation) -> PoolResult<H256>;

    /// Get operations from the pool
    async fn get_ops(
        &self,
        entry_point: Address,
        max_ops: u64,
        shard_index: u64,
    ) -> PoolResult<Vec<PoolOperation>>;

    /// Remove operations from the pool by hash
    async fn remove_ops(&self, entry_point: Address, ops: Vec<H256>) -> PoolResult<()>;

    /// Remove operations associated with entities from the pool
    async fn remove_entities(&self, entry_point: Address, entities: Vec<Entity>) -> PoolResult<()>;

    /// Subscribe to new chain heads from the pool.
    ///
    /// The pool will notify the subscriber when a new chain head is received, and the pool
    /// has processed all operations up to that head.
    async fn subscribe_new_heads(&self) -> PoolResult<Pin<Box<dyn Stream<Item = NewHead> + Send>>>;

    /// Clear the pool state, used for debug methods
    async fn debug_clear_state(&self) -> PoolResult<()>;

    /// Dump all operations in the pool, used for debug methods
    async fn debug_dump_mempool(&self, entry_point: Address) -> PoolResult<Vec<PoolOperation>>;

    /// Set reputations for entities, used for debug methods
    async fn debug_set_reputations(
        &self,
        entry_point: Address,
        reputations: Vec<Reputation>,
    ) -> PoolResult<()>;

    /// Dump reputations for entities, used for debug methods
    async fn debug_dump_reputation(&self, entry_point: Address) -> PoolResult<Vec<Reputation>>;
}
