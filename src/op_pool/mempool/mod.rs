mod pool;
pub mod uo_pool;

use ethers::types::{Address, H256, U256, U64};
use std::sync::Arc;

use crate::common::types::UserOperation;

/// In-memory operation pool
pub trait Mempool {
    /// Returns the entry point address this pool targets.
    fn entry_point(&self) -> Address;

    /// Event listener for when a new block is mined.
    ///
    /// Pool is updated according to the new blocks events.
    fn on_new_block(&self, event: OnNewBlockEvent);

    /// Event listener for when a user operation event is received.
    ///
    /// Pool is updated according to the new operation event.
    fn on_user_operation_event(&self, event: OnUserOperationEvent);

    /// Adds a validated user operation to the pool.
    ///
    /// Adds a user operation to the pool that was submitted via a local
    /// RPC call and was validated before submission.
    fn add_operation(
        &self,
        origin: OperationOrigin,
        operation: UserOperation,
    ) -> anyhow::Result<H256>;

    /// Adds multiple validated user operations to the pool.
    ///
    /// Adds multiple user operations to the pool that were discovered
    /// via the P2P gossip protocol.
    fn add_operations(
        &self,
        origin: OperationOrigin,
        operations: impl IntoIterator<Item = UserOperation>,
    ) -> Vec<anyhow::Result<H256>>;

    /// Removes a set of operations from the pool.
    fn remove_operations<'a>(&self, hashes: impl IntoIterator<Item = &'a H256>);

    /// Returns the best operations from the pool.
    ///
    /// Returns the best operations from the pool based on their gas bids up to
    /// the specified maximum number of operations.
    fn best_operations(&self, max: usize) -> Vec<Arc<UserOperation>>;

    /// Clears the mempool
    fn clear(&self);
}

/// Event when a new block is mined.
#[derive(Debug)]
pub struct OnNewBlockEvent {
    /// The block hash
    pub block_hash: H256,
    /// The block number
    pub block_number: U64,
    /// The next base fee
    pub next_base_fee: U256,
}

/// Event when a user operation event is received.
#[derive(Debug)]
pub struct OnUserOperationEvent {
    /// The operation hash
    pub op_hash: H256,
    /// The operation sender
    pub sender: Address,
    /// The operation nonce
    pub nonce: U256,
}

/// Origin of an operation.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // TODO(danc): remove once implemented
pub enum OperationOrigin {
    /// The operation was submitted via a local RPC call.
    Local,
    /// The operation was discovered via the P2P gossip protocol.
    External,
}
