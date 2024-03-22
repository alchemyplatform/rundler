// This file is part of Rundler.
//
// Rundler is free software: you can redistribute it and/or modify it under the
// terms of the GNU Lesser General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later version.
//
// Rundler is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with Rundler.
// If not, see https://www.gnu.org/licenses/.

use std::pin::Pin;

use ethers::types::{Address, H256};
use futures_util::Stream;
#[cfg(feature = "test-utils")]
use mockall::automock;

use super::{
    error::PoolError,
    types::{NewHead, PaymasterMetadata, PoolOperation, Reputation, ReputationStatus, StakeStatus},
};
use crate::{EntityUpdate, UserOperationId, UserOperationVariant};

/// Result type for pool server operations.
pub type PoolResult<T> = std::result::Result<T, PoolError>;

/// Pool server trait
#[cfg_attr(feature = "test-utils", automock)]
#[async_trait::async_trait]
pub trait Pool: Send + Sync + 'static {
    /// Get the supported entry points of the pool
    async fn get_supported_entry_points(&self) -> PoolResult<Vec<Address>>;

    /// Add an operation to the pool
    async fn add_op(&self, entry_point: Address, op: UserOperationVariant) -> PoolResult<H256>;

    /// Get operations from the pool
    async fn get_ops(
        &self,
        entry_point: Address,
        max_ops: u64,
        shard_index: u64,
    ) -> PoolResult<Vec<PoolOperation>>;

    /// Get an operation from the pool by hash
    /// Checks each entry point in order until the operation is found
    /// Returns None if the operation is not found
    async fn get_op_by_hash(&self, hash: H256) -> PoolResult<Option<PoolOperation>>;

    /// Remove operations from the pool by hash
    async fn remove_ops(&self, entry_point: Address, ops: Vec<H256>) -> PoolResult<()>;

    /// Remove an operation from the pool by id
    async fn remove_op_by_id(
        &self,
        entry_point: Address,
        id: UserOperationId,
    ) -> PoolResult<Option<H256>>;

    /// Update operations associated with entities from the pool
    async fn update_entities(
        &self,
        entry_point: Address,
        entities: Vec<EntityUpdate>,
    ) -> PoolResult<()>;

    /// Subscribe to new chain heads from the pool.
    ///
    /// The pool will notify the subscriber when a new chain head is received, and the pool
    /// has processed all operations up to that head.
    async fn subscribe_new_heads(&self) -> PoolResult<Pin<Box<dyn Stream<Item = NewHead> + Send>>>;

    /// Get reputation status given entrypoint and address
    async fn get_reputation_status(
        &self,
        entry_point: Address,
        address: Address,
    ) -> PoolResult<ReputationStatus>;

    /// Get stake status given entrypoint and address
    async fn get_stake_status(
        &self,
        entry_point: Address,
        address: Address,
    ) -> PoolResult<StakeStatus>;

    /// Clear the pool state, used for debug methods
    async fn debug_clear_state(
        &self,
        clear_mempool: bool,
        clear_paymaster: bool,
        clear_reputation: bool,
    ) -> PoolResult<()>;

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

    /// Dump paymaster balances, used for debug methods
    async fn debug_dump_paymaster_balances(
        &self,
        entry_point: Address,
    ) -> PoolResult<Vec<PaymasterMetadata>>;

    /// Controls whether or not the certain tracking data structures are used to block user operations
    async fn admin_set_tracking(
        &self,
        entry_point: Address,
        paymaster: bool,
        reputation: bool,
    ) -> PoolResult<()>;
}
