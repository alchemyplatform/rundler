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

use alloy_primitives::{Address, B256, U256};
use futures_util::Stream;

use super::{
    error::PoolError,
    types::{
        NewHead, PaymasterMetadata, PoolOperation, PoolOperationStatus, Reputation,
        ReputationStatus, StakeStatus,
    },
};
use crate::{
    EntityUpdate, UserOperation, UserOperationId, UserOperationPermissions, UserOperationVariant,
};

/// Result type for pool server operations.
pub type PoolResult<T> = std::result::Result<T, PoolError>;

/// Summary of an operation in the pool
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolOperationSummary {
    /// Entry point of the operation
    pub entry_point: Address,
    /// Hash of the operation
    pub hash: B256,
    /// Sender of the operation
    pub sender: Address,
    /// Sim block number of the operation
    pub sim_block_number: u64,
    /// Max fee per gas of the operation
    pub max_fee_per_gas: u128,
    /// Max priority fee per gas of the operation
    pub max_priority_fee_per_gas: u128,
    /// Total gas limit the operation can consume
    pub gas_limit: u128,
    /// Maximum WEI the bundler will pay for this operation (None if not sponsored)
    pub bundler_sponsorship_max_cost: Option<U256>,
}

/// Pool server trait
#[async_trait::async_trait]
#[auto_impl::auto_impl(&, &mut, Rc, Arc, Box)]
pub trait Pool: Send + Sync {
    /// Get the supported entry points of the pool
    async fn get_supported_entry_points(&self) -> PoolResult<Vec<Address>>;

    /// Add an operation to the pool
    async fn add_op(
        &self,
        op: UserOperationVariant,
        perms: UserOperationPermissions,
    ) -> PoolResult<B256>;

    /// Get operations from the pool
    async fn get_ops(
        &self,
        entry_point: Address,
        max_ops: u64,
        filter_id: Option<String>,
    ) -> PoolResult<Vec<PoolOperation>>;

    /// Get summaries of operations from the pool
    async fn get_ops_summaries(
        &self,
        entry_point: Address,
        max_ops: u64,
        filter_id: Option<String>,
    ) -> PoolResult<Vec<PoolOperationSummary>>;

    /// Get operations from the pool by hashes
    async fn get_ops_by_hashes(
        &self,
        entry_point: Address,
        hashes: Vec<B256>,
    ) -> PoolResult<Vec<PoolOperation>>;

    /// Get an operation from the pool by hash
    /// Checks each entry point in order until the operation is found
    /// Returns None if the operation is not found
    async fn get_op_by_hash(&self, hash: B256) -> PoolResult<Option<PoolOperation>>;

    /// Get an operation from the pool by id
    async fn get_op_by_id(&self, id: UserOperationId) -> PoolResult<Option<PoolOperation>>;

    /// Remove operations from the pool by hash
    async fn remove_ops(&self, entry_point: Address, ops: Vec<B256>) -> PoolResult<()>;

    /// Remove an operation from the pool by id
    async fn remove_op_by_id(
        &self,
        entry_point: Address,
        id: UserOperationId,
    ) -> PoolResult<Option<B256>>;

    /// Get extended status for a user operation
    async fn get_op_status(&self, hash: B256) -> PoolResult<Option<PoolOperationStatus>>;

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
    async fn subscribe_new_heads(
        &self,
        to_track: Vec<Address>,
    ) -> PoolResult<Pin<Box<dyn Stream<Item = NewHead> + Send>>>;

    /// Notify the pool about a pending bundle transaction.
    /// Automatically replaces any existing pending bundle for the same builder.
    async fn notify_pending_bundle(
        &self,
        entry_point: Address,
        tx_hash: B256,
        sent_at_block: u64,
        builder_address: Address,
        uo_hashes: Vec<B256>,
    ) -> PoolResult<()>;

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

impl From<&PoolOperation> for PoolOperationSummary {
    fn from(op: &PoolOperation) -> Self {
        Self {
            entry_point: op.entry_point,
            hash: op.uo.hash(),
            sender: op.uo.sender(),
            sim_block_number: op.sim_block_number,
            max_fee_per_gas: op.uo.max_fee_per_gas(),
            max_priority_fee_per_gas: op.uo.max_priority_fee_per_gas(),
            gas_limit: op.uo.total_verification_gas_limit()
                + op.uo.call_gas_limit()
                + op.uo.pre_verification_gas(),
            bundler_sponsorship_max_cost: op.perms.bundler_sponsorship.as_ref().map(|s| s.max_cost),
        }
    }
}

#[cfg(feature = "test-utils")]
mockall::mock! {
    pub Pool {}

    #[async_trait::async_trait]
    impl Pool for Pool {
        async fn get_supported_entry_points(&self) -> PoolResult<Vec<Address>>;
        async fn add_op(
            &self,
            op: UserOperationVariant,
            perms: UserOperationPermissions,
        ) -> PoolResult<B256>;
        async fn get_ops(
            &self,
            entry_point: Address,
            max_ops: u64,
            filter_id: Option<String>,
        ) -> PoolResult<Vec<PoolOperation>>;
        async fn get_ops_summaries(
            &self,
            entry_point: Address,
            max_ops: u64,
            filter_id: Option<String>,
        ) -> PoolResult<Vec<PoolOperationSummary>>;
        async fn get_ops_by_hashes(
            &self,
            entry_point: Address,
            hashes: Vec<B256>,
        ) -> PoolResult<Vec<PoolOperation>>;
        async fn get_op_by_hash(&self, hash: B256) -> PoolResult<Option<PoolOperation>>;
        async fn get_op_by_id(&self, id: UserOperationId) -> PoolResult<Option<PoolOperation>>;
        async fn remove_ops(&self, entry_point: Address, ops: Vec<B256>) -> PoolResult<()>;
        async fn remove_op_by_id(
            &self,
            entry_point: Address,
            id: UserOperationId,
        ) -> PoolResult<Option<B256>>;
        async fn update_entities(
            &self,
            entry_point: Address,
            entities: Vec<EntityUpdate>,
        ) -> PoolResult<()>;
        async fn subscribe_new_heads(
            &self,
            to_track: Vec<Address>,
        ) -> PoolResult<Pin<Box<dyn Stream<Item = NewHead> + Send>>>;
        async fn get_reputation_status(
            &self,
            entry_point: Address,
            address: Address,
        ) -> PoolResult<ReputationStatus>;
        async fn get_stake_status(
            &self,
            entry_point: Address,
            address: Address,
        ) -> PoolResult<StakeStatus>;
        async fn admin_set_tracking(
            &self,
            entry_point: Address,
            paymaster: bool,
            reputation: bool,
        ) -> PoolResult<()>;
        async fn debug_clear_state(
            &self,
            clear_mempool: bool,
            clear_paymaster: bool,
            clear_reputation: bool,
        ) -> PoolResult<()>;
        async fn debug_dump_mempool(&self, entry_point: Address) -> PoolResult<Vec<PoolOperation>>;
        async fn debug_set_reputations(
            &self,
            entry_point: Address,
            reputations: Vec<Reputation>,
        ) -> PoolResult<()>;
        async fn debug_dump_reputation(&self, entry_point: Address) -> PoolResult<Vec<Reputation>>;
        async fn debug_dump_paymaster_balances(
            &self,
            entry_point: Address,
        ) -> PoolResult<Vec<PaymasterMetadata>>;
        async fn notify_pending_bundle(
            &self,
            entry_point: Address,
            tx_hash: B256,
            sent_at_block: u64,
            builder_address: Address,
            uo_hashes: Vec<B256>,
        ) -> PoolResult<()>;
        async fn get_op_status(&self, hash: B256) -> PoolResult<Option<PoolOperationStatus>>;
    }
}
