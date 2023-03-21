pub mod error;
mod pool;
pub mod uo_pool;

use ethers::types::{Address, H256, U256};
use std::sync::Arc;
use strum::IntoEnumIterator;

use crate::common::types::ValidTimeRange;
use crate::common::{
    protos::op_pool::Reputation,
    types::{Entity, UserOperation},
};

use self::error::MempoolResult;

use super::events::NewBlockEvent;

/// In-memory operation pool
pub trait Mempool: Send + Sync {
    /// Returns the entry point address this pool targets.
    fn entry_point(&self) -> Address;

    /// Event listener for when a new block is mined.
    ///
    /// Pool is updated according to the new blocks events.
    fn on_new_block(&self, event: &NewBlockEvent);

    /// Adds a validated user operation to the pool.
    ///
    /// Adds a user operation to the pool that was submitted via a local
    /// RPC call and was validated before submission.
    fn add_operation(&self, origin: OperationOrigin, op: PoolOperation) -> MempoolResult<H256>;

    /// Adds multiple validated user operations to the pool.
    ///
    /// Adds multiple user operations to the pool that were discovered
    /// via the P2P gossip protocol.
    fn add_operations(
        &self,
        origin: OperationOrigin,
        operations: impl IntoIterator<Item = PoolOperation>,
    ) -> Vec<MempoolResult<H256>>;

    /// Removes a set of operations from the pool.
    fn remove_operations<'a>(&self, hashes: impl IntoIterator<Item = &'a H256>);

    /// Returns the best operations from the pool.
    ///
    /// Returns the best operations from the pool based on their gas bids up to
    /// the specified maximum number of operations.
    fn best_operations(&self, max: usize) -> Vec<Arc<PoolOperation>>;

    /// Debug methods

    /// Clears the mempool
    fn clear(&self);

    /// Dumps the mempool's reputation tracking
    fn dump_reputation(&self) -> Vec<Reputation>;

    /// Overwrites the mempool's reputation for an address
    fn set_reputation(&self, address: Address, ops_seen: u64, ops_included: u64);
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

// TODO(danc): remove this once PR #26 is merged
/// An expected storage slot value for a user operation during validation.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct ExpectedStorageSlot {
    pub address: Address,
    pub slot: U256,
    pub expected_value: Option<U256>,
}

/// A user operation with additional metadata from validation.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct PoolOperation {
    pub uo: UserOperation,
    pub aggregator: Option<Address>,
    pub valid_time_range: ValidTimeRange,
    pub expected_code_hash: H256,
    pub sim_block_hash: H256,
    pub entities_needing_stake: Vec<Entity>,
    pub expected_storage_slots: Vec<ExpectedStorageSlot>,
}

impl PoolOperation {
    /// Returns the address of the entity that is required to stake for this operation.
    pub fn entity_address(&self, entity: Entity) -> Option<Address> {
        match entity {
            Entity::Account => Some(self.uo.sender),
            Entity::Paymaster => self.uo.paymaster(),
            Entity::Factory => self.uo.factory(),
            Entity::Aggregator => self.aggregator,
        }
    }

    /// Returns true if the operation requires the given entity to stake.
    pub fn requires_stake(&self, entity: Entity) -> bool {
        self.entities_needing_stake.contains(&entity)
    }

    /// Returns an iterator over all entities that are included in this opearation.
    pub fn entities(&'_ self) -> impl Iterator<Item = (Entity, Address)> + '_ {
        Entity::iter()
            .filter_map(|entity| self.entity_address(entity).map(|address| (entity, address)))
    }
}

#[cfg(test)]
mod tests {
    use ethers::types::Bytes;

    use super::*;

    #[test]
    fn test_entities() {
        let sender = Address::random();
        let aggregator = Address::random();
        let paymaster = Address::random();
        let factory = Address::random();

        let po = PoolOperation {
            uo: UserOperation {
                sender,
                paymaster_and_data: Bytes::from(paymaster.as_fixed_bytes()),
                init_code: Bytes::from(factory.as_fixed_bytes()),
                ..Default::default()
            },
            aggregator: Some(aggregator),
            valid_time_range: ValidTimeRange::all_time(),
            expected_code_hash: H256::random(),
            sim_block_hash: H256::random(),
            entities_needing_stake: vec![Entity::Account, Entity::Aggregator],
            expected_storage_slots: vec![],
        };

        assert!(po.requires_stake(Entity::Account));
        assert!(!po.requires_stake(Entity::Paymaster));
        assert!(!po.requires_stake(Entity::Factory));
        assert!(po.requires_stake(Entity::Aggregator));

        assert_eq!(po.entity_address(Entity::Account), Some(sender));
        assert_eq!(po.entity_address(Entity::Paymaster), Some(paymaster));
        assert_eq!(po.entity_address(Entity::Factory), Some(factory));
        assert_eq!(po.entity_address(Entity::Aggregator), Some(aggregator));

        let entities = po.entities().collect::<Vec<_>>();
        assert_eq!(entities.len(), 4);
        for (entity, address) in entities {
            match entity {
                Entity::Account => assert_eq!(address, sender),
                Entity::Paymaster => assert_eq!(address, paymaster),
                Entity::Factory => assert_eq!(address, factory),
                Entity::Aggregator => assert_eq!(address, aggregator),
            }
        }
    }
}
