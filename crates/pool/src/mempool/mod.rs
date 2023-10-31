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

mod error;
pub use error::MempoolError;

mod pool;

mod reputation;
pub(crate) use reputation::{HourlyMovingAverageReputation, ReputationParams};
pub use reputation::{Reputation, ReputationStatus};

mod size;

mod uo_pool;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use ethers::types::{Address, H256};
#[cfg(test)]
use mockall::automock;
use rundler_sim::{MempoolConfig, PrecheckSettings, SimulationSettings};
use rundler_types::{Entity, EntityType, EntityUpdate, UserOperation, ValidTimeRange};
use strum::IntoEnumIterator;
use tonic::async_trait;
pub(crate) use uo_pool::UoPool;

use self::error::MempoolResult;
use super::chain::ChainUpdate;

#[cfg_attr(test, automock)]
#[async_trait]
/// In-memory operation pool
pub trait Mempool: Send + Sync + 'static {
    /// Call to update the mempool with a new chain update
    fn on_chain_update(&self, update: &ChainUpdate);

    /// Returns the entry point address this pool targets.
    fn entry_point(&self) -> Address;

    /// Adds a user operation to the pool
    async fn add_operation(
        &self,
        origin: OperationOrigin,
        op: UserOperation,
    ) -> MempoolResult<H256>;

    /// Removes a set of operations from the pool.
    fn remove_operations(&self, hashes: &[H256]);

    /// Removes all operations associated with a given entity from the pool.
    fn remove_entity(&self, entity: Entity);

    /// Updates the reputation of an entity.
    fn update_entity(&self, entity_update: EntityUpdate);

    /// Returns the best operations from the pool.
    ///
    /// Returns the best operations from the pool based on their gas bids up to
    /// the specified maximum number of operations, limiting to one per sender.
    ///
    /// The `shard_index` is used to divide the mempool into disjoint shards to ensure
    /// that two bundle builders don't attempt to but bundle the same operations. If
    /// the supplied `shard_index` does not exist, the call will error.
    fn best_operations(
        &self,
        max: usize,
        shard_index: u64,
    ) -> MempoolResult<Vec<Arc<PoolOperation>>>;

    /// Returns the all operations from the pool up to a max size
    fn all_operations(&self, max: usize) -> Vec<Arc<PoolOperation>>;

    /// Debug methods

    /// Clears the mempool
    fn clear(&self);

    /// Dumps the mempool's reputation tracking
    fn dump_reputation(&self) -> Vec<Reputation>;

    /// Overwrites the mempool's reputation for an address
    fn set_reputation(&self, address: Address, ops_seen: u64, ops_included: u64);
}

/// Config for the mempool
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Address of the entry point this pool targets
    pub entry_point: Address,
    /// Chain ID this pool targets
    pub chain_id: u64,
    /// The maximum number of operations an unstaked sender can have in the mempool
    pub max_userops_per_sender: usize,
    /// The minimum fee bump required to replace an operation in the mempool
    /// Applies to both priority fee and fee. Expressed as an integer percentage value
    pub min_replacement_fee_increase_percentage: u64,
    /// After this threshold is met, we will start to drop the worst userops from the mempool
    pub max_size_of_pool_bytes: usize,
    /// Operations that are always banned from the mempool
    pub blocklist: Option<HashSet<Address>>,
    /// Operations that are always allowed in the mempool, regardless of reputation
    pub allowlist: Option<HashSet<Address>>,
    /// Settings for precheck validation
    pub precheck_settings: PrecheckSettings,
    /// Settings for simulation validation
    pub sim_settings: SimulationSettings,
    /// Configuration for the mempool channels, by channel ID
    pub mempool_channel_configs: HashMap<H256, MempoolConfig>,
    /// Number of mempool shards to use. A mempool shard is a disjoint subset of the mempool
    /// that is used to ensure that two bundle builders don't attempt to but bundle the same
    /// operations. The mempool is divided into shards by taking the hash of the operation
    /// and modding it by the number of shards.
    pub num_shards: u64,
}

/// Origin of an operation.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // TODO(danc): remove once implemented
pub enum OperationOrigin {
    /// The operation was submitted via a local RPC call.
    Local,
    /// The operation was discovered via the P2P gossip protocol.
    External,
    /// The operation was returned to the pool when the block it was in was
    /// reorged away.
    ReturnedAfterReorg,
}

/// A user operation with additional metadata from validation.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct PoolOperation {
    /// The user operation stored in the pool
    pub uo: UserOperation,
    /// The aggregator address for this operation, if any.
    pub aggregator: Option<Address>,
    /// The valid time range for this operation.
    pub valid_time_range: ValidTimeRange,
    /// The expected code hash for all contracts accessed during validation for this operation.
    pub expected_code_hash: H256,
    /// The block hash simulation was completed at
    pub sim_block_hash: H256,
    /// List of entities that need to stake for this operation.
    pub entities_needing_stake: Vec<EntityType>,
    /// Whether the account is staked.
    pub account_is_staked: bool,
}

impl PoolOperation {
    /// Returns true if the operation contains the given entity.
    pub fn contains_entity(&self, entity: &Entity) -> bool {
        self.entity_address(entity.kind)
            .map(|address| address == entity.address)
            .unwrap_or(false)
    }

    /// Returns true if the operation requires the given entity to stake.
    ///
    /// For non-accounts, its possible that the entity is staked, but doesn't
    /// _need_ to stake for this operation. For example, if the operation does not
    /// access any storage slots that require staking. In that case this function
    /// will return false.
    ///
    /// For staked accounts, this function will always return true. Staked accounts
    /// are able to circumvent the mempool operation limits always need their reputation
    /// checked to prevent them from filling the pool.
    pub fn is_staked(&self, entity: EntityType) -> bool {
        match entity {
            EntityType::Account => self.account_is_staked,
            _ => self.entities_needing_stake.contains(&entity),
        }
    }

    /// Returns an iterator over all entities that are included in this operation.
    pub fn entities(&'_ self) -> impl Iterator<Item = Entity> + '_ {
        EntityType::iter().filter_map(|entity| {
            self.entity_address(entity)
                .map(|address| Entity::new(entity, address))
        })
    }

    /// Returns an iterator over all staked entities that are included in this operation.
    pub fn staked_entities(&'_ self) -> impl Iterator<Item = Entity> + '_ {
        EntityType::iter()
            .filter(|entity| self.is_staked(*entity))
            .filter_map(|entity| {
                self.entity_address(entity)
                    .map(|address| Entity::new(entity, address))
            })
    }

    /// Compute the amount of heap memory the PoolOperation takes up.
    pub fn mem_size(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.uo.heap_size()
            + self.entities_needing_stake.len() * std::mem::size_of::<EntityType>()
    }

    fn entity_address(&self, entity: EntityType) -> Option<Address> {
        match entity {
            EntityType::Account => Some(self.uo.sender),
            EntityType::Paymaster => self.uo.paymaster(),
            EntityType::Factory => self.uo.factory(),
            EntityType::Aggregator => self.aggregator,
        }
    }
}

#[cfg(test)]
mod tests {
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
                paymaster_and_data: paymaster.as_fixed_bytes().into(),
                init_code: factory.as_fixed_bytes().into(),
                ..Default::default()
            },
            aggregator: Some(aggregator),
            valid_time_range: ValidTimeRange::all_time(),
            expected_code_hash: H256::random(),
            sim_block_hash: H256::random(),
            entities_needing_stake: vec![EntityType::Account, EntityType::Aggregator],
            account_is_staked: true,
        };

        assert!(po.is_staked(EntityType::Account));
        assert!(!po.is_staked(EntityType::Paymaster));
        assert!(!po.is_staked(EntityType::Factory));
        assert!(po.is_staked(EntityType::Aggregator));

        assert_eq!(po.entity_address(EntityType::Account), Some(sender));
        assert_eq!(po.entity_address(EntityType::Paymaster), Some(paymaster));
        assert_eq!(po.entity_address(EntityType::Factory), Some(factory));
        assert_eq!(po.entity_address(EntityType::Aggregator), Some(aggregator));

        let entities = po.entities().collect::<Vec<_>>();
        assert_eq!(entities.len(), 4);
        for e in entities {
            match e.kind {
                EntityType::Account => assert_eq!(e.address, sender),
                EntityType::Paymaster => assert_eq!(e.address, paymaster),
                EntityType::Factory => assert_eq!(e.address, factory),
                EntityType::Aggregator => assert_eq!(e.address, aggregator),
            }
        }
    }
}
