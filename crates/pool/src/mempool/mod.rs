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

mod entity_tracker;
mod pool;

mod reputation;
pub(crate) use reputation::{AddressReputation, ReputationParams};

mod size;

mod paymaster;
pub(crate) use paymaster::{PaymasterConfig, PaymasterTracker};

mod uo_pool;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use ethers::types::{Address, H256};
#[cfg(test)]
use mockall::automock;
use rundler_sim::{MempoolConfig, PrecheckSettings, SimulationSettings};
use rundler_types::{
    pool::{
        MempoolError, PaymasterMetadata, PoolOperation, Reputation, ReputationStatus, StakeStatus,
    },
    EntityUpdate, EntryPointVersion, UserOperationId, UserOperationVariant,
};
use tonic::async_trait;
pub(crate) use uo_pool::UoPool;

use super::chain::ChainUpdate;

pub(crate) type MempoolResult<T> = std::result::Result<T, MempoolError>;

#[cfg_attr(test, automock)]
#[async_trait]
/// In-memory operation pool
pub trait Mempool: Send + Sync + 'static {
    /// Call to update the mempool with a new chain update
    async fn on_chain_update(&self, update: &ChainUpdate);

    /// Returns the entry point address this pool targets.
    fn entry_point(&self) -> Address;

    /// Returns the entry point version this pool targets.
    fn entry_point_version(&self) -> EntryPointVersion;

    /// Adds a user operation to the pool
    async fn add_operation(
        &self,
        origin: OperationOrigin,
        op: UserOperationVariant,
    ) -> MempoolResult<H256>;

    /// Removes a set of operations from the pool.
    fn remove_operations(&self, hashes: &[H256]);

    /// Removes an operation from the pool by its ID.
    fn remove_op_by_id(&self, id: &UserOperationId) -> MempoolResult<Option<H256>>;

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

    /// Looks up a user operation by hash, returns None if not found
    fn get_user_operation_by_hash(&self, hash: H256) -> Option<Arc<PoolOperation>>;

    /// Debug methods

    /// Clears the mempool of UOs or reputation of all addresses
    fn clear_state(&self, clear_mempool: bool, clear_paymaster: bool, clear_reputation: bool);

    /// Dumps the mempool's reputation tracking
    fn dump_reputation(&self) -> Vec<Reputation>;

    /// Dumps the mempool's paymaster balance cache
    fn dump_paymaster_balances(&self) -> Vec<PaymasterMetadata>;

    /// Dumps the mempool's reputation tracking
    fn get_reputation_status(&self, address: Address) -> ReputationStatus;

    /// Overwrites the mempool's reputation for an address
    fn set_reputation(&self, address: Address, ops_seen: u64, ops_included: u64);

    /// Get stake status for address
    async fn get_stake_status(&self, address: Address) -> MempoolResult<StakeStatus>;

    /// Reset paymaster state
    async fn reset_confirmed_paymaster_balances(&self) -> MempoolResult<()>;

    /// Turns on and off tracking errors
    fn set_tracking(&self, paymaster: bool, reputation: bool);
}

/// Config for the mempool
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Address of the entry point this pool targets
    pub entry_point: Address,
    /// Version of the entry point this pool targets
    pub entry_point_version: EntryPointVersion,
    /// Chain ID this pool targets
    pub chain_id: u64,
    /// The maximum number of operations an unstaked sender can have in the mempool
    pub same_sender_mempool_count: usize,
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
    /// the maximum number of user operations with a throttled entity that can stay in the mempool
    pub throttled_entity_mempool_count: u64,
    /// The maximum number of blocks a user operation with a throttled entity can stay in the mempool
    pub throttled_entity_live_blocks: u64,
    /// Boolean field used to toggle the operation of the paymaster tracker
    pub paymaster_tracking_enabled: bool,
    /// Number of paymaster balances to cache
    pub paymaster_cache_length: u32,
    /// Boolean field used to toggle the operation of the reputation tracker
    pub reputation_tracking_enabled: bool,
    /// The minimum number of blocks a user operation must be in the mempool before it can be dropped
    pub drop_min_num_blocks: u64,
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

#[cfg(test)]
mod tests {
    use rundler_types::{
        v0_6::UserOperation, Entity, EntityInfo, EntityInfos, EntityType, ValidTimeRange,
    };

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
            }
            .into(),
            entry_point: Address::random(),
            aggregator: Some(aggregator),
            valid_time_range: ValidTimeRange::all_time(),
            expected_code_hash: H256::random(),
            sim_block_hash: H256::random(),
            sim_block_number: 0,
            account_is_staked: true,
            entity_infos: EntityInfos {
                factory: Some(EntityInfo {
                    entity: Entity::factory(factory),
                    is_staked: false,
                }),
                sender: EntityInfo {
                    entity: Entity::account(sender),
                    is_staked: false,
                },
                paymaster: Some(EntityInfo {
                    entity: Entity::paymaster(paymaster),
                    is_staked: false,
                }),
                aggregator: Some(EntityInfo {
                    entity: Entity::aggregator(aggregator),
                    is_staked: false,
                }),
            },
        };

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
