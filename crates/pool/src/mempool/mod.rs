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
    time::Duration,
};

use alloy_primitives::{Address, B256};
#[cfg(test)]
use mockall::automock;
use rundler_sim::{MempoolConfig, PrecheckSettings, SimulationSettings};
use rundler_types::{
    chain::ChainSpec,
    pool::{
        MempoolError, PaymasterMetadata, PoolOperation, PreconfInfo, Reputation, ReputationStatus,
        StakeStatus,
    },
    EntityUpdate, EntryPointVersion, UserOperationId, UserOperationPermissions,
    UserOperationVariant,
};
use tonic::async_trait;
pub(crate) use uo_pool::{UoPool, UoPoolProviders};

use super::chain::ChainUpdate;

pub(crate) type MempoolResult<T> = std::result::Result<T, MempoolError>;

#[cfg_attr(test, automock)]
#[async_trait]
/// In-memory operation pool
pub(crate) trait Mempool: Send + Sync {
    /// Call to update the mempool with a new chain update
    async fn on_chain_update(&self, update: &ChainUpdate);

    /// Returns the entry point version this pool targets.
    fn entry_point_version(&self) -> EntryPointVersion;

    /// Adds a user operation to the pool
    async fn add_operation(
        &self,
        origin: OperationOrigin,
        op: UserOperationVariant,
        perms: UserOperationPermissions,
    ) -> MempoolResult<B256>;

    /// Removes a set of operations from the pool.
    fn remove_operations(&self, hashes: &[B256]);

    /// Removes an operation from the pool by its ID.
    fn remove_op_by_id(&self, id: &UserOperationId) -> MempoolResult<Option<B256>>;

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
    ///
    /// The `filter_id` is used to identify the filter that the operations belong to.
    /// If the `filter_id` does not exist, the call will error.
    fn best_operations(
        &self,
        max: usize,
        filter_id: Option<String>,
    ) -> MempoolResult<Vec<Arc<PoolOperation>>>;

    /// Returns the all operations from the pool up to a max size
    fn all_operations(&self, max: usize) -> Vec<Arc<PoolOperation>>;

    /// Looks up a user operation by hash, returns None if not found
    fn get_user_operation_by_hash(
        &self,
        hash: B256,
    ) -> (Option<Arc<PoolOperation>>, Option<PreconfInfo>);

    /// Looks up a user operation by id, returns None if not found
    fn get_op_by_id(&self, id: &UserOperationId) -> Option<Arc<PoolOperation>>;

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
    /// Chain specification
    pub chain_spec: ChainSpec,
    /// Address of the entry point this pool targets
    pub entry_point: Address,
    /// Version of the entry point this pool targets
    pub entry_point_version: EntryPointVersion,
    /// The maximum number of operations an unstaked sender can have in the mempool
    pub same_sender_mempool_count: usize,
    /// The minimum fee bump required to replace an operation in the mempool
    /// Applies to both priority fee and fee. Expressed as an integer percentage value
    pub min_replacement_fee_increase_percentage: u32,
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
    pub mempool_channel_configs: HashMap<B256, MempoolConfig>,
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
    /// Boolean field used to toggle the operation of the DA tracker
    pub da_gas_tracking_enabled: bool,
    /// The minimum number of blocks a user operation must be in the mempool before it can be dropped
    pub drop_min_num_blocks: u64,
    /// Reject user operations with gas limit efficiency below this threshold.
    /// Gas limit efficiency is defined as the ratio of the gas limit to the gas used.
    /// This applies to the execution gas limit.
    pub execution_gas_limit_efficiency_reject_threshold: f64,
    /// Reject user operations with gas limit efficiency below this threshold.
    /// Gas limit efficiency is defined as the ratio of the gas limit to the gas used.
    /// This applies to the verification gas limit.
    pub verification_gas_limit_efficiency_reject_threshold: f64,
    /// Maximum time a UO is allowed in the pool before being dropped
    pub max_time_in_pool: Option<Duration>,
    /// The maximum number of storage slots that can be expected to be used by a user operation during validation
    pub max_expected_storage_slots: usize,
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
        v0_6::{UserOperationBuilder, UserOperationRequiredFields},
        Entity, EntityInfo, EntityInfos, EntityType, ValidTimeRange,
    };

    use super::*;

    #[test]
    fn test_entities() {
        let sender = Address::random();
        let aggregator = Address::random();
        let paymaster = Address::random();
        let factory = Address::random();

        let po = PoolOperation {
            uo: UserOperationBuilder::new(
                &ChainSpec::default(),
                UserOperationRequiredFields {
                    sender,
                    paymaster_and_data: paymaster.to_vec().into(),
                    init_code: factory.to_vec().into(),
                    ..Default::default()
                },
            )
            .build()
            .into(),
            entry_point: Address::random(),
            aggregator: Some(aggregator),
            valid_time_range: ValidTimeRange::all_time(),
            expected_code_hash: B256::random(),
            sim_block_hash: B256::random(),
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
            da_gas_data: Default::default(),
            filter_id: None,
            perms: UserOperationPermissions::default(),
            sender_is_7702: false,
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
