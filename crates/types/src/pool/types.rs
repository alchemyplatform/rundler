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

use ethers::types::{Address, H256, U256};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    entity::EntityInfos, Entity, EntityType, StakeInfo, UserOperation, UserOperationVariant,
    ValidTimeRange,
};

/// The new head of the chain, as viewed by the pool
#[derive(Clone, Debug)]
pub struct NewHead {
    /// The hash of the new head
    pub block_hash: H256,
    /// The number of the new head
    pub block_number: u64,
}

impl Default for NewHead {
    fn default() -> NewHead {
        NewHead {
            block_hash: H256::zero(),
            block_number: 0,
        }
    }
}

/// The reputation of an entity
#[derive(Debug, Clone)]
pub struct Reputation {
    /// The entity's address
    pub address: Address,
    /// Number of ops seen in the current interval
    pub ops_seen: u64,
    /// Number of ops included in the current interval
    pub ops_included: u64,
}

/// Reputation status for an entity
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ReputationStatus {
    /// Entity is not throttled or banned
    Ok,
    /// Entity is throttled
    Throttled,
    /// Entity is banned
    Banned,
}

impl Serialize for ReputationStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            ReputationStatus::Ok => serializer.serialize_str("ok"),
            ReputationStatus::Throttled => serializer.serialize_str("throttled"),
            ReputationStatus::Banned => serializer.serialize_str("banned"),
        }
    }
}

impl<'de> Deserialize<'de> for ReputationStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "ok" => Ok(ReputationStatus::Ok),
            "throttled" => Ok(ReputationStatus::Throttled),
            "banned" => Ok(ReputationStatus::Banned),
            _ => Err(de::Error::custom(format!("Invalid reputation status {s}"))),
        }
    }
}

/// Stake status structure
#[derive(Debug, Clone, Copy)]
pub struct StakeStatus {
    /// Address is staked
    pub is_staked: bool,
    /// Stake information about address
    pub stake_info: StakeInfo,
}

/// The metadata for a paymaster
#[derive(Debug, Default, Clone, Eq, PartialEq, Copy)]
pub struct PaymasterMetadata {
    /// Paymaster address
    pub address: Address,
    /// The on-chain balance of the paymaster
    pub confirmed_balance: U256,
    /// The pending balance is the confirm balance subtracted by
    /// the max cost of all the pending user operations that use the paymaster  
    pub pending_balance: U256,
}

/// A user operation with additional metadata from validation.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PoolOperation {
    /// The user operation stored in the pool
    pub uo: UserOperationVariant,
    /// The entry point address for this operation
    pub entry_point: Address,
    /// The aggregator address for this operation, if any.
    pub aggregator: Option<Address>,
    /// The valid time range for this operation.
    pub valid_time_range: ValidTimeRange,
    /// The expected code hash for all contracts accessed during validation for this operation.
    pub expected_code_hash: H256,
    /// The block hash simulation was completed at
    pub sim_block_hash: H256,
    /// The block number simulation was completed at
    pub sim_block_number: u64,
    /// List of entities that need to stake for this operation.
    pub entities_needing_stake: Vec<EntityType>,
    /// Whether the account is staked.
    pub account_is_staked: bool,
    /// Staking information about all the entities.
    pub entity_infos: EntityInfos,
}

impl PoolOperation {
    /// Returns true if the operation contains the given entity.
    pub fn contains_entity(&self, entity: &Entity) -> bool {
        if let Some(e) = self.entity_infos.get(entity.kind) {
            e.address == entity.address
        } else {
            false
        }
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
    pub fn requires_stake(&self, entity: EntityType) -> bool {
        match entity {
            EntityType::Account => self.account_is_staked,
            _ => self.entities_needing_stake.contains(&entity),
        }
    }

    /// Returns an iterator over all entities that are included in this operation.
    pub fn entities(&'_ self) -> impl Iterator<Item = Entity> + '_ {
        self.entity_infos
            .entities()
            .map(|(t, entity)| Entity::new(t, entity.address))
    }

    /// Returns an iterator over all entities that need stake in this operation. This can be a subset of entities that are staked in the operation.
    pub fn entities_requiring_stake(&'_ self) -> impl Iterator<Item = Entity> + '_ {
        self.entity_infos.entities().filter_map(|(t, entity)| {
            if self.requires_stake(t) {
                Entity::new(t, entity.address).into()
            } else {
                None
            }
        })
    }

    /// Return all the unstaked entities that are used in this operation.
    pub fn unstaked_entities(&'_ self) -> impl Iterator<Item = Entity> + '_ {
        self.entity_infos.entities().filter_map(|(t, entity)| {
            if entity.is_staked {
                None
            } else {
                Entity::new(t, entity.address).into()
            }
        })
    }

    /// Compute the amount of heap memory the PoolOperation takes up.
    pub fn mem_size(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.uo.heap_size()
            + self.entities_needing_stake.len() * std::mem::size_of::<EntityType>()
    }
}
