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

use alloy_primitives::{Address, B256, U256};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    da::DAGasData, entity::EntityInfos, Entity, EntityType, StakeInfo, UserOperation,
    UserOperationPermissions, UserOperationVariant, ValidTimeRange,
};

/// The new head of the chain, as viewed by the pool
#[derive(Clone, Debug, Default)]
pub struct NewHead {
    /// The hash of the new head
    pub block_hash: B256,
    /// The number of the new head
    pub block_number: u64,
    /// The updates to the state of the addresses
    pub address_updates: Vec<AddressUpdate>,
}

/// An the state of an address
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AddressUpdate {
    /// The address being tracked
    pub address: Address,
    /// The balance for the address
    pub balance: U256,
    /// Maybe a new nonce for the address
    pub nonce: Option<u64>,
    /// Mined transaction hashes
    pub mined_tx_hashes: Vec<B256>,
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
    pub expected_code_hash: B256,
    /// The block hash simulation was completed at
    pub sim_block_hash: B256,
    /// The block number simulation was completed at
    pub sim_block_number: u64,
    /// Whether the account is staked.
    pub account_is_staked: bool,
    /// Staking information about all the entities.
    pub entity_infos: EntityInfos,
    /// The DA gas data for this operation
    pub da_gas_data: DAGasData,
    /// The matched filter ID for this operation
    pub filter_id: Option<String>,
    /// Permissions for this operation
    pub perms: UserOperationPermissions,
}

/// The preconfirmed information for an user operation
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PreconfInfo {
    /// The hash of the preconfirmed transaction
    pub tx_hash: B256,
}

impl PoolOperation {
    /// Returns true if the operation contains the given entity.
    pub fn contains_entity(&self, entity: &Entity) -> bool {
        if let Some(ei) = self.entity_infos.get(entity.kind) {
            ei.entity.address == entity.address
        } else {
            false
        }
    }

    /// Returns an iterator over all entities that are included in this operation.
    pub fn entities(&'_ self) -> impl Iterator<Item = Entity> + '_ {
        self.entity_infos
            .entities()
            .map(|(t, ei)| Entity::new(t, ei.entity.address))
    }

    /// Return all the unstaked entities that are used in this operation.
    pub fn unstaked_entities(&'_ self) -> impl Iterator<Item = Entity> + '_ {
        self.entity_infos.entities().filter_map(|(t, ei)| {
            if ei.is_staked || ei.kind() == EntityType::Aggregator {
                None
            } else {
                Entity::new(t, ei.entity.address).into()
            }
        })
    }

    /// Compute the amount of heap memory the PoolOperation takes up.
    pub fn mem_size(&self) -> usize {
        std::mem::size_of::<Self>() + self.uo.heap_size()
    }
}
