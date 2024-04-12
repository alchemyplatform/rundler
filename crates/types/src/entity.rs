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

use std::{fmt::Display, hash::Hash, str::FromStr};

use anyhow::bail;
use ethers::{types::Address, utils::to_checksum};
use parse_display::Display;
use serde::{ser::SerializeStruct, Deserialize, Serialize};
use strum::{EnumIter, IntoEnumIterator};

/// The type of an entity
#[derive(
    Display,
    Debug,
    Clone,
    Ord,
    Copy,
    Eq,
    PartialEq,
    EnumIter,
    PartialOrd,
    Deserialize,
    Hash,
    Serialize,
    Default,
)]
#[display(style = "camelCase")]
#[serde(rename_all = "camelCase")]
pub enum EntityType {
    /// Account type
    #[default]
    Account,
    /// Paymaster type
    Paymaster,
    /// Aggregator type
    Aggregator,
    /// Factory type
    Factory,
}

impl EntityType {
    /// Get the string representation of the entity type
    pub fn to_str(&self) -> &'static str {
        match self {
            EntityType::Account => "account",
            EntityType::Paymaster => "paymaster",
            EntityType::Aggregator => "aggregator",
            EntityType::Factory => "factory",
        }
    }
}

impl FromStr for EntityType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "account" => Ok(EntityType::Account),
            "paymaster" => Ok(EntityType::Paymaster),
            "aggregator" => Ok(EntityType::Aggregator),
            "factory" => Ok(EntityType::Factory),
            _ => bail!("Invalid entity type: {s}"),
        }
    }
}

/// An entity associated with a user operation
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Default)]
pub struct Entity {
    /// The type of entity
    pub kind: EntityType,
    /// The address of the entity
    pub address: Address,
}

impl Entity {
    /// Create a new entity of the given type and address
    pub fn new(kind: EntityType, address: Address) -> Self {
        Self { kind, address }
    }

    /// Create a new account entity at address
    pub fn account(address: Address) -> Self {
        Self::new(EntityType::Account, address)
    }

    /// Create a new paymaster entity at address
    pub fn paymaster(address: Address) -> Self {
        Self::new(EntityType::Paymaster, address)
    }

    /// Create a new aggregator entity at address
    pub fn aggregator(address: Address) -> Self {
        Self::new(EntityType::Aggregator, address)
    }

    /// Create a new factory entity at address
    pub fn factory(address: Address) -> Self {
        Self::new(EntityType::Factory, address)
    }
}

impl Display for Entity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{:?}", self.kind, to_checksum(&self.address, None))
    }
}

impl Serialize for Entity {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut e = serializer.serialize_struct("Entity", 1)?;
        e.serialize_field(self.kind.to_str(), &to_checksum(&self.address, None))?;
        e.end()
    }
}

/// Updates that can be applied to an entity
#[derive(Display, Debug, Clone, Ord, Copy, Eq, PartialEq, EnumIter, PartialOrd, Deserialize)]
#[display(style = "camelCase")]
#[serde(rename_all = "camelCase")]
pub enum EntityUpdateType {
    /// UREP-030
    UnstakedInvalidation,
    /// SREP-050
    StakedInvalidation,
}

impl TryFrom<i32> for EntityUpdateType {
    type Error = anyhow::Error;

    fn try_from(update_type: i32) -> Result<Self, Self::Error> {
        match update_type {
            x if x == EntityUpdateType::UnstakedInvalidation as i32 => {
                Ok(Self::UnstakedInvalidation)
            }
            x if x == EntityUpdateType::StakedInvalidation as i32 => Ok(Self::StakedInvalidation),
            _ => bail!("Invalid entity update type: {update_type}"),
        }
    }
}

/// A update that needs to be applied to an entity
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct EntityUpdate {
    /// The entity to update
    pub entity: Entity,
    /// The kind of update to perform for the entity
    pub update_type: EntityUpdateType,
}

/// additional context about an entity
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EntityInfo {
    /// The entity
    pub entity: Entity,
    /// Whether the entity is staked or not
    pub is_staked: bool,
}

impl EntityInfo {
    /// Create a new entity info
    pub fn new(entity: Entity, is_staked: bool) -> Self {
        Self { entity, is_staked }
    }

    /// Get the entity address
    pub fn address(self) -> Address {
        self.entity.address
    }

    /// Get the entity type
    pub fn kind(self) -> EntityType {
        self.entity.kind
    }

    /// Check if the entity is staked
    pub fn is_staked(self) -> bool {
        self.is_staked
    }
}

/// additional context for all the entities used in an op
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EntityInfos {
    /// The entity info for the factory
    pub factory: Option<EntityInfo>,
    /// The entity info for the op sender
    pub sender: EntityInfo,
    /// The entity info for the paymaster
    pub paymaster: Option<EntityInfo>,
    /// The entity info for the aggregator
    pub aggregator: Option<EntityInfo>,
}

impl EntityInfos {
    /// Get iterator over the entities
    pub fn entities(&'_ self) -> impl Iterator<Item = (EntityType, EntityInfo)> + '_ {
        EntityType::iter().filter_map(|t| self.get(t).map(|info| (t, info)))
    }

    /// Get the EntityInfo of a specific entity
    pub fn get(self, entity: EntityType) -> Option<EntityInfo> {
        match entity {
            EntityType::Factory => self.factory,
            EntityType::Account => Some(self.sender),
            EntityType::Paymaster => self.paymaster,
            EntityType::Aggregator => self.aggregator,
        }
    }

    /// Get the type of an entity from its address, if any
    pub fn type_from_address(self, address: Address) -> Option<EntityType> {
        if address.eq(&self.sender.entity.address) {
            return Some(EntityType::Account);
        }

        if let Some(factory) = self.factory {
            if address.eq(&factory.entity.address) {
                return Some(EntityType::Factory);
            }
        }

        if let Some(paymaster) = self.paymaster {
            if address.eq(&paymaster.entity.address) {
                return Some(EntityType::Paymaster);
            }
        }

        if let Some(aggregator) = self.aggregator {
            if address.eq(&aggregator.entity.address) {
                return Some(EntityType::Aggregator);
            }
        }

        None
    }

    /// Get the sender address
    pub fn sender_address(self) -> Address {
        self.sender.entity.address
    }

    /// Set the sender info
    pub fn set_sender(&mut self, addr: Address, is_staked: bool) {
        self.sender = EntityInfo {
            entity: Entity::account(addr),
            is_staked,
        };
    }

    /// Set the factory info
    pub fn set_factory(&mut self, addr: Address, is_staked: bool) {
        self.factory = Some(EntityInfo {
            entity: Entity::factory(addr),
            is_staked,
        });
    }

    /// Set the paymaster info
    pub fn set_paymaster(&mut self, addr: Address, is_staked: bool) {
        self.paymaster = Some(EntityInfo {
            entity: Entity::paymaster(addr),
            is_staked,
        });
    }

    /// Set the aggregator info
    pub fn set_aggregator(&mut self, addr: Address, is_staked: bool) {
        self.aggregator = Some(EntityInfo {
            entity: Entity::aggregator(addr),
            is_staked,
        });
    }
}
