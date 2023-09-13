use std::{fmt::Display, str::FromStr};

use anyhow::bail;
use ethers::{types::Address, utils::to_checksum};
use parse_display::Display;
use serde::{ser::SerializeStruct, Deserialize, Serialize};
use strum::EnumIter;

/// The type of an entity
#[derive(Display, Debug, Clone, Ord, Copy, Eq, PartialEq, EnumIter, PartialOrd, Deserialize)]
#[display(style = "camelCase")]
#[serde(rename_all = "camelCase")]
pub enum EntityType {
    /// Account type
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
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct Entity {
    /// The tpe of entity
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
