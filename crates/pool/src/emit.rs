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

use std::fmt::Display;

use ethers::types::{Address, H256};
use rundler_types::{Entity, EntityType, Timestamp, UserOperation, UserOperationVariant};
use rundler_utils::strs;

use crate::mempool::OperationOrigin;

/// Event type for the pool
#[derive(Clone, Debug)]
pub enum OpPoolEvent {
    /// An operation was received and added to the pool
    ReceivedOp {
        /// Operation hash
        op_hash: H256,
        /// The full operation
        op: UserOperationVariant,
        /// Block number the operation was added to the pool
        block_number: u64,
        /// Operation origin
        origin: OperationOrigin,
        /// Operation valid after timestamp
        valid_after: Timestamp,
        /// Operation valid until timestamp
        valid_until: Timestamp,
        /// Operation entities
        entities: EntitySummary,
    },
    /// An operation was removed from the pool
    RemovedOp {
        /// Operation hash
        op_hash: H256,
        /// Removal reason
        reason: OpRemovalReason,
    },
    /// All operations for an entity were removed from the pool
    RemovedEntity {
        /// The removed entity
        entity: Entity,
    },
    /// An Entity was throttled
    ThrottledEntity {
        /// The throttled entity
        entity: Entity,
    },
}

/// Summary of the entities associated with an operation
#[derive(Clone, Debug, Default)]
pub struct EntitySummary {
    /// Sender entity status
    pub sender: EntityStatus,
    /// Factory entity status, if any
    pub factory: Option<EntityStatus>,
    /// Paymaster entity status, if any
    pub paymaster: Option<EntityStatus>,
    /// Aggregator entity status, if any
    pub aggregator: Option<EntityStatus>,
}

/// Status of an entity
#[derive(Clone, Debug, Default)]
pub struct EntityStatus {
    /// Address of the entity
    pub address: Address,
    /// Entity reputation
    pub reputation: EntityReputation,
}

/// Reputation of an entity
#[derive(Clone, Debug, Default)]
pub enum EntityReputation {
    #[default]
    Ok,
    ThrottledButOk,
    ThrottledAndRejected,
    Banned,
}

/// Reason an operation was removed from the pool
#[derive(Clone, Debug)]
pub enum OpRemovalReason {
    /// Removal was requested
    Requested,
    /// Op was mined
    Mined {
        /// Mined at block number
        block_number: u64,
        /// Mined at block hash
        block_hash: H256,
        /// Mined in transaction hash
        tx_hash: H256,
    },
    /// Op was associated with a throttled entity and was removed
    /// because it was too old
    ThrottledAndOld {
        /// Op added at block number
        added_at_block_number: u64,
        /// Op removed at block number
        current_block_number: u64,
    },
    /// Op was removed because an associated entity had all of its
    /// ops removed
    EntityRemoved {
        /// The removed entity
        entity: Entity,
    },
    /// Op was removed because an associated entity was throttled
    EntityThrottled {
        /// The throttled entity
        entity: Entity,
    },
    /// Op was removed because it expired
    Expired {
        /// Op was valid until this timestamp
        valid_until: Timestamp,
    },
}

impl EntitySummary {
    pub fn set_status(&mut self, kind: EntityType, status: EntityStatus) {
        match kind {
            EntityType::Account => self.sender = status,
            EntityType::Paymaster => self.paymaster = Some(status),
            EntityType::Aggregator => self.aggregator = Some(status),
            EntityType::Factory => self.factory = Some(status),
        };
    }
}

impl Display for OpPoolEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpPoolEvent::ReceivedOp {
                op,
                op_hash,
                entities,
                ..
            } => {
                write!(
                    f,
                    concat!(
                        "Pool accepted op.",
                        "    Op hash: {:?}",
                        "{}",
                        "{}",
                        "{}",
                        "{}",
                        "    maxFeePerGas: {}",
                        "    maxPriorityFeePerGas: {}"
                    ),
                    op_hash,
                    format_entity_status("Sender", Some(&entities.sender)),
                    format_entity_status("Factory", entities.factory.as_ref()),
                    format_entity_status("Paymaster", entities.paymaster.as_ref()),
                    format_entity_status("Aggregator", entities.aggregator.as_ref()),
                    op.max_fee_per_gas(),
                    op.max_priority_fee_per_gas(),
                )
            }
            OpPoolEvent::RemovedOp { op_hash, reason } => {
                write!(
                    f,
                    concat!(
                        "Removed op from pool.",
                        "    Op hash: {:?}",
                        "    Reason: {:?}",
                    ),
                    op_hash, reason,
                )
            }
            OpPoolEvent::RemovedEntity { entity } => {
                write!(
                    f,
                    concat!("Removed entity from pool.", "    Entity: {}",),
                    entity,
                )
            }
            OpPoolEvent::ThrottledEntity { entity } => {
                write!(f, concat!("Throttled entity.", "    Entity: {}",), entity,)
            }
        }
    }
}

fn format_entity_status(name: &str, status: Option<&EntityStatus>) -> String {
    strs::to_string_or_empty(status.map(|status| format!("    {name}: {:?}", status.address)))
}
