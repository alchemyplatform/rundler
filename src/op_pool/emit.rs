use std::{fmt::Display, sync::Arc};

use ethers::types::{Address, H256};

use crate::{
    common::{
        strs,
        types::{Entity, EntityType, Timestamp, UserOperation},
    },
    op_pool::mempool::OperationOrigin,
};

#[derive(Clone, Debug)]
pub enum OpPoolEvent {
    ReceivedOp {
        op_hash: H256,
        op: UserOperation,
        block_number: u64,
        origin: OperationOrigin,
        valid_after: Option<Timestamp>,
        valid_until: Option<Timestamp>,
        entities: EntitySummary,
        error: Option<Arc<String>>,
    },
    RemovedOp {
        op_hash: H256,
        reason: OpRemovalReason,
    },
    RemovedEntity {
        entity: Entity,
    },
}

#[derive(Clone, Debug, Default)]
pub struct EntitySummary {
    pub sender: EntityStatus,
    pub factory: Option<EntityStatus>,
    pub paymaster: Option<EntityStatus>,
    pub aggregator: Option<EntityStatus>,
}

#[derive(Clone, Debug, Default)]
pub struct EntityStatus {
    pub address: Address,
    pub reputation: EntityReputation,
}

#[derive(Clone, Debug, Default)]
pub enum EntityReputation {
    #[default]
    Ok,
    ThrottledButOk,
    ThrottledAndRejected,
    Banned,
}

#[derive(Clone, Debug)]
pub enum OpRemovalReason {
    Requested,
    Mined {
        block_number: u64,
        block_hash: H256,
        tx_hash: H256,
    },
    ThrottledAndOld {
        added_at_block_number: u64,
        current_block_number: u64,
    },
    EntityRemoved {
        entity: Entity,
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
                op_hash,
                entities,
                error,
                ..
            } => {
                let intro = strs::to_string_or(
                    error
                        .as_ref()
                        .map(|error| format!("Pool rejected op with error.    Error: {error}")),
                    "Pool accepted op.",
                );
                write!(
                    f,
                    concat!("{}", "    Op hash: {:?}", "{}", "{}", "{}", "{}",),
                    intro,
                    op_hash,
                    format_entity_status("Sender", Some(&entities.sender)),
                    format_entity_status("Factory", entities.factory.as_ref()),
                    format_entity_status("Paymaster", entities.paymaster.as_ref()),
                    format_entity_status("Aggregator", entities.aggregator.as_ref()),
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
        }
    }
}

fn format_entity_status(name: &str, status: Option<&EntityStatus>) -> String {
    strs::to_string_or_empty(status.map(|status| format!("    {name}: {:?}", status.address)))
}
