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

use std::collections::{BTreeSet, HashMap, HashSet};

use anyhow::Error;
use ethers::types::{Address, Opcode, H256, U256};
#[cfg(feature = "test-utils")]
use mockall::automock;
use rundler_provider::AggregatorSimOut;
use rundler_types::{
    Entity, EntityType, StakeInfo, StorageSlot, UserOperation, ValidTimeRange, ValidationOutput,
};
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;

/// Simulation module for Entry Point v0.6
pub mod v0_6;

mod mempool;
pub use mempool::MempoolConfig;

use crate::{ExpectedStorage, ViolationError};

/// The result of a successful simulation
#[derive(Clone, Debug, Default)]
pub struct SimulationResult {
    /// The mempool IDs that support this operation
    pub mempools: Vec<H256>,
    /// Block hash this operation was simulated against
    pub block_hash: H256,
    /// Block number this operation was simulated against
    pub block_number: Option<u64>,
    /// Gas used in the pre-op phase of simulation measured
    /// by the entry point
    pub pre_op_gas: U256,
    /// The time range for which this operation is valid
    pub valid_time_range: ValidTimeRange,
    /// If using an aggregator, the result of the aggregation
    /// simulation
    pub aggregator: Option<AggregatorSimOut>,
    /// Code hash of all accessed contracts
    pub code_hash: H256,
    /// List of used entities that need to be staked for this operation
    /// to be valid
    pub entities_needing_stake: Vec<EntityType>,
    /// Whether the sender account is staked
    pub account_is_staked: bool,
    /// List of all addresses accessed during validation
    pub accessed_addresses: HashSet<Address>,
    /// List of addresses that have associated storage slots
    /// accessed within the simulation
    pub associated_addresses: HashSet<Address>,
    /// Expected storage values for all accessed slots during validation
    pub expected_storage: ExpectedStorage,
    /// Whether the operation requires a post-op
    pub requires_post_op: bool,
    /// All the entities used in this operation and their staking state
    pub entity_infos: EntityInfos,
}

impl SimulationResult {
    /// Get the aggregator address if one was used
    pub fn aggregator_address(&self) -> Option<Address> {
        self.aggregator.as_ref().map(|agg| agg.address)
    }
}

/// The result of a failed simulation. We return a list of the violations that ocurred during the failed simulation
/// and also information about all the entities used in the op to handle entity penalties
#[derive(Clone, Debug)]
pub struct SimulationError {
    /// A list of violations that occurred during simulation, or some other error that occurred not directly related to simulation rules
    pub violation_error: ViolationError<SimulationViolation>,
    /// The addresses and staking states of all the entities involved in an op. This value is None when simulation fails at a point where we are no
    pub entity_infos: Option<EntityInfos>,
}

impl From<Error> for SimulationError {
    fn from(error: Error) -> Self {
        SimulationError {
            violation_error: ViolationError::Other(error),
            entity_infos: None,
        }
    }
}

/// Simulator trait for running user operation simulations
#[cfg_attr(feature = "test-utils", automock(type UO = rundler_types::v0_6::UserOperation;))]
#[async_trait::async_trait]
pub trait Simulator: Send + Sync + 'static {
    /// The type of user operation that this simulator can handle
    type UO: UserOperation;

    /// Simulate a user operation, returning simulation information
    /// upon success, or simulation violations.
    async fn simulate_validation(
        &self,
        op: Self::UO,
        block_hash: Option<H256>,
        expected_code_hash: Option<H256>,
    ) -> Result<SimulationResult, SimulationError>;
}

/// All possible simulation violations
#[derive(Clone, Debug, parse_display::Display, Ord, Eq, PartialOrd, PartialEq)]
pub enum SimulationViolation {
    // Make sure to maintain the order here based on the importance
    // of the violation for converting to an JSON RPC error
    /// The user operation signature is invalid
    #[display("invalid signature")]
    InvalidSignature,
    /// The user operation used an opcode that is not allowed
    #[display("{0.kind} uses banned opcode: {2} in contract {1:?}")]
    UsedForbiddenOpcode(Entity, Address, ViolationOpCode),
    /// The user operation used a precompile that is not allowed
    #[display("{0.kind} uses banned precompile: {2:?} in contract {1:?}")]
    UsedForbiddenPrecompile(Entity, Address, Address),
    /// The user operation accessed a contract that has not been deployed
    #[display(
        "{0.kind} tried to access code at {1} during validation, but that address is not a contract"
    )]
    AccessedUndeployedContract(Entity, Address),
    /// The user operation factory entity called CREATE2 more than once during initialization
    #[display("factory may only call CREATE2 once during initialization")]
    FactoryCalledCreate2Twice(Address),
    /// The user operation accessed a storage slot that is not allowed
    #[display("{0.kind} accessed forbidden storage at address {1:?} during validation")]
    InvalidStorageAccess(Entity, StorageSlot),
    /// The user operation called an entry point method that is not allowed
    #[display("{0.kind} called entry point method other than depositTo")]
    CalledBannedEntryPointMethod(Entity),
    /// The user operation made a call that contained value to a contract other than the entrypoint
    /// during validation
    #[display("{0.kind} must not send ETH during validation (except from account to entry point)")]
    CallHadValue(Entity),
    /// The code hash of accessed contracts changed on the second simulation
    #[display("code accessed by validation has changed since the last time validation was run")]
    CodeHashChanged,
    /// The user operation contained an entity that accessed storage without being staked
    #[display("{0.needs_stake} needs to be staked: {0.accessing_entity} accessed storage at {0.accessed_address} slot {0.slot} (associated with {0.accessed_entity:?})")]
    NotStaked(Box<NeedsStakeInformation>),
    /// The user operation uses a paymaster that returns a context while being unstaked
    #[display("Unstaked paymaster must not return context")]
    UnstakedPaymasterContext,
    /// The user operation uses an aggregator entity and it is not staked
    #[display("An aggregator must be staked, regardless of storager usage")]
    UnstakedAggregator,
    /// Simulation reverted with an unintended reason, containing a message
    #[display("reverted while simulating {0} validation: {1}")]
    UnintendedRevertWithMessage(EntityType, String, Option<Address>),
    /// Simulation reverted with an unintended reason
    #[display("reverted while simulating {0} validation")]
    UnintendedRevert(EntityType, Option<Address>),
    /// Simulation did not revert, a revert is always expected
    #[display("simulateValidation did not revert. Make sure your EntryPoint is valid")]
    DidNotRevert,
    /// Simulation had the wrong number of phases
    #[display("simulateValidation should have 3 parts but had {0} instead. Make sure your EntryPoint is valid")]
    WrongNumberOfPhases(u32),
    /// The user operation ran out of gas during validation
    #[display("ran out of gas during {0.kind} validation")]
    OutOfGas(Entity),
    /// The user operation aggregator signature validation failed
    #[display("aggregator signature validation failed")]
    AggregatorValidationFailed,
    /// Verification gas limit doesn't have the required buffer on the measured gas
    #[display("verification gas limit doesn't have the required buffer on the measured gas, limit: {0}, needed: {1}")]
    VerificationGasLimitBufferTooLow(U256, U256),
}

/// A wrapper around Opcode that implements extra traits
#[derive(Debug, PartialEq, Clone, parse_display::Display, Eq)]
#[display("{0:?}")]
pub struct ViolationOpCode(pub Opcode);

impl PartialOrd for ViolationOpCode {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ViolationOpCode {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let left = self.0 as i32;
        let right = other.0 as i32;

        left.cmp(&right)
    }
}

fn entity_type_from_simulation_phase(i: usize) -> Option<EntityType> {
    match i {
        0 => Some(EntityType::Factory),
        1 => Some(EntityType::Account),
        2 => Some(EntityType::Paymaster),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
/// additional context about an entity
pub struct EntityInfo {
    /// The address of an entity
    pub address: Address,
    /// Whether the entity is staked or not
    pub is_staked: bool,
}

impl EntityInfo {
    fn override_is_staked(&mut self, allow_unstaked_addresses: &HashSet<Address>) {
        self.is_staked = allow_unstaked_addresses.contains(&self.address) || self.is_staked;
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
/// additional context for all the entities used in an op
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
    fn new(
        factory_address: Option<Address>,
        sender_address: Address,
        paymaster_address: Option<Address>,
        entry_point_out: &ValidationOutput,
        sim_settings: Settings,
    ) -> Self {
        let factory = factory_address.map(|address| EntityInfo {
            address,
            is_staked: is_staked(entry_point_out.factory_info, sim_settings),
        });
        let sender = EntityInfo {
            address: sender_address,
            is_staked: is_staked(entry_point_out.sender_info, sim_settings),
        };
        let paymaster = paymaster_address.map(|address| EntityInfo {
            address,
            is_staked: is_staked(entry_point_out.paymaster_info, sim_settings),
        });
        let aggregator = entry_point_out
            .aggregator_info
            .map(|aggregator_info| EntityInfo {
                address: aggregator_info.address,
                is_staked: is_staked(aggregator_info.stake_info, sim_settings),
            });

        Self {
            factory,
            sender,
            paymaster,
            aggregator,
        }
    }

    /// Get iterator over the entities
    pub fn entities(&'_ self) -> impl Iterator<Item = (EntityType, EntityInfo)> + '_ {
        EntityType::iter().filter_map(|t| self.get(t).map(|info| (t, info)))
    }

    fn override_is_staked(&mut self, allow_unstaked_addresses: &HashSet<Address>) {
        if let Some(mut factory) = self.factory {
            factory.override_is_staked(allow_unstaked_addresses)
        }
        self.sender.override_is_staked(allow_unstaked_addresses);
        if let Some(mut paymaster) = self.paymaster {
            paymaster.override_is_staked(allow_unstaked_addresses)
        }
        if let Some(mut aggregator) = self.aggregator {
            aggregator.override_is_staked(allow_unstaked_addresses)
        }
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

    fn sender_address(self) -> Address {
        self.sender.address
    }
}

fn is_staked(info: StakeInfo, sim_settings: Settings) -> bool {
    info.stake >= sim_settings.min_stake_value.into()
        && info.unstake_delay_sec >= sim_settings.min_unstake_delay.into()
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum StorageRestriction {
    /// (Entity needing stake, accessing entity type, accessed entity type, accessed address, accessed slot)
    NeedsStake(EntityType, EntityType, Option<EntityType>, Address, U256),
    Banned(U256),
}

/// Information about a storage violation based on stake status
#[derive(Debug, PartialEq, Clone, PartialOrd, Eq, Ord)]
pub struct NeedsStakeInformation {
    /// Entity needing stake info
    pub needs_stake: Entity,
    /// The entity that accessed the storage requiring stake
    pub accessing_entity: EntityType,
    /// Type of accessed entity, if it is a known entity
    pub accessed_entity: Option<EntityType>,
    /// Address that was accessed while unstaked
    pub accessed_address: Address,
    /// The accessed slot number
    pub slot: U256,
    /// Minumum stake
    pub min_stake: U256,
    /// Minumum delay after an unstake event
    pub min_unstake_delay: U256,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AccessInfo {
    // slot value, just prior this current operation
    pub(crate) reads: HashMap<U256, String>,
    // count of writes.
    pub(crate) writes: HashMap<U256, u32>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct AssociatedSlotsByAddress(HashMap<Address, BTreeSet<U256>>);

impl AssociatedSlotsByAddress {
    pub(crate) fn is_associated_slot(&self, address: Address, slot: U256) -> bool {
        if slot == address.as_bytes().into() {
            return true;
        }
        let Some(associated_slots) = self.0.get(&address) else {
            return false;
        };
        let Some(&next_smallest_slot) = associated_slots.range(..(slot + 1)).next_back() else {
            return false;
        };
        slot - next_smallest_slot < 128.into()
    }

    pub(crate) fn addresses(&self) -> HashSet<Address> {
        self.0.clone().into_keys().collect()
    }
}

#[derive(Clone, Debug)]
struct ParseStorageAccess<'a> {
    access_info: &'a AccessInfo,
    slots_by_address: &'a AssociatedSlotsByAddress,
    address: Address,
    sender: Address,
    entrypoint: Address,
    has_factory: bool,
    entity: &'a Entity,
}

fn parse_storage_accesses(args: ParseStorageAccess<'_>) -> Result<Vec<StorageRestriction>, Error> {
    let ParseStorageAccess {
        access_info,
        address,
        sender,
        entrypoint,
        entity,
        slots_by_address,
        has_factory,
        ..
    } = args;

    let mut restrictions = vec![];

    // STO-010 - always allowed to access storage on the account
    // [OP-051, OP-054] - block access to the entrypoint, except for depositTo and fallback
    //   - this is handled at another level, so we don't need to check for it here
    //   - at this level we can allow any entry point access through
    if address.eq(&sender) || address.eq(&entrypoint) {
        return Ok(restrictions);
    }

    let slots: Vec<&U256> = access_info
        .reads
        .keys()
        .chain(access_info.writes.keys())
        .collect();

    for slot in slots {
        let is_sender_associated = slots_by_address.is_associated_slot(sender, *slot);
        // [STO-032]
        let is_entity_associated = slots_by_address.is_associated_slot(entity.address, *slot);
        // [STO-031]
        let is_same_address = address.eq(&entity.address);
        // [STO-033]
        let is_read_permission = !access_info.writes.contains_key(slot);

        // STO-021 - Associated storage on external contracts is allowed
        if is_sender_associated && !is_same_address {
            // STO-022 - Factory must be staked to access associated storage in a deploy
            if has_factory {
                match entity.kind {
                    EntityType::Paymaster | EntityType::Aggregator => {
                        // If its a paymaster/aggregator, then the paymaster must be staked to access associated storage
                        // during a deploy
                        restrictions.push(StorageRestriction::NeedsStake(
                            entity.kind,
                            entity.kind,
                            Some(EntityType::Account),
                            address,
                            *slot,
                        ));
                    }
                    EntityType::Account | EntityType::Factory => {
                        restrictions.push(StorageRestriction::NeedsStake(
                            EntityType::Factory,
                            entity.kind,
                            Some(EntityType::Account),
                            address,
                            *slot,
                        ));
                    }
                }
            }
        } else if is_entity_associated || is_same_address {
            restrictions.push(StorageRestriction::NeedsStake(
                entity.kind,
                entity.kind,
                Some(entity.kind),
                address,
                *slot,
            ));
        } else if is_read_permission {
            restrictions.push(StorageRestriction::NeedsStake(
                entity.kind,
                entity.kind,
                None,
                address,
                *slot,
            ));
        } else {
            restrictions.push(StorageRestriction::Banned(*slot));
        }
    }

    Ok(restrictions)
}

/// Simulation Settings
#[derive(Debug, Copy, Clone)]
pub struct Settings {
    /// The minimum amount of time that a staked entity must have configured as
    /// their unstake delay on the entry point contract in order to be considered staked.
    pub min_unstake_delay: u32,
    /// The minimum amount of stake that a staked entity must have on the entry point
    /// contract in order to be considered staked.
    pub min_stake_value: u128,
    /// The maximum amount of gas that can be used during the simulation call
    pub max_simulate_handle_ops_gas: u64,
    /// The maximum amount of verification gas that can be used during the simulation call
    pub max_verification_gas: u64,
}

impl Settings {
    /// Create new settings
    pub fn new(
        min_unstake_delay: u32,
        min_stake_value: u128,
        max_simulate_handle_ops_gas: u64,
        max_verification_gas: u64,
    ) -> Self {
        Self {
            min_unstake_delay,
            min_stake_value,
            max_simulate_handle_ops_gas,
            max_verification_gas,
        }
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl Default for Settings {
    fn default() -> Self {
        Self {
            // one day in seconds: defined in the ERC-4337 spec
            min_unstake_delay: 84600,
            // 10^18 wei = 1 eth
            min_stake_value: 1_000_000_000_000_000_000,
            // 550 million gas: currently the defaults for Alchemy eth_call
            max_simulate_handle_ops_gas: 550_000_000,
            max_verification_gas: 5_000_000,
        }
    }
}
