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

use std::{
    collections::{HashMap, HashSet},
    mem,
    ops::Deref,
    sync::Arc,
};

use async_trait::async_trait;
use ethers::{
    abi::AbiDecode,
    types::{Address, BlockId, Opcode, H256, U256},
};
use indexmap::IndexSet;
#[cfg(feature = "test-utils")]
use mockall::automock;
use rundler_provider::{AggregatorOut, AggregatorSimOut, Provider};
use rundler_types::{
    contracts::i_entry_point::FailedOp, Entity, EntityType, StorageSlot, UserOperation,
    ValidTimeRange,
};

use super::{
    mempool::{match_mempools, MempoolConfig, MempoolMatchResult},
    tracer::{
        parse_combined_tracer_str, AssociatedSlotsByAddress, SimulateValidationTracer,
        SimulationTracerOutput, StorageAccess,
    },
    validation_results::{StakeInfo, ValidationOutput, ValidationReturnInfo},
};
use crate::{
    types::{ExpectedStorage, ViolationError},
    utils,
};

/// The result of a successful simulation
#[derive(Clone, Debug, Default)]
pub struct SimulationSuccess {
    /// The mempool IDs that support this operation
    pub mempools: Vec<H256>,
    /// Block hash this operation was simulated against
    pub block_hash: H256,
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
    /// Expected storage values for all accessed slots during validation
    pub expected_storage: ExpectedStorage,
    /// Whether the operation requires a post-op
    pub requires_post_op: bool,
}

impl SimulationSuccess {
    /// Get the aggregator address if one was used
    pub fn aggregator_address(&self) -> Option<Address> {
        self.aggregator.as_ref().map(|agg| agg.address)
    }
}

/// The result of a failed simulation
pub type SimulationError = ViolationError<SimulationViolation>;

/// Simulator trait for running user operation simulations
#[cfg_attr(feature = "test-utils", automock)]
#[async_trait::async_trait]
pub trait Simulator: Send + Sync + 'static {
    /// Simulate a user operation, returning simulation information
    /// upon success, or simulation violations.
    async fn simulate_validation(
        &self,
        op: UserOperation,
        block_hash: Option<H256>,
        expected_code_hash: Option<H256>,
    ) -> Result<SimulationSuccess, SimulationError>;
}

/// Simulator implementation.
///
/// This simulator supports the use of "alternative mempools".
/// During simulation, the simulator will check the violations found
/// against the mempool configurations provided in the constructor.
///
/// If a mempool is found to support all of the associated violations,
/// it will be included in the list of mempools returned by the simulator.
///
/// If no mempools are found, the simulator will return an error containing
/// the violations.
#[derive(Debug)]
pub struct SimulatorImpl<P: Provider, T: SimulateValidationTracer> {
    provider: Arc<P>,
    entry_point_address: Address,
    simulate_validation_tracer: T,
    sim_settings: Settings,
    mempool_configs: HashMap<H256, MempoolConfig>,
}

impl<P, T> SimulatorImpl<P, T>
where
    P: Provider,
    T: SimulateValidationTracer,
{
    /// Create a new simulator
    ///
    /// `mempool_configs` is a map of mempool IDs to mempool configurations.
    /// It is used during simulation to determine which mempools support
    /// the violations found during simulation.
    pub fn new(
        provider: Arc<P>,
        entry_point_address: Address,
        simulate_validation_tracer: T,
        sim_settings: Settings,
        mempool_configs: HashMap<H256, MempoolConfig>,
    ) -> Self {
        Self {
            provider,
            entry_point_address,
            simulate_validation_tracer,
            sim_settings,
            mempool_configs,
        }
    }

    /// Return the associated settings
    pub fn settings(&self) -> &Settings {
        &self.sim_settings
    }

    // Run the tracer and transform the output.
    // Any violations during this stage are errors.
    async fn create_context(
        &self,
        op: UserOperation,
        block_id: BlockId,
    ) -> Result<ValidationContext, SimulationError> {
        let factory_address = op.factory();
        let sender_address = op.sender;
        let paymaster_address = op.paymaster();
        let tracer_out = self
            .simulate_validation_tracer
            .trace_simulate_validation(op.clone(), block_id, self.sim_settings.max_verification_gas)
            .await?;
        let num_phases = tracer_out.phases.len() as u32;
        // Check if there are too many phases here, then check too few at the
        // end. We are detecting cases where the entry point is broken. Too many
        // phases definitely means it's broken, but too few phases could still
        // mean the entry point is fine if one of the phases fails and it
        // doesn't reach the end of execution.
        if num_phases > 3 {
            Err(vec![SimulationViolation::WrongNumberOfPhases(num_phases)])?
        }
        let Some(ref revert_data) = tracer_out.revert_data else {
            Err(vec![SimulationViolation::DidNotRevert])?
        };
        let last_entity = entity_type_from_simulation_phase(tracer_out.phases.len() - 1).unwrap();

        if let Ok(failed_op) = FailedOp::decode_hex(revert_data) {
            let entity_addr = match last_entity {
                EntityType::Factory => factory_address,
                EntityType::Paymaster => paymaster_address,
                EntityType::Account => Some(sender_address),
                _ => None,
            };
            Err(vec![SimulationViolation::UnintendedRevertWithMessage(
                last_entity,
                failed_op.reason,
                entity_addr,
            )])?
        }
        let Ok(entry_point_out) = ValidationOutput::decode_hex(revert_data) else {
            Err(vec![SimulationViolation::UnintendedRevert(last_entity)])?
        };
        let entity_infos = EntityInfos::new(
            factory_address,
            sender_address,
            paymaster_address,
            &entry_point_out,
            self.sim_settings,
        );
        let is_unstaked_wallet_creation = entity_infos
            .get(EntityType::Factory)
            .filter(|factory| !factory.is_staked)
            .is_some();
        if num_phases < 3 {
            Err(vec![SimulationViolation::WrongNumberOfPhases(num_phases)])?
        };
        Ok(ValidationContext {
            block_id,
            entity_infos,
            tracer_out,
            entry_point_out,
            is_unstaked_wallet_creation,
            entities_needing_stake: vec![],
            accessed_addresses: HashSet::new(),
        })
    }

    async fn validate_aggregator_signature(
        &self,
        op: UserOperation,
        aggregator_address: Option<Address>,
        gas_cap: u64,
    ) -> anyhow::Result<AggregatorOut> {
        let Some(aggregator_address) = aggregator_address else {
            return Ok(AggregatorOut::NotNeeded);
        };

        Ok(self
            .provider
            .clone()
            .validate_user_op_signature(aggregator_address, op, gas_cap)
            .await?)
    }

    // Parse the output from tracing and return a list of violations.
    // Most violations found during this stage are allowlistable and can be added
    // to the list of allowlisted violations on a given mempool.
    fn gather_context_violations(
        &self,
        context: &mut ValidationContext,
    ) -> anyhow::Result<Vec<SimulationViolation>> {
        let &mut ValidationContext {
            ref entity_infos,
            ref tracer_out,
            ref entry_point_out,
            is_unstaked_wallet_creation,
            ref mut entities_needing_stake,
            ref mut accessed_addresses,
            ..
        } = context;

        let mut violations = vec![];

        if entry_point_out.return_info.sig_failed {
            violations.push(SimulationViolation::InvalidSignature);
        }

        let sender_address = entity_infos.sender_address();

        for (index, phase) in tracer_out.phases.iter().enumerate().take(3) {
            let kind = entity_type_from_simulation_phase(index).unwrap();
            let Some(entity_info) = entity_infos.get(kind) else {
                continue;
            };
            let entity = Entity {
                kind,
                address: entity_info.address,
            };
            for opcode in &phase.forbidden_opcodes_used {
                let (contract, opcode) = parse_combined_tracer_str(opcode)?;
                violations.push(SimulationViolation::UsedForbiddenOpcode(
                    entity,
                    contract,
                    ViolationOpCode(opcode),
                ));
            }

            for (addr, opcode) in &phase.ext_code_access_info {
                if *addr == self.entry_point_address {
                    violations.push(SimulationViolation::UsedForbiddenOpcode(
                        entity,
                        *addr,
                        ViolationOpCode(*opcode),
                    ));
                }
            }

            for precompile in &phase.forbidden_precompiles_used {
                let (contract, precompile) = parse_combined_tracer_str(precompile)?;
                violations.push(SimulationViolation::UsedForbiddenPrecompile(
                    entity, contract, precompile,
                ));
            }
            let mut needs_stake = entity.kind == EntityType::Paymaster
                && !entry_point_out.return_info.paymaster_context.is_empty();
            let mut banned_slots_accessed = IndexSet::<StorageSlot>::new();
            for StorageAccess { address, slots } in &phase.storage_accesses {
                let address = *address;
                accessed_addresses.insert(address);
                for slot in slots {
                    let restriction = get_storage_restriction(GetStorageRestrictionArgs {
                        slots_by_address: &tracer_out.associated_slots_by_address,
                        is_unstaked_wallet_creation,
                        entry_point_address: self.entry_point_address,
                        entity_address: entity_info.address,
                        sender_address,
                        accessed_address: address,
                        slot: *slot,
                    });
                    match restriction {
                        StorageRestriction::Allowed => {}
                        StorageRestriction::NeedsStake => needs_stake = true,
                        StorageRestriction::Banned => {
                            banned_slots_accessed.insert(StorageSlot {
                                address,
                                slot: *slot,
                            });
                        }
                    }
                }
            }
            if needs_stake {
                entities_needing_stake.push(entity.kind);
                if !entity_info.is_staked {
                    violations.push(SimulationViolation::NotStaked(
                        entity,
                        self.sim_settings.min_stake_value.into(),
                        self.sim_settings.min_unstake_delay.into(),
                    ));
                }
            }
            for slot in banned_slots_accessed {
                violations.push(SimulationViolation::InvalidStorageAccess(entity, slot));
            }
            let non_sender_called_with_value = phase
                .addresses_calling_with_value
                .iter()
                .any(|address| address != &sender_address);
            if non_sender_called_with_value || phase.called_non_entry_point_with_value {
                violations.push(SimulationViolation::CallHadValue(entity));
            }
            if phase.called_banned_entry_point_method {
                violations.push(SimulationViolation::CalledBannedEntryPointMethod(entity));
            }

            // These violations are not allowlistable but we need to collect them here
            if phase.ran_out_of_gas {
                violations.push(SimulationViolation::OutOfGas(entity));
            }
            for &address in &phase.undeployed_contract_accesses {
                violations.push(SimulationViolation::AccessedUndeployedContract(
                    entity, address,
                ))
            }
        }

        if let Some(aggregator_info) = entry_point_out.aggregator_info {
            entities_needing_stake.push(EntityType::Aggregator);
            if !is_staked(aggregator_info.stake_info, self.sim_settings) {
                violations.push(SimulationViolation::NotStaked(
                    Entity::aggregator(aggregator_info.address),
                    self.sim_settings.min_stake_value.into(),
                    self.sim_settings.min_unstake_delay.into(),
                ));
            }
        }
        if tracer_out.factory_called_create2_twice {
            let factory = entity_infos.get(EntityType::Factory);
            match factory {
                Some(factory) => {
                    violations.push(SimulationViolation::FactoryCalledCreate2Twice(
                        factory.address,
                    ));
                }
                None => {
                    // weird case where CREATE2 is called > 1, but there isn't a factory
                    // defined. This should never happen, blame the violation on the entry point.
                    violations.push(SimulationViolation::FactoryCalledCreate2Twice(
                        self.entry_point_address,
                    ));
                }
            }
        }

        Ok(violations)
    }

    // Check the code hash of the entities associated with the user operation
    // if needed, validate that the signature is valid for the aggregator.
    // Violations during this stage are always errors.
    async fn check_contracts(
        &self,
        op: UserOperation,
        context: &mut ValidationContext,
        expected_code_hash: Option<H256>,
    ) -> Result<(H256, Option<AggregatorSimOut>), SimulationError> {
        let &mut ValidationContext {
            block_id,
            ref mut tracer_out,
            ref entry_point_out,
            ..
        } = context;

        // collect a vector of violations to ensure a deterministic error message
        let mut violations = vec![];

        let aggregator_address = entry_point_out.aggregator_info.map(|info| info.address);
        let code_hash_future = utils::get_code_hash(
            self.provider.deref(),
            mem::take(&mut tracer_out.accessed_contract_addresses),
            Some(block_id),
        );
        let aggregator_signature_future = self.validate_aggregator_signature(
            op,
            aggregator_address,
            self.sim_settings.max_verification_gas,
        );

        let (code_hash, aggregator_out) =
            tokio::try_join!(code_hash_future, aggregator_signature_future)?;

        if let Some(expected_code_hash) = expected_code_hash {
            if expected_code_hash != code_hash {
                violations.push(SimulationViolation::CodeHashChanged)
            }
        }
        let aggregator = match aggregator_out {
            AggregatorOut::NotNeeded => None,
            AggregatorOut::SuccessWithInfo(info) => Some(info),
            AggregatorOut::ValidationReverted => {
                violations.push(SimulationViolation::AggregatorValidationFailed);
                None
            }
        };

        if !violations.is_empty() {
            return Err(violations.into());
        }

        Ok((code_hash, aggregator))
    }
}

#[async_trait]
impl<P, T> Simulator for SimulatorImpl<P, T>
where
    P: Provider,
    T: SimulateValidationTracer,
{
    async fn simulate_validation(
        &self,
        op: UserOperation,
        block_hash: Option<H256>,
        expected_code_hash: Option<H256>,
    ) -> Result<SimulationSuccess, SimulationError> {
        let block_hash = match block_hash {
            Some(block_hash) => block_hash,
            None => self
                .provider
                .get_latest_block_hash()
                .await
                .map_err(anyhow::Error::from)?,
        };
        let block_id = block_hash.into();
        let mut context = match self.create_context(op.clone(), block_id).await {
            Ok(context) => context,
            error @ Err(_) => error?,
        };

        // Gather all violations from the tracer
        let mut violations = self.gather_context_violations(&mut context)?;
        // Sort violations so that the final error message is deterministic
        violations.sort();
        // Check violations against mempool rules, find supporting mempools, error if none found
        let mempools = match match_mempools(&self.mempool_configs, &violations) {
            MempoolMatchResult::Matches(pools) => pools,
            MempoolMatchResult::NoMatch(i) => return Err(vec![violations[i].clone()].into()),
        };

        // Check code hash and aggregator signature, these can't fail
        let (code_hash, aggregator) = self
            .check_contracts(op, &mut context, expected_code_hash)
            .await?;

        // Transform outputs into success struct
        let ValidationContext {
            tracer_out,
            entry_point_out,
            is_unstaked_wallet_creation: _,
            entities_needing_stake,
            accessed_addresses,
            ..
        } = context;
        let ValidationOutput {
            return_info,
            sender_info,
            ..
        } = entry_point_out;
        let account_is_staked = is_staked(sender_info, self.sim_settings);
        let ValidationReturnInfo {
            pre_op_gas,
            valid_after,
            valid_until,
            paymaster_context,
            ..
        } = return_info;
        Ok(SimulationSuccess {
            mempools,
            block_hash,
            pre_op_gas,
            valid_time_range: ValidTimeRange::new(valid_after, valid_until),
            aggregator,
            code_hash,
            entities_needing_stake,
            account_is_staked,
            accessed_addresses,
            expected_storage: tracer_out.expected_storage,
            requires_post_op: !paymaster_context.is_empty(),
        })
    }
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
    #[display("{0.kind} must be staked")]
    NotStaked(Entity, U256, U256),
    /// Simulation reverted with an unintended reason, containing a message
    #[display("reverted while simulating {0} validation: {1}")]
    UnintendedRevertWithMessage(EntityType, String, Option<Address>),
    /// Simulation reverted with an unintended reason
    #[display("reverted while simulating {0} validation")]
    UnintendedRevert(EntityType),
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

#[derive(Debug)]
struct ValidationContext {
    block_id: BlockId,
    entity_infos: EntityInfos,
    tracer_out: SimulationTracerOutput,
    entry_point_out: ValidationOutput,
    is_unstaked_wallet_creation: bool,
    entities_needing_stake: Vec<EntityType>,
    accessed_addresses: HashSet<Address>,
}

#[derive(Clone, Copy, Debug)]
struct EntityInfo {
    address: Address,
    is_staked: bool,
}

#[derive(Clone, Copy, Debug)]
struct EntityInfos {
    factory: Option<EntityInfo>,
    sender: EntityInfo,
    paymaster: Option<EntityInfo>,
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
        Self {
            factory,
            sender,
            paymaster,
        }
    }

    fn get(self, entity: EntityType) -> Option<EntityInfo> {
        match entity {
            EntityType::Factory => self.factory,
            EntityType::Account => Some(self.sender),
            EntityType::Paymaster => self.paymaster,
            _ => None,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StorageRestriction {
    Allowed,
    NeedsStake,
    Banned,
}

#[derive(Clone, Copy, Debug)]
struct GetStorageRestrictionArgs<'a> {
    slots_by_address: &'a AssociatedSlotsByAddress,
    is_unstaked_wallet_creation: bool,
    entry_point_address: Address,
    entity_address: Address,
    sender_address: Address,
    accessed_address: Address,
    slot: U256,
}

fn get_storage_restriction(args: GetStorageRestrictionArgs<'_>) -> StorageRestriction {
    let GetStorageRestrictionArgs {
        slots_by_address,
        is_unstaked_wallet_creation,
        entry_point_address,
        entity_address,
        sender_address,
        accessed_address,
        slot,
        ..
    } = args;
    if accessed_address == sender_address {
        StorageRestriction::Allowed
    } else if slots_by_address.is_associated_slot(sender_address, slot) {
        // Allow entities to access the sender's associated storage unless its during an unstaked wallet creation
        // Can always access the entry point's associated storage (note only depositTo is allowed to be called)
        if accessed_address == entry_point_address || !is_unstaked_wallet_creation {
            StorageRestriction::Allowed
        } else {
            StorageRestriction::NeedsStake
        }
    } else if accessed_address == entity_address
        || slots_by_address.is_associated_slot(entity_address, slot)
    {
        StorageRestriction::NeedsStake
    } else {
        StorageRestriction::Banned
    }
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ethers::{
        abi::AbiEncode,
        providers::JsonRpcError,
        types::{Address, BlockNumber, Bytes},
        utils::hex,
    };
    use rundler_provider::{AggregatorOut, MockProvider, ProviderError};

    use super::*;
    use crate::simulation::tracer::{MockSimulateValidationTracer, Phase};

    fn create_base_config() -> (MockProvider, MockSimulateValidationTracer) {
        (MockProvider::new(), MockSimulateValidationTracer::new())
    }

    fn get_test_tracer_output() -> SimulationTracerOutput {
        SimulationTracerOutput {
            accessed_contract_addresses: vec![
                Address::from_str("0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789").unwrap(),
                Address::from_str("0xb856dbd4fa1a79a46d426f537455e7d3e79ab7c4").unwrap(),
                Address::from_str("0x8abb13360b87be5eeb1b98647a016add927a136c").unwrap(),
            ],
            associated_slots_by_address: serde_json::from_str(r#"
            {
                "0x0000000000000000000000000000000000000000": [
                    "0xd5c1ebdd81c5c7bebcd52bc11c8d37f7038b3c64f849c2ca58a022abeab1adae",
                    "0xad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5"
                ],
                "0xb856dbd4fa1a79a46d426f537455e7d3e79ab7c4": [
                    "0x3072884cc37d411af7360b34f105e1e860b1631783232a4f2d5c094d365cdaab",
                    "0xf5357e1da3acf909ceaed3492183cbad85a3c9e1f0076495f66d3eed05219bd5",
                    "0xf264fff4db20d04721712f34a6b5a8bca69a212345e40a92101082e79bdd1f0a"
                ]
            }
            "#).unwrap(),
            factory_called_create2_twice: false,
            expected_storage: serde_json::from_str(r#"
            {
                "0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789": {
                    "0xad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "0xad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb6": "0x0000000000000000000000000000000000000000000000000000000000000000"
                }
            }
            "#).unwrap(),
            phases: vec![
                Phase {
                    addresses_calling_with_value: vec![],
                    called_banned_entry_point_method: false,
                    called_non_entry_point_with_value: false,
                    forbidden_opcodes_used: vec![],
                    forbidden_precompiles_used: vec![],
                    ran_out_of_gas: false,
                    storage_accesses: vec![],
                    undeployed_contract_accesses: vec![],
                    ext_code_access_info: HashMap::new(),
                },
                Phase {
                    addresses_calling_with_value: vec![Address::from_str("0xb856dbd4fa1a79a46d426f537455e7d3e79ab7c4").unwrap()],
                    called_banned_entry_point_method: false,
                    called_non_entry_point_with_value: false,
                    forbidden_opcodes_used: vec![],
                    forbidden_precompiles_used: vec![],
                    ran_out_of_gas: false,
                    storage_accesses: vec![
                        StorageAccess {
                            address: Address::from_str("0xb856dbd4fa1a79a46d426f537455e7d3e79ab7c4").unwrap(),
                            slots: vec![
                                U256::from_str("0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc").unwrap(),
                                U256::from_str("0x0000000000000000000000000000000000000000000000000000000000000000").unwrap()
                            ],
                        },
                        StorageAccess {
                            address: Address::from_str("0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789").unwrap(),
                            slots: vec![
                                U256::from_str("0xf5357e1da3acf909ceaed3492183cbad85a3c9e1f0076495f66d3eed05219bd5").unwrap()
                            ],
                        }
                    ],
                    undeployed_contract_accesses: vec![],
                    ext_code_access_info: HashMap::new(),
                },
                Phase {
                    addresses_calling_with_value: vec![],
                    called_banned_entry_point_method: false,
                    called_non_entry_point_with_value: false,
                    forbidden_opcodes_used: vec![],
                    forbidden_precompiles_used: vec![],
                    ran_out_of_gas: false,
                    storage_accesses: vec![],
                    undeployed_contract_accesses: vec![],
                    ext_code_access_info: HashMap::new(),
                }
            ],
            revert_data: Some("0xe0cff05f00000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000014eff00000000000000000000000000000000000000000000000000000b7679c50c24000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffff00000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000000".into()),
        }
    }

    fn create_simulator(
        provider: MockProvider,
        simulate_validation_tracer: MockSimulateValidationTracer,
    ) -> SimulatorImpl<MockProvider, MockSimulateValidationTracer> {
        let settings = Settings::default();

        let mut mempool_configs = HashMap::new();
        mempool_configs.insert(H256::zero(), MempoolConfig::default());

        let provider = Arc::new(provider);

        let simulator: SimulatorImpl<MockProvider, MockSimulateValidationTracer> =
            SimulatorImpl::new(
                Arc::clone(&provider),
                Address::from_str("0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789").unwrap(),
                simulate_validation_tracer,
                settings,
                mempool_configs,
            );

        simulator
    }

    #[tokio::test]
    async fn test_simulate_validation() {
        let (mut provider, mut tracer) = create_base_config();

        provider.expect_get_latest_block_hash().returning(|| {
            Ok(
                H256::from_str(
                    "0x38138f1cb4653ab6ab1c89ae3a6acc8705b54bd16a997d880c4421014ed66c3d",
                )
                .unwrap(),
            )
        });

        tracer
            .expect_trace_simulate_validation()
            .returning(move |_, _, _| Ok(get_test_tracer_output()));

        // The underlying eth_call when getting the code hash in check_contracts
        provider.expect_call().returning(|_, _| {
            let json_rpc_error = JsonRpcError {
                code: -32000,
                message: "execution reverted".to_string(),
                data: Some(serde_json::Value::String(
                    "0x091cd005abf68e7b82c951a8619f065986132f67a0945153533cfcdd93b6895f33dbc0c7"
                        .to_string(),
                )),
            };
            Err(ProviderError::JsonRpcError(json_rpc_error))
        });

        provider
            .expect_validate_user_op_signature()
            .returning(|_, _, _| Ok(AggregatorOut::NotNeeded));

        let user_operation = UserOperation {
            sender: Address::from_str("b856dbd4fa1a79a46d426f537455e7d3e79ab7c4").unwrap(),
            nonce: U256::from(264),
            init_code: Bytes::from_str("0x").unwrap(),
            call_data: Bytes::from_str("0xb61d27f6000000000000000000000000b856dbd4fa1a79a46d426f537455e7d3e79ab7c4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000004d087d28800000000000000000000000000000000000000000000000000000000").unwrap(),
            call_gas_limit: U256::from(9100),
            verification_gas_limit: U256::from(64805),
            pre_verification_gas: U256::from(46128),
            max_fee_per_gas: U256::from(105000100),
            max_priority_fee_per_gas: U256::from(105000000),
            paymaster_and_data: Bytes::from_str("0x").unwrap(),
            signature: Bytes::from_str("0x98f89993ce573172635b44ef3b0741bd0c19dd06909d3539159f6d66bef8c0945550cc858b1cf5921dfce0986605097ba34c2cf3fc279154dd25e161ea7b3d0f1c").unwrap(),
        };

        let simulator = create_simulator(provider, tracer);
        let res = simulator
            .simulate_validation(user_operation, None, None)
            .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_create_context_two_phases_unintended_revert() {
        let (provider, mut tracer) = create_base_config();

        tracer
            .expect_trace_simulate_validation()
            .returning(|_, _, _| {
                let mut tracer_output = get_test_tracer_output();
                tracer_output.revert_data = Some(hex::encode(
                    FailedOp {
                        op_index: U256::from(100),
                        reason: "AA23 reverted (or OOG)".to_string(),
                    }
                    .encode(),
                ));
                Ok(tracer_output)
            });

        let user_operation = UserOperation {
            sender: Address::from_str("b856dbd4fa1a79a46d426f537455e7d3e79ab7c4").unwrap(),
            nonce: U256::from(264),
            init_code: Bytes::from_str("0x").unwrap(),
            call_data: Bytes::from_str("0xb61d27f6000000000000000000000000b856dbd4fa1a79a46d426f537455e7d3e79ab7c4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000004d087d28800000000000000000000000000000000000000000000000000000000").unwrap(),
            call_gas_limit: U256::from(9100),
            verification_gas_limit: U256::from(64805),
            pre_verification_gas: U256::from(46128),
            max_fee_per_gas: U256::from(105000100),
            max_priority_fee_per_gas: U256::from(105000000),
            paymaster_and_data: Bytes::from_str("0x").unwrap(),
            signature: Bytes::from_str("0x98f89993ce573172635b44ef3b0741bd0c19dd06909d3539159f6d66bef8c0945550cc858b1cf5921dfce0986605097ba34c2cf3fc279154dd25e161ea7b3d0f1c").unwrap(),
        };

        let simulator = create_simulator(provider, tracer);
        let res = simulator
            .create_context(user_operation, BlockId::Number(BlockNumber::Latest))
            .await;

        assert!(matches!(
            res,
            Err(ViolationError::Violations(violations)) if matches!(
                violations.get(0),
                Some(&SimulationViolation::UnintendedRevertWithMessage(
                    EntityType::Paymaster,
                    ref reason,
                    _
                )) if reason == "AA23 reverted (or OOG)"
            )
        ));
    }

    #[tokio::test]
    async fn test_gather_context_violations() {
        let (provider, tracer) = create_base_config();

        let mut tracer_output = get_test_tracer_output();

        // add forbidden opcodes and precompiles
        tracer_output.phases[1].forbidden_opcodes_used = vec![
            String::from("0xb856dbd4fa1a79a46d426f537455e7d3e79ab7c4:GASPRICE"),
            String::from("0xb856dbd4fa1a79a46d426f537455e7d3e79ab7c4:COINBASE"),
        ];
        tracer_output.phases[1].forbidden_precompiles_used = vec![String::from(
            "0xb856dbd4fa1a79a46d426f537455e7d3e79ab7c4:0x0000000000000000000000000000000000000019",
        )];

        // add a storage access for a random unrelated address
        tracer_output.phases[1]
            .storage_accesses
            .push(StorageAccess {
                address: Address::from_str("0x1c0e100fcf093c64cdaa545b425ad7ed8e8a0db6").unwrap(),
                slots: vec![U256::from_str(
                    "0xa3f946b7ed2f016739c6be6031c5579a53d3784a471c3b5f9c2a1f8706c65a4b",
                )
                .unwrap()],
            });

        let mut validation_context = ValidationContext {
            block_id: BlockId::Number(BlockNumber::Latest),
            entity_infos: EntityInfos::new(
                Some(Address::from_str("0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789").unwrap()),
                Address::from_str("0xb856dbd4fa1a79a46d426f537455e7d3e79ab7c4").unwrap(),
                Some(Address::from_str("0x8abb13360b87be5eeb1b98647a016add927a136c").unwrap()),
                &ValidationOutput {
                    return_info: ValidationReturnInfo::from((
                        U256::default(),
                        U256::default(),
                        false,
                        0,
                        0,
                        Bytes::default(),
                    )),
                    sender_info: StakeInfo::from((U256::default(), U256::default())),
                    factory_info: StakeInfo::from((U256::default(), U256::default())),
                    paymaster_info: StakeInfo::from((U256::default(), U256::default())),
                    aggregator_info: None,
                },
                Settings::default(),
            ),
            tracer_out: tracer_output,
            entry_point_out: ValidationOutput {
                return_info: ValidationReturnInfo::from((
                    U256::default(),
                    U256::default(),
                    true,
                    0,
                    0,
                    Bytes::default(),
                )),
                sender_info: StakeInfo::from((U256::default(), U256::default())),
                factory_info: StakeInfo::from((U256::default(), U256::default())),
                paymaster_info: StakeInfo::from((U256::default(), U256::default())),
                aggregator_info: None,
            },
            is_unstaked_wallet_creation: false,

            entities_needing_stake: vec![],
            accessed_addresses: HashSet::new(),
        };

        let simulator = create_simulator(provider, tracer);
        let res = simulator.gather_context_violations(&mut validation_context);

        assert_eq!(
            res.unwrap(),
            vec![
                SimulationViolation::InvalidSignature,
                SimulationViolation::UsedForbiddenOpcode(
                    Entity {
                        kind: EntityType::Account,
                        address: Address::from_str("0xb856dbd4fa1a79a46d426f537455e7d3e79ab7c4")
                            .unwrap()
                    },
                    Address::from_str("0xb856dbd4fa1a79a46d426f537455e7d3e79ab7c4").unwrap(),
                    ViolationOpCode(Opcode::GASPRICE),
                ),
                SimulationViolation::UsedForbiddenOpcode(
                    Entity {
                        kind: EntityType::Account,
                        address: Address::from_str("0xb856dbd4fa1a79a46d426f537455e7d3e79ab7c4")
                            .unwrap()
                    },
                    Address::from_str("0xb856dbd4fa1a79a46d426f537455e7d3e79ab7c4").unwrap(),
                    ViolationOpCode(Opcode::COINBASE),
                ),
                SimulationViolation::UsedForbiddenPrecompile(
                    Entity {
                        kind: EntityType::Account,
                        address: Address::from_str("0xb856dbd4fa1a79a46d426f537455e7d3e79ab7c4")
                            .unwrap()
                    },
                    Address::from_str("0xb856dbd4fa1a79a46d426f537455e7d3e79ab7c4").unwrap(),
                    Address::from_str("0x0000000000000000000000000000000000000019").unwrap(),
                ),
                SimulationViolation::InvalidStorageAccess(
                    Entity {
                        kind: EntityType::Account,
                        address: Address::from_str("0xb856dbd4fa1a79a46d426f537455e7d3e79ab7c4")
                            .unwrap()
                    },
                    StorageSlot {
                        address: Address::from_str("0x1c0e100fcf093c64cdaa545b425ad7ed8e8a0db6")
                            .unwrap(),
                        slot: U256::from_str(
                            "0xa3f946b7ed2f016739c6be6031c5579a53d3784a471c3b5f9c2a1f8706c65a4b"
                        )
                        .unwrap()
                    }
                )
            ]
        );
    }
}
