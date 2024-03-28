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

use anyhow::Error;
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
    contracts::i_entry_point::FailedOp, Entity, EntityType, StakeInfo, StorageSlot, UserOperation,
    ValidTimeRange, ValidationOutput, ValidationReturnInfo,
};
use strum::IntoEnumIterator;

use super::{
    mempool::{match_mempools, AllowEntity, AllowRule, MempoolConfig, MempoolMatchResult},
    tracer::{
        parse_combined_tracer_str, AccessInfo, AssociatedSlotsByAddress, SimulateValidationTracer,
        SimulationTracerOutput,
    },
};
use crate::{
    types::{ExpectedStorage, ViolationError},
    utils,
};

/// Required buffer for verification gas limit when targeting the 0.6 entrypoint contract
pub(crate) const REQUIRED_VERIFICATION_GAS_LIMIT_BUFFER: U256 = U256([2000, 0, 0, 0]);

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
    ) -> Result<SimulationResult, SimulationError>;
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
    allow_unstaked_addresses: HashSet<Address>,
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
        // Get a list of entities that are allowed to act as staked entities despite being unstaked
        let mut allow_unstaked_addresses = HashSet::new();
        for config in mempool_configs.values() {
            for entry in &config.allowlist {
                if entry.rule == AllowRule::NotStaked {
                    if let AllowEntity::Address(address) = entry.entity {
                        allow_unstaked_addresses.insert(address);
                    }
                }
            }
        }

        Self {
            provider,
            entry_point_address,
            simulate_validation_tracer,
            sim_settings,
            mempool_configs,
            allow_unstaked_addresses,
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
            Err(SimulationError {
                violation_error: ViolationError::Violations(vec![
                    SimulationViolation::WrongNumberOfPhases(num_phases),
                ]),
                entity_infos: None,
            })?
        }
        let Some(ref revert_data) = tracer_out.revert_data else {
            Err(SimulationError {
                violation_error: ViolationError::Violations(vec![
                    SimulationViolation::DidNotRevert,
                ]),
                entity_infos: None,
            })?
        };
        let last_entity_type =
            entity_type_from_simulation_phase(tracer_out.phases.len() - 1).unwrap();

        if let Ok(failed_op) = FailedOp::decode_hex(revert_data) {
            let entity_addr = match last_entity_type {
                EntityType::Factory => factory_address,
                EntityType::Paymaster => paymaster_address,
                EntityType::Account => Some(sender_address),
                _ => None,
            };
            Err(SimulationError {
                violation_error: ViolationError::Violations(vec![
                    SimulationViolation::UnintendedRevertWithMessage(
                        last_entity_type,
                        failed_op.reason,
                        entity_addr,
                    ),
                ]),
                entity_infos: None,
            })?
        }
        let Ok(entry_point_out) = ValidationOutput::decode_hex(revert_data) else {
            let entity_addr = match last_entity_type {
                EntityType::Factory => factory_address,
                EntityType::Paymaster => paymaster_address,
                EntityType::Account => Some(sender_address),
                _ => None,
            };
            Err(SimulationError {
                violation_error: ViolationError::Violations(vec![
                    SimulationViolation::UnintendedRevert(last_entity_type, entity_addr),
                ]),
                entity_infos: None,
            })?
        };
        let entity_infos = EntityInfos::new(
            factory_address,
            sender_address,
            paymaster_address,
            &entry_point_out,
            self.sim_settings,
        );
        if num_phases < 3 {
            Err(SimulationError {
                violation_error: ViolationError::Violations(vec![
                    SimulationViolation::WrongNumberOfPhases(num_phases),
                ]),
                entity_infos: Some(entity_infos),
            })?
        };

        let associated_addresses = tracer_out.associated_slots_by_address.addresses();

        let initcode_length = op.init_code.len();
        Ok(ValidationContext {
            op,
            block_id,
            entity_infos,
            tracer_out,
            entry_point_out,
            associated_addresses,
            entities_needing_stake: vec![],
            accessed_addresses: HashSet::new(),
            initcode_length,
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
            ref op,
            ref entity_infos,
            ref tracer_out,
            ref entry_point_out,
            ref mut entities_needing_stake,
            ref mut accessed_addresses,
            initcode_length,
            ..
        } = context;

        let mut violations = vec![];

        if entry_point_out.return_info.sig_failed {
            violations.push(SimulationViolation::InvalidSignature);
        }

        let sender_address = entity_infos.sender_address();
        let mut entity_types_needing_stake = HashMap::new();

        for (index, phase) in tracer_out.phases.iter().enumerate().take(3) {
            let kind = entity_type_from_simulation_phase(index).unwrap();
            let Some(entity_info) = entity_infos.get(kind) else {
                continue;
            };
            let entity = Entity::new(kind, entity_info.address);
            for opcode in &phase.forbidden_opcodes_used {
                let (contract, opcode) = parse_combined_tracer_str(opcode)?;

                // OP-080: staked entities are allowed to use BALANCE and SELFBALANCE
                if entity_info.is_staked
                    && (opcode == Opcode::BALANCE || opcode == Opcode::SELFBALANCE)
                {
                    continue;
                }

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

            if entity.kind == EntityType::Paymaster
                && !entry_point_out.return_info.paymaster_context.is_empty()
                && !entity_info.is_staked
            {
                // [EREP-050]
                violations.push(SimulationViolation::UnstakedPaymasterContext);
            }

            let mut banned_slots_accessed = IndexSet::<StorageSlot>::new();
            for (addr, access_info) in &phase.storage_accesses {
                let address = *addr;
                accessed_addresses.insert(address);

                let violation = parse_storage_accesses(ParseStorageAccess {
                    access_info,
                    slots_by_address: &tracer_out.associated_slots_by_address,
                    address,
                    sender: sender_address,
                    entrypoint: self.entry_point_address,
                    initcode_length,
                    entity: &entity,
                    entity_infos,
                })?;

                match violation {
                    StorageRestriction::Allowed => {}
                    StorageRestriction::NeedsStake(addr, entity_type, slot) => {
                        if !entity_info.is_staked {
                            if let Some(et) = entity_type {
                                if let Some(e_info) = entity_infos.get(et) {
                                    let ent = Entity::new(et, e_info.address);
                                    entity_types_needing_stake
                                        .insert(ent, (addr, entity_type, slot));
                                }
                            } else {
                                entity_types_needing_stake
                                    .insert(entity, (addr, entity_type, slot));
                            }
                        }
                    }
                    StorageRestriction::Banned(slot) => {
                        banned_slots_accessed.insert(StorageSlot { address, slot });
                    }
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
            if !is_staked(aggregator_info.stake_info, self.sim_settings) {
                violations.push(SimulationViolation::UnstakedAggregator)
            }
        }

        for (ent, (accessed_address, accessed_entity, slot)) in entity_types_needing_stake {
            entities_needing_stake.push(ent.kind);

            violations.push(SimulationViolation::NotStaked(Box::new(
                NeedsStakeInformation {
                    entity: ent,
                    accessed_address,
                    accessed_entity,
                    slot,
                    min_stake: self.sim_settings.min_stake_value.into(),
                    min_unstake_delay: self.sim_settings.min_unstake_delay.into(),
                },
            )));
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

        // This is a special case to cover a bug in the 0.6 entrypoint contract where a specially
        // crafted UO can use extra verification gas that isn't caught during simulation, but when
        // it runs on chain causes the transaction to revert.
        let verification_gas_used = entry_point_out
            .return_info
            .pre_op_gas
            .saturating_sub(op.pre_verification_gas);
        let verification_buffer = op
            .verification_gas_limit
            .saturating_sub(verification_gas_used);
        if verification_buffer < REQUIRED_VERIFICATION_GAS_LIMIT_BUFFER {
            violations.push(SimulationViolation::VerificationGasLimitBufferTooLow(
                op.verification_gas_limit,
                verification_gas_used + REQUIRED_VERIFICATION_GAS_LIMIT_BUFFER,
            ));
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
            return Err(SimulationError {
                violation_error: ViolationError::Violations(violations),
                entity_infos: None,
            });
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
    ) -> Result<SimulationResult, SimulationError> {
        let (block_hash, block_number) = match block_hash {
            // If we are given a block_hash, we return a None block number, avoiding an extra call
            Some(block_hash) => (block_hash, None),
            None => {
                let hash_and_num = self
                    .provider
                    .get_latest_block_hash_and_number()
                    .await
                    .map_err(anyhow::Error::from)?;
                (hash_and_num.0, Some(hash_and_num.1.as_u64()))
            }
        };
        let block_id = block_hash.into();
        let mut context = match self.create_context(op.clone(), block_id).await {
            Ok(context) => context,
            error @ Err(_) => error?,
        };

        // Gather all violations from the tracer
        let mut overridable_violations = self.gather_context_violations(&mut context)?;
        // Sort violations so that the final error message is deterministic
        overridable_violations.sort();
        // Check violations against mempool rules, find supporting mempools, error if none found
        let mempools = match match_mempools(&self.mempool_configs, &overridable_violations) {
            MempoolMatchResult::Matches(pools) => pools,
            MempoolMatchResult::NoMatch(i) => {
                return Err(SimulationError {
                    violation_error: ViolationError::Violations(vec![
                        overridable_violations[i].clone()
                    ]),
                    entity_infos: Some(context.entity_infos),
                })
            }
        };

        // Check code hash and aggregator signature, these can't fail
        let (code_hash, aggregator) = self
            .check_contracts(op, &mut context, expected_code_hash)
            .await?;

        // Transform outputs into success struct
        let ValidationContext {
            tracer_out,
            entry_point_out,
            entities_needing_stake,
            accessed_addresses,
            associated_addresses,
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

        // Conduct any stake overrides before assigning entity_infos
        context
            .entity_infos
            .override_is_staked(&self.allow_unstaked_addresses);

        Ok(SimulationResult {
            mempools,
            block_hash,
            block_number,
            pre_op_gas,
            valid_time_range: ValidTimeRange::new(valid_after, valid_until),
            aggregator,
            code_hash,
            entities_needing_stake,
            account_is_staked,
            accessed_addresses,
            associated_addresses,
            expected_storage: tracer_out.expected_storage,
            requires_post_op: !paymaster_context.is_empty(),
            entity_infos: context.entity_infos,
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
    #[display("Unstaked {0.entity} accessed {0.accessed_address} ({0.accessed_entity:?}) at slot {0.slot}")]
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

#[derive(Debug)]
struct ValidationContext {
    op: UserOperation,
    block_id: BlockId,
    entity_infos: EntityInfos,
    tracer_out: SimulationTracerOutput,
    entry_point_out: ValidationOutput,
    entities_needing_stake: Vec<EntityType>,
    accessed_addresses: HashSet<Address>,
    initcode_length: usize,
    associated_addresses: HashSet<Address>,
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

    fn type_from_address(self, address: Address) -> Option<EntityType> {
        if address.eq(&self.sender.address) {
            return Some(EntityType::Account);
        }

        if let Some(factory) = self.factory {
            if address.eq(&factory.address) {
                return Some(EntityType::Factory);
            }
        }

        if let Some(paymaster) = self.paymaster {
            if address.eq(&paymaster.address) {
                return Some(EntityType::Paymaster);
            }
        }

        if let Some(aggregator) = self.aggregator {
            if address.eq(&aggregator.address) {
                return Some(EntityType::Aggregator);
            }
        }

        None
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
    Allowed,
    NeedsStake(Address, Option<EntityType>, U256),
    Banned(U256),
}

/// Information about a storage violation based on stake status
#[derive(Debug, PartialEq, Clone, PartialOrd, Eq, Ord)]
pub struct NeedsStakeInformation {
    /// Entity of stake information
    pub entity: Entity,
    /// Address that was accessed while unstaked
    pub accessed_address: Address,
    /// Type of accessed entity if it is a known entity
    pub accessed_entity: Option<EntityType>,
    /// The accessed slot number
    pub slot: U256,
    /// Minumum stake
    pub min_stake: U256,
    /// Minumum delay after an unstake event
    pub min_unstake_delay: U256,
}

#[derive(Clone, Debug)]
struct ParseStorageAccess<'a> {
    access_info: &'a AccessInfo,
    slots_by_address: &'a AssociatedSlotsByAddress,
    address: Address,
    sender: Address,
    entrypoint: Address,
    initcode_length: usize,
    entity: &'a Entity,
    entity_infos: &'a EntityInfos,
}

fn parse_storage_accesses(args: ParseStorageAccess<'_>) -> Result<StorageRestriction, Error> {
    let ParseStorageAccess {
        access_info,
        address,
        sender,
        entrypoint,
        entity_infos,
        entity,
        slots_by_address,
        initcode_length,
        ..
    } = args;

    if address.eq(&sender) || address.eq(&entrypoint) {
        return Ok(StorageRestriction::Allowed);
    }

    let mut required_stake_slot = None;

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

        if is_sender_associated {
            if initcode_length > 2
                // special case: account.validateUserOp is allowed to use assoc storage if factory is staked.
                // [STO-022], [STO-021]
                && !(entity.address.eq(&sender)
                    && entity_infos
                        .factory
                        .expect("Factory needs to be present and staked")
                        .is_staked)
            {
                return Ok(StorageRestriction::NeedsStake(
                    entity_infos.factory.unwrap().address,
                    Some(EntityType::Factory),
                    *slot,
                ));
            }
        } else if is_entity_associated || is_same_address || is_read_permission {
            required_stake_slot = Some(slot);
        } else {
            return Ok(StorageRestriction::Banned(*slot));
        }
    }

    if let Some(required_stake_slot) = required_stake_slot {
        if let Some(entity_type) = entity_infos.type_from_address(address) {
            return Ok(StorageRestriction::NeedsStake(
                address,
                Some(entity_type),
                *required_stake_slot,
            ));
        }

        return Ok(StorageRestriction::NeedsStake(
            address,
            None,
            *required_stake_slot,
        ));
    }

    Ok(StorageRestriction::Allowed)
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
        types::{Address, BlockNumber, Bytes, U64},
        utils::hex,
    };
    use rundler_provider::{AggregatorOut, MockProvider};
    use rundler_types::contracts::get_code_hashes::CodeHashesResult;

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
                    storage_accesses: HashMap::new(),
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
                    storage_accesses:  HashMap::new(),
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
                    storage_accesses: HashMap::new(),
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

        provider
            .expect_get_latest_block_hash_and_number()
            .returning(|| {
                Ok((
                    H256::from_str(
                        "0x38138f1cb4653ab6ab1c89ae3a6acc8705b54bd16a997d880c4421014ed66c3d",
                    )
                    .unwrap(),
                    U64::zero(),
                ))
            });

        tracer
            .expect_trace_simulate_validation()
            .returning(move |_, _, _| Ok(get_test_tracer_output()));

        // The underlying call constructor when getting the code hash in check_contracts
        provider
            .expect_call_constructor()
            .returning(|_, _: Vec<Address>, _, _| {
                Ok(CodeHashesResult {
                    hash: H256::from_str(
                        "0x091cd005abf68e7b82c951a8619f065986132f67a0945153533cfcdd93b6895f",
                    )
                    .unwrap()
                    .into(),
                })
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
            Err(SimulationError { violation_error: ViolationError::Violations(violations), entity_infos: None}) if matches!(
                violations.first(),
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
        let mut writes = HashMap::new();

        writes.insert(
            H256::from_str("0xa3f946b7ed2f016739c6be6031c5579a53d3784a471c3b5f9c2a1f8706c65a4b")
                .unwrap()
                .to_fixed_bytes()
                .into(),
            1,
        );

        tracer_output.phases[1].storage_accesses.insert(
            Address::from_str("0x1c0e100fcf093c64cdaa545b425ad7ed8e8a0db6").unwrap(),
            AccessInfo {
                reads: HashMap::new(),
                writes,
            },
        );

        let mut validation_context = ValidationContext {
            op: UserOperation {
                verification_gas_limit: U256::from(2000),
                pre_verification_gas: U256::from(1000),
                ..Default::default()
            },
            initcode_length: 10,
            associated_addresses: HashSet::new(),
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
                    3000.into(),
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
                ),
                SimulationViolation::VerificationGasLimitBufferTooLow(2000.into(), 4000.into())
            ]
        );
    }

    #[tokio::test]
    async fn test_op_080() {
        let (provider, tracer) = create_base_config();

        let mut tracer_output = get_test_tracer_output();

        // add forbidden opcodes and precompiles
        tracer_output.phases[2].forbidden_opcodes_used = vec![
            String::from("0x8abb13360b87be5eeb1b98647a016add927a136c:SELFBALANCE"),
            String::from("0x8abb13360b87be5eeb1b98647a016add927a136c:BALANCE"),
        ];

        let mut validation_context = ValidationContext {
            op: UserOperation {
                verification_gas_limit: U256::from(100000),
                pre_verification_gas: U256::from(1000),
                ..Default::default()
            },
            initcode_length: 10,
            associated_addresses: HashSet::new(),
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
                    3000.into(),
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
            entities_needing_stake: vec![],
            accessed_addresses: HashSet::new(),
        };

        let simulator = create_simulator(provider, tracer);
        let res = simulator.gather_context_violations(&mut validation_context);

        // unstaked causes errors
        assert_eq!(
            res.unwrap(),
            vec![
                SimulationViolation::InvalidSignature,
                SimulationViolation::UsedForbiddenOpcode(
                    Entity {
                        kind: EntityType::Paymaster,
                        address: Address::from_str("0x8abb13360b87be5eeb1b98647a016add927a136c")
                            .unwrap()
                    },
                    Address::from_str("0x8abb13360b87be5eeb1b98647a016add927a136c").unwrap(),
                    ViolationOpCode(Opcode::SELFBALANCE)
                ),
                SimulationViolation::UsedForbiddenOpcode(
                    Entity {
                        kind: EntityType::Paymaster,
                        address: Address::from_str("0x8abb13360b87be5eeb1b98647a016add927a136c")
                            .unwrap()
                    },
                    Address::from_str("0x8abb13360b87be5eeb1b98647a016add927a136c").unwrap(),
                    ViolationOpCode(Opcode::BALANCE)
                )
            ]
        );

        // staked causes no errors
        validation_context
            .entity_infos
            .paymaster
            .as_mut()
            .unwrap()
            .is_staked = true;
        let res = simulator.gather_context_violations(&mut validation_context);
        assert_eq!(res.unwrap(), vec![SimulationViolation::InvalidSignature]);
    }

    #[tokio::test]
    async fn test_factory_staking_logic() {
        let (provider, tracer) = create_base_config();

        let mut writes: HashMap<U256, u32> = HashMap::new();

        let sender_address =
            Address::from_str("0xb856dbd4fa1a79a46d426f537455e7d3e79ab7c4").unwrap();

        let factory_address =
            Address::from_str("0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789").unwrap();

        let paymaster_address = "0x8abb13360b87be5eeb1b98647a016add927a136c"
            .parse()
            .unwrap();

        let sender_bytes = sender_address.as_bytes().into();

        writes.insert(sender_bytes, 1);

        let mut tracer_output = get_test_tracer_output();
        tracer_output.phases[2].storage_accesses.insert(
            paymaster_address,
            AccessInfo {
                reads: HashMap::new(),
                writes,
            },
        );

        let mut validation_context = ValidationContext {
            op: UserOperation {
                verification_gas_limit: U256::from(100000),
                pre_verification_gas: U256::from(1000),
                ..Default::default()
            },
            initcode_length: 10,
            associated_addresses: HashSet::new(),
            block_id: BlockId::Number(BlockNumber::Latest),
            entity_infos: EntityInfos::new(
                Some(factory_address),
                sender_address,
                Some(paymaster_address),
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
                    3000.into(),
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
            entities_needing_stake: vec![],
            accessed_addresses: HashSet::new(),
        };

        // Create the simulator using the provider and tracer
        let simulator = create_simulator(provider, tracer);
        let res = simulator.gather_context_violations(&mut validation_context);

        let expected = NeedsStakeInformation {
            accessed_entity: Some(EntityType::Factory),
            accessed_address: factory_address,
            slot: sender_address.as_bytes().into(),
            entity: Entity::new(EntityType::Factory, factory_address),
            min_stake: U256::from(1000000000000000000_u64),
            min_unstake_delay: 84600.into(),
        };

        assert_eq!(
            res.unwrap(),
            vec![SimulationViolation::NotStaked(Box::new(expected))]
        );

        // staked causes no errors
        validation_context
            .entity_infos
            .factory
            .as_mut()
            .unwrap()
            .is_staked = true;
        let res = simulator.gather_context_violations(&mut validation_context);
        assert_eq!(res.unwrap(), vec![]);
    }
}
