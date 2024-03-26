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
    types::{Address, BlockId, H256},
};
use indexmap::IndexSet;
use rundler_provider::{
    AggregatorOut, AggregatorSimOut, EntryPoint, Provider, SignatureAggregator, SimulationProvider,
};
use rundler_types::{
    contracts::v0_6::i_entry_point::FailedOp,
    pool::{NeedsStakeInformation, SimulationViolation},
    v0_6::UserOperation,
    Entity, EntityInfos, EntityType, StorageSlot, UserOperation as UserOperationTrait,
    ValidTimeRange, ValidationOutput, ValidationReturnInfo, ViolationOpCode,
};

use super::{
    tracer::{parse_combined_tracer_str, SimulateValidationTracer, SimulationTracerOutput},
    REQUIRED_VERIFICATION_GAS_LIMIT_BUFFER,
};
use crate::{
    simulation::{
        self,
        mempool::{match_mempools, AllowEntity, AllowRule, MempoolConfig, MempoolMatchResult},
        ParseStorageAccess, Settings, StorageRestriction,
    },
    types::ViolationError,
    utils, SimulationError, SimulationResult,
};

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
pub struct Simulator<P, E, T> {
    provider: Arc<P>,
    entry_point: E,
    simulate_validation_tracer: T,
    sim_settings: Settings,
    mempool_configs: HashMap<H256, MempoolConfig>,
    allow_unstaked_addresses: HashSet<Address>,
}

impl<P, E, T> Simulator<P, E, T>
where
    P: Provider,
    E: EntryPoint
        + SimulationProvider<UO = UserOperation>
        + SignatureAggregator<UO = UserOperation>
        + Clone,
    T: SimulateValidationTracer,
{
    /// Create a new simulator
    ///
    /// `mempool_configs` is a map of mempool IDs to mempool configurations.
    /// It is used during simulation to determine which mempools support
    /// the violations found during simulation.
    pub fn new(
        provider: Arc<P>,
        entry_point: E,
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
            entry_point,
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
        let Ok(entry_point_out) = ValidationOutput::decode_v0_6_hex(revert_data) else {
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
        let entity_infos = simulation::infos_from_validation_output(
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
        let has_factory = op.factory().is_some();
        Ok(ValidationContext {
            op,
            block_id,
            entity_infos,
            tracer_out,
            entry_point_out,
            associated_addresses,
            entities_needing_stake: vec![],
            accessed_addresses: HashSet::new(),
            has_factory,
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

        self.entry_point
            .clone()
            .validate_user_op_signature(aggregator_address, op, gas_cap)
            .await
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
            has_factory,
            ..
        } = context;

        let mut violations = vec![];

        // v0.6 doesn't distinguish between the different types of signature failures
        // both of these will be set to true if the signature failed.
        if entry_point_out.return_info.account_sig_failed
            || entry_point_out.return_info.paymaster_sig_failed
        {
            violations.push(SimulationViolation::InvalidSignature);
        }

        let sender_address = entity_infos.sender_address();
        let mut entity_types_needing_stake = HashMap::new();

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
                if *addr == self.entry_point.address() {
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

                let violation = simulation::parse_storage_accesses(ParseStorageAccess {
                    access_info,
                    slots_by_address: &tracer_out.associated_slots_by_address,
                    address,
                    sender: sender_address,
                    entrypoint: self.entry_point.address(),
                    has_factory,
                    entity: &entity,
                    entity_infos,
                })?;

                match violation {
                    StorageRestriction::Allowed => {}
                    StorageRestriction::NeedsStake(addr, entity_type, slot) => {
                        if !entity_info.is_staked {
                            entity_types_needing_stake.insert(entity, (addr, entity_type, slot));
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
            if !simulation::is_staked(aggregator_info.stake_info, self.sim_settings) {
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
                        self.entry_point.address(),
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
            .total_verification_gas_limit()
            .saturating_sub(verification_gas_used);
        if verification_buffer < REQUIRED_VERIFICATION_GAS_LIMIT_BUFFER {
            violations.push(SimulationViolation::VerificationGasLimitBufferTooLow(
                op.total_verification_gas_limit(),
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
impl<P, E, T> simulation::Simulator for Simulator<P, E, T>
where
    P: Provider,
    E: EntryPoint
        + SimulationProvider<UO = UserOperation>
        + SignatureAggregator<UO = UserOperation>
        + Clone,
    T: SimulateValidationTracer,
{
    type UO = UserOperation;

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
        let account_is_staked = simulation::is_staked(sender_info, self.sim_settings);
        let ValidationReturnInfo {
            pre_op_gas,
            valid_after,
            valid_until,
            paymaster_context,
            ..
        } = return_info;

        // Conduct any stake overrides before assigning entity_infos
        simulation::override_infos_staked(
            &mut context.entity_infos,
            &self.allow_unstaked_addresses,
        );

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
    has_factory: bool,
    associated_addresses: HashSet<Address>,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ethers::{
        abi::AbiEncode,
        types::{Address, BlockNumber, Bytes, Opcode, U256, U64},
        utils::hex,
    };
    use rundler_provider::{AggregatorOut, MockEntryPointV0_6, MockProvider};
    use rundler_types::{contracts::utils::get_code_hashes::CodeHashesResult, StakeInfo};

    use super::*;
    use crate::simulation::{
        v0_6::tracer::{MockSimulateValidationTracer, Phase},
        AccessInfo, Simulator as SimulatorTrait,
    };

    fn create_base_config() -> (
        MockProvider,
        MockEntryPointV0_6,
        MockSimulateValidationTracer,
    ) {
        (
            MockProvider::new(),
            MockEntryPointV0_6::new(),
            MockSimulateValidationTracer::new(),
        )
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
        entry_point: MockEntryPointV0_6,
        simulate_validation_tracer: MockSimulateValidationTracer,
    ) -> Simulator<MockProvider, Arc<MockEntryPointV0_6>, MockSimulateValidationTracer> {
        let settings = Settings::default();

        let mut mempool_configs = HashMap::new();
        mempool_configs.insert(H256::zero(), MempoolConfig::default());

        let provider = Arc::new(provider);

        let simulator: Simulator<
            MockProvider,
            Arc<MockEntryPointV0_6>,
            MockSimulateValidationTracer,
        > = Simulator::new(
            Arc::clone(&provider),
            Arc::new(entry_point),
            simulate_validation_tracer,
            settings,
            mempool_configs,
        );

        simulator
    }

    #[tokio::test]
    async fn test_simulate_validation() {
        let (mut provider, mut entry_point, mut tracer) = create_base_config();

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

        entry_point
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

        let simulator = create_simulator(provider, entry_point, tracer);
        let res = simulator
            .simulate_validation(user_operation, None, None)
            .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_create_context_two_phases_unintended_revert() {
        let (provider, entry_point, mut tracer) = create_base_config();

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

        let simulator = create_simulator(provider, entry_point, tracer);
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
        let (provider, mut entry_point, tracer) = create_base_config();
        entry_point
            .expect_address()
            .returning(|| Address::from_str("0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789").unwrap());

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
            has_factory: true,
            associated_addresses: HashSet::new(),
            block_id: BlockId::Number(BlockNumber::Latest),
            entity_infos: simulation::infos_from_validation_output(
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

        let simulator = create_simulator(provider, entry_point, tracer);
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
}
