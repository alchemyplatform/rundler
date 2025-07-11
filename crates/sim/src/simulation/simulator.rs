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
    marker::PhantomData,
};

use alloy_primitives::{Address, B256, U256};
use async_trait::async_trait;
use futures_util::TryFutureExt;
use rundler_provider::{EntryPoint, EvmProvider, SimulationProvider};
use rundler_types::{
    pool::{NeedsStakeInformation, SimulationViolation},
    v0_6::UserOperation as UserOperationV0_6,
    v0_7::UserOperation as UserOperationV0_7,
    Entity, EntityInfo, EntityInfos, EntityType, Opcode, StorageSlot, UserOperation,
    ValidTimeRange, ValidationOutput, ValidationReturnInfo, ViolationOpCode,
};

use super::{
    context::{
        self, AccessInfo, AssociatedSlotsByAddress, ValidationContext, ValidationContextProvider,
    },
    UnsafeSimulator,
};
use crate::{
    simulation::{
        mempool::{self, AllowEntity, AllowRule, MempoolConfig, MempoolMatchResult},
        v0_6::ValidationContextProvider as ValidationContextProviderV0_6,
        v0_7::ValidationContextProvider as ValidationContextProviderV0_7,
        Settings, Simulator,
    },
    types::ViolationError,
    SimulationError, SimulationResult,
};

/// Create a new simulator for v0.6 entry point contracts
pub fn new_v0_6_simulator<P, E>(
    provider: P,
    entry_point: E,
    sim_settings: Settings,
    mempool_configs: HashMap<B256, MempoolConfig>,
) -> impl Simulator<UO = UserOperationV0_6>
where
    P: EvmProvider + Clone,
    E: EntryPoint + SimulationProvider<UO = UserOperationV0_6> + Clone,
{
    SimulatorImpl::new(
        provider.clone(),
        entry_point.clone(),
        ValidationContextProviderV0_6::new(provider, entry_point, sim_settings.clone()),
        sim_settings,
        mempool_configs,
    )
}

/// Create a new simulator for v0.6 entry point contracts
pub fn new_v0_7_simulator<P, E>(
    provider: P,
    entry_point: E,
    sim_settings: Settings,
    mempool_configs: HashMap<B256, MempoolConfig>,
) -> impl Simulator<UO = UserOperationV0_7>
where
    P: EvmProvider + Clone,
    E: EntryPoint + SimulationProvider<UO = UserOperationV0_7> + Clone,
{
    SimulatorImpl::new(
        provider.clone(),
        entry_point.clone(),
        ValidationContextProviderV0_7::new(provider, entry_point, sim_settings.clone()),
        sim_settings,
        mempool_configs,
    )
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
pub struct SimulatorImpl<UO, P, E, V> {
    provider: P,
    entry_point: E,
    validation_context_provider: V,
    sim_settings: Settings,
    mempool_configs: HashMap<B256, MempoolConfig>,
    allow_unstaked_addresses: HashSet<Address>,
    unsafe_sim: UnsafeSimulator<UO, E>,
    _uo_type: PhantomData<UO>,
}

impl<UO, P, E, V> SimulatorImpl<UO, P, E, V>
where
    UO: UserOperation,
    P: EvmProvider,
    E: EntryPoint + Clone,
    V: ValidationContextProvider<UO = UO>,
{
    /// Create a new simulator
    ///
    /// `mempool_configs` is a map of mempool IDs to mempool configurations.
    /// It is used during simulation to determine which mempools support
    /// the violations found during simulation.
    pub fn new(
        provider: P,
        entry_point: E,
        validation_context_provider: V,
        sim_settings: Settings,
        mempool_configs: HashMap<B256, MempoolConfig>,
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
            unsafe_sim: UnsafeSimulator::new(entry_point.clone(), sim_settings.clone()),
            entry_point,
            validation_context_provider,
            sim_settings,
            mempool_configs,
            allow_unstaked_addresses,
            _uo_type: PhantomData,
        }
    }

    // Parse the output from tracing and return a list of violations.
    // Most violations found during this stage are allowlistable and can be added
    // to the list of allowlisted violations on a given mempool.
    fn gather_context_violations(
        &self,
        context: &mut ValidationContext<UO>,
    ) -> Result<Vec<SimulationViolation>, SimulationError> {
        let &mut ValidationContext {
            ref entity_infos,
            ref tracer_out,
            ref entry_point_out,
            ref mut accessed_addresses,
            has_factory,
            ..
        } = context;

        let mut violations = vec![];

        let sender_address = entity_infos.sender_address();
        for (index, phase) in tracer_out.phases.iter().enumerate().take(3) {
            let kind = context::entity_type_from_simulation_phase(index).unwrap();
            let Some(ei) = entity_infos.get(kind) else {
                continue;
            };
            for opcode in &phase.forbidden_opcodes_used {
                let (contract, opcode) = context::parse_combined_context_str(opcode)?;

                // [OP-080] - staked entities are allowed to use BALANCE and SELFBALANCE
                if ei.is_staked && (opcode == Opcode::BALANCE || opcode == Opcode::SELFBALANCE) {
                    continue;
                }

                // [OP-011]
                violations.push(SimulationViolation::UsedForbiddenOpcode(
                    ei.entity,
                    contract,
                    ViolationOpCode(opcode),
                ));
            }

            for (addr, opcode) in &phase.ext_code_access_info {
                if addr == self.entry_point.address() {
                    // [OP-054]
                    // [OP-051] - If calling `EXTCODESIZE ISZERO` the tracer won't add to this list
                    violations.push(SimulationViolation::UsedForbiddenOpcode(
                        ei.entity,
                        *addr,
                        ViolationOpCode(*opcode),
                    ));
                }
            }

            for precompile in &phase.forbidden_precompiles_used {
                let (contract, precompile) = context::parse_combined_context_str(precompile)?;
                // [OP-062]
                violations.push(SimulationViolation::UsedForbiddenPrecompile(
                    ei.entity, contract, precompile,
                ));
            }

            for (addr, access_info) in &phase.storage_accesses {
                let address = *addr;
                accessed_addresses.insert(address);

                let restrictions = parse_storage_accesses(ParseStorageAccess {
                    access_info,
                    slots_by_address: &tracer_out.associated_slots_by_address,
                    address,
                    sender: sender_address,
                    entrypoint: *self.entry_point.address(),
                    has_factory,
                    entity: &ei.entity,
                });

                for restriction in restrictions {
                    match restriction {
                        StorageRestriction::NeedsStake(
                            needs_stake,
                            accessing_entity,
                            accessed_entity,
                            accessed_address,
                            slot,
                        ) => {
                            let needs_stake_entity = entity_infos
                                .get(needs_stake)
                                .expect("entity type not found in entity_infos");

                            if !needs_stake_entity.is_staked {
                                // [STO-*]
                                violations.push(SimulationViolation::NotStaked(Box::new(
                                    NeedsStakeInformation {
                                        needs_stake: ei.entity,
                                        accessing_entity,
                                        accessed_entity,
                                        accessed_address,
                                        slot,
                                        min_stake: self.sim_settings.min_stake_value,
                                        min_unstake_delay: self.sim_settings.min_unstake_delay,
                                    },
                                )));
                            }
                        }
                        StorageRestriction::AssociatedStorageDuringDeploy(
                            needs_stake,
                            address,
                            slot,
                        ) => {
                            let needs_stake_entity = needs_stake.and_then(|t| entity_infos.get(t));

                            if needs_stake.is_none() {
                                if let Some(factory) = entity_infos.get(EntityType::Factory) {
                                    if factory.is_staked {
                                        tracing::debug!("Associated storage accessed by staked entity during deploy, and factory is staked");
                                        continue;
                                    }
                                }
                            }

                            if let Some(needs_stake_entity_info) = needs_stake_entity {
                                if needs_stake_entity_info.is_staked {
                                    tracing::debug!("Associated storage accessed by staked entity during deploy, and entity is staked");
                                    continue;
                                }
                            }

                            // [STO-022]
                            violations.push(SimulationViolation::AssociatedStorageDuringDeploy(
                                needs_stake_entity.map(|ei| ei.entity),
                                StorageSlot { address, slot },
                            ))
                        }
                        StorageRestriction::Banned(slot) => {
                            // [STO-*]
                            violations.push(SimulationViolation::InvalidStorageAccess(
                                ei.entity,
                                StorageSlot { address, slot },
                            ));
                        }
                    }
                }
            }

            if phase.called_non_entry_point_with_value {
                // [OP-061]
                violations.push(SimulationViolation::CallHadValue(ei.entity));
            }
            if phase.called_banned_entry_point_method {
                // [OP-054]
                violations.push(SimulationViolation::CalledBannedEntryPointMethod(ei.entity));
            }

            if phase.ran_out_of_gas {
                // [OP-020]
                violations.push(SimulationViolation::OutOfGas(ei.entity));
            }
            for &address in &phase.undeployed_contract_accesses {
                // OP-042 - Factory can access undeployed sender
                if ei.entity.kind == EntityType::Factory && address == sender_address {
                    continue;
                }
                // OP-041 - Access to an address without deployed code is forbidden
                violations.push(SimulationViolation::AccessedUndeployedContract(
                    ei.entity, address,
                ))
            }
        }

        if !entry_point_out.return_info.is_valid_time_range() {
            violations.push(SimulationViolation::InvalidTimeRange(
                entry_point_out.return_info.valid_until,
                entry_point_out.return_info.valid_after,
            ));
        }

        if let Some(agg_info) = entry_point_out.aggregator_info {
            if let Some(agg) = context.op.aggregator() {
                if agg_info.address != agg {
                    violations.push(SimulationViolation::AggregatorMismatch(
                        agg,
                        agg_info.address,
                    ));
                }
            } else {
                violations.push(SimulationViolation::AggregatorMismatch(
                    Address::ZERO,
                    agg_info.address,
                ));
            }
        }

        for (address, contract_info) in &tracer_out.accessed_contracts {
            if contract_info.header.as_str() == "0xEFF000" {
                // All arbitrum stylus contracts start with 0xEFF000
                violations.push(SimulationViolation::AccessedUnsupportedContractType(
                    "Arbitrum Stylus".to_string(),
                    *address,
                ));
            }
        }

        if tracer_out.factory_called_create2_twice {
            let factory = entity_infos.get(EntityType::Factory);
            match factory {
                Some(factory) => {
                    // [OP-031]
                    violations.push(SimulationViolation::FactoryCalledCreate2Twice(
                        factory.entity.address,
                    ));
                }
                None => {
                    // [OP-031]
                    // weird case where CREATE2 is called > 1, but there isn't a factory
                    // defined. This should never happen, blame the violation on the entry point.
                    violations.push(SimulationViolation::FactoryCalledCreate2Twice(
                        *self.entry_point.address(),
                    ));
                }
            }
        }

        // Get violations specific to the implemented entry point from the context provider
        violations.extend(
            self.validation_context_provider
                .get_specific_violations(context)?,
        );

        Ok(violations)
    }

    // Check the code hash of the entities associated with the user operation
    // Violations during this stage are always errors.
    async fn check_code_hash(
        &self,
        context: &mut ValidationContext<UO>,
        expected_code_hash: Option<B256>,
    ) -> Result<B256, SimulationError> {
        let &mut ValidationContext {
            block_id,
            ref mut tracer_out,
            ..
        } = context;

        // collect a vector of violations to ensure a deterministic error message
        let mut violations = vec![];

        let code_hash = self
            .provider
            .get_code_hash(
                tracer_out.accessed_contracts.keys().cloned().collect(),
                Some(block_id),
            )
            .map_err(|e| SimulationError::from(anyhow::anyhow!("should call get_code_hash {e:?}")))
            .await?;

        if let Some(expected_code_hash) = expected_code_hash {
            // [COD-010]
            if expected_code_hash != code_hash {
                violations.push(SimulationViolation::CodeHashChanged)
            }
        }

        if !violations.is_empty() {
            return Err(SimulationError {
                violation_error: ViolationError::Violations(violations),
                entity_infos: None,
            });
        }

        Ok(code_hash)
    }
}

#[async_trait]
impl<UO, P, E, V> Simulator for SimulatorImpl<UO, P, E, V>
where
    UO: UserOperation,
    P: EvmProvider,
    E: EntryPoint + SimulationProvider<UO = UO> + Clone,
    V: ValidationContextProvider<UO = UO>,
{
    type UO = UO;

    async fn simulate_validation(
        &self,
        op: UO,
        trusted: bool,
        block_hash: B256,
        expected_code_hash: Option<B256>,
    ) -> Result<SimulationResult, SimulationError> {
        if trusted {
            return self
                .unsafe_sim
                .simulate_validation(op, trusted, block_hash, expected_code_hash)
                .await;
        }

        let block_id = block_hash.into();
        let mut context = match self
            .validation_context_provider
            .get_context(op.clone(), block_id)
            .await
        {
            Ok(context) => context,
            error @ Err(ViolationError::Other(_)) => {
                if self.sim_settings.enable_unsafe_fallback {
                    tracing::warn!(
                        "tracing error with enable_unsafe_fallback set, falling back to unsafe sim. Error: {error:?}"
                    );
                    return self
                        .unsafe_sim
                        .simulate_validation(op, trusted, block_hash, expected_code_hash)
                        .await;
                } else {
                    error?
                }
            }
            error @ Err(ViolationError::Violations(_)) => error?,
        };

        // Gather all violations from the tracer
        let mut overridable_violations = self.gather_context_violations(&mut context)?;
        // Sort violations so that the final error message is deterministic
        overridable_violations.sort();
        // Check violations against mempool rules, find supporting mempools, error if none found
        let mempools = match mempool::match_mempools(&self.mempool_configs, &overridable_violations)
        {
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

        let code_hash = self
            .check_code_hash(&mut context, expected_code_hash)
            .await?;

        // Transform outputs into success struct
        let ValidationContext {
            tracer_out,
            entry_point_out,
            accessed_addresses,
            associated_addresses,
            ..
        } = context;
        let ValidationOutput {
            return_info,
            sender_info,
            ..
        } = entry_point_out;
        let account_is_staked = context::is_staked(sender_info, &self.sim_settings);
        let ValidationReturnInfo {
            pre_op_gas,
            valid_after,
            valid_until,
            paymaster_context,
            ..
        } = return_info;

        // Conduct any stake overrides before assigning entity_infos
        override_infos_staked(&mut context.entity_infos, &self.allow_unstaked_addresses);

        Ok(SimulationResult {
            mempools,
            pre_op_gas,
            valid_time_range: ValidTimeRange::new(valid_after, valid_until),
            code_hash,
            account_is_staked,
            accessed_addresses,
            associated_addresses,
            expected_storage: tracer_out.expected_storage,
            requires_post_op: !paymaster_context.is_empty(),
            entity_infos: context.entity_infos,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum StorageRestriction {
    /// (Entity needing stake, accessing entity type, accessed entity type, accessed address, accessed slot)
    NeedsStake(EntityType, EntityType, Option<EntityType>, Address, U256),
    AssociatedStorageDuringDeploy(Option<EntityType>, Address, U256),
    Banned(U256),
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

fn parse_storage_accesses(args: ParseStorageAccess<'_>) -> Vec<StorageRestriction> {
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

    // [STO-010] - always allowed to access storage on the account
    // [OP-054] - block access to the entrypoint, except for depositTo and fallback
    //   - this is handled at another level, so we don't need to check for it here
    //   - at this level we can allow any entry point access through
    if address.eq(&sender) || address.eq(&entrypoint) {
        return restrictions;
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

        // [STO-021] - Associated storage on external contracts is allowed
        if is_sender_associated && !is_same_address {
            // [STO-022] - Factory must be staked to access associated storage in a deploy
            if has_factory {
                match entity.kind {
                    EntityType::Paymaster | EntityType::Aggregator => {
                        // If its a paymaster/aggregator, then the entity OR factory must be staked to access associated storage
                        // during a deploy
                        restrictions.push(StorageRestriction::AssociatedStorageDuringDeploy(
                            Some(entity.kind),
                            address,
                            *slot,
                        ));
                    }
                    // If its a factory/account, then the factory must be staked to access associated storage during a deploy
                    EntityType::Account | EntityType::Factory => {
                        restrictions.push(StorageRestriction::AssociatedStorageDuringDeploy(
                            None, address, *slot,
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

    restrictions
}

fn override_is_staked(ei: &mut EntityInfo, allow_unstaked_addresses: &HashSet<Address>) {
    ei.is_staked = allow_unstaked_addresses.contains(&ei.entity.address) || ei.is_staked;
}

fn override_infos_staked(eis: &mut EntityInfos, allow_unstaked_addresses: &HashSet<Address>) {
    override_is_staked(&mut eis.sender, allow_unstaked_addresses);

    if let Some(mut factory) = eis.factory {
        override_is_staked(&mut factory, allow_unstaked_addresses);
    }
    if let Some(mut paymaster) = eis.paymaster {
        override_is_staked(&mut paymaster, allow_unstaked_addresses);
    }
    if let Some(mut aggregator) = eis.aggregator {
        override_is_staked(&mut aggregator, allow_unstaked_addresses);
    }
}

#[cfg(test)]
mod tests {
    use std::{ops::Sub, sync::Arc, time::Duration};

    use alloy_primitives::{address, b256, bytes, uint, Bytes};
    use context::ContractInfo;
    use rundler_provider::{BlockId, BlockNumberOrTag, MockEntryPointV0_6, MockEvmProvider};
    use rundler_types::{
        aggregator::AggregatorCosts,
        chain::ChainSpec,
        v0_6::{UserOperation, UserOperationBuilder, UserOperationRequiredFields},
        AggregatorInfo, Opcode, StakeInfo, Timestamp, UserOperation as _,
    };

    use self::context::{Phase, TracerOutput};
    use super::*;

    mockall::mock! {
        ValidationContextProviderV0_6 {}

        #[async_trait::async_trait]
        impl ValidationContextProvider for ValidationContextProviderV0_6 {
            type UO = UserOperation;
            async fn get_context(
                &self,
                op: UserOperationV0_6,
                block_id: rundler_provider::BlockId,
            ) -> Result<ValidationContext<UserOperationV0_6>, ViolationError<SimulationViolation>>;
            fn get_specific_violations(
                &self,
                context: &ValidationContext<UserOperationV0_6>,
            ) -> anyhow::Result<Vec<SimulationViolation>>;
        }
    }

    fn create_base_config() -> (
        MockEvmProvider,
        MockEntryPointV0_6,
        MockValidationContextProviderV0_6,
    ) {
        (
            MockEvmProvider::new(),
            MockEntryPointV0_6::new(),
            MockValidationContextProviderV0_6::new(),
        )
    }

    fn get_test_context() -> ValidationContext<UserOperation> {
        let tracer_out = TracerOutput {
            accessed_contracts: HashMap::from([
                (
                    address!("5ff137d4b0fdcd49dca30c7cf57e578a026d2789"),
                    ContractInfo {
                        header: "0x608060".to_string(),
                        opcode: Opcode::CALL,
                        length: 32,
                    }
                ),
                (
                    address!("b856dbd4fa1a79a46d426f537455e7d3e79ab7c4"),
                    ContractInfo {
                        header: "0x608060".to_string(),
                        opcode: Opcode::CALL,
                        length: 32,
                    }
                ),
                (
                    address!("8abb13360b87be5eeb1b98647a016add927a136c"),
                    ContractInfo {
                        header: "0x608060".to_string(),
                        opcode: Opcode::CALL,
                        length: 32,
                    }
                ),
            ]),
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
        };

        ValidationContext {
            op: UserOperationBuilder::new(
                &ChainSpec::default(),
                UserOperationRequiredFields {
                    verification_gas_limit: 2000,
                    pre_verification_gas: 1000,
                    ..Default::default()
                },
            )
            .build(),
            has_factory: true,
            associated_addresses: HashSet::new(),
            block_id: BlockId::Number(BlockNumberOrTag::Latest),
            entity_infos: context::infos_from_validation_output(
                Some(address!("5ff137d4b0fdcd49dca30c7cf57e578a026d2789")),
                address!("b856dbd4fa1a79a46d426f537455e7d3e79ab7c4"),
                Some(address!("8abb13360b87be5eeb1b98647a016add927a136c")),
                &ValidationOutput {
                    return_info: ValidationReturnInfo::default(),
                    sender_info: StakeInfo::default(),
                    factory_info: StakeInfo::default(),
                    paymaster_info: StakeInfo::default(),
                    aggregator_info: None,
                },
                &Settings::default(),
            ),
            tracer_out,
            entry_point_out: ValidationOutput {
                return_info: ValidationReturnInfo {
                    pre_op_gas: 3000,
                    account_sig_failed: true,
                    paymaster_sig_failed: true,
                    valid_after: 0.into(),
                    valid_until: u64::MAX.into(),
                    paymaster_context: Bytes::default(),
                },
                sender_info: StakeInfo::default(),
                factory_info: StakeInfo::default(),
                paymaster_info: StakeInfo::default(),
                aggregator_info: None,
            },
            accessed_addresses: HashSet::new(),
        }
    }

    fn create_simulator(
        provider: MockEvmProvider,
        entry_point: MockEntryPointV0_6,
        context: MockValidationContextProviderV0_6,
    ) -> SimulatorImpl<
        UserOperation,
        MockEvmProvider,
        Arc<MockEntryPointV0_6>,
        MockValidationContextProviderV0_6,
    > {
        let settings = Settings::default();

        let mut mempool_configs = HashMap::new();
        mempool_configs.insert(B256::ZERO, MempoolConfig::default());

        SimulatorImpl::new(
            provider,
            Arc::new(entry_point),
            context,
            settings,
            mempool_configs,
        )
    }

    #[tokio::test]
    async fn test_simulate_validation() {
        let (mut provider, entry_point, mut context) = create_base_config();

        provider
            .expect_get_latest_block_hash_and_number()
            .returning(|| {
                Ok((
                    b256!("38138f1cb4653ab6ab1c89ae3a6acc8705b54bd16a997d880c4421014ed66c3d"),
                    0,
                ))
            });

        provider.expect_get_code_hash().returning(|_, _| {
            Ok(b256!(
                "091cd005abf68e7b82c951a8619f065986132f67a0945153533cfcdd93b6895f"
            ))
        });

        context
            .expect_get_context()
            .returning(move |_, _| Ok(get_test_context()));
        context
            .expect_get_specific_violations()
            .returning(|_| Ok(vec![]));

        let user_operation = UserOperationBuilder::new(
            &ChainSpec::default(),
            UserOperationRequiredFields {
                sender: address!("b856dbd4fa1a79a46d426f537455e7d3e79ab7c4"),
                nonce: U256::from(264),
                init_code: Bytes::default(),
                call_data: bytes!("b61d27f6000000000000000000000000b856dbd4fa1a79a46d426f537455e7d3e79ab7c4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000004d087d28800000000000000000000000000000000000000000000000000000000"),
                call_gas_limit: 9100,
                verification_gas_limit: 64805,
                pre_verification_gas: 46128,
                max_fee_per_gas: 105000100,
                max_priority_fee_per_gas: 105000000,
                paymaster_and_data: Bytes::default(),
                signature: bytes!("98f89993ce573172635b44ef3b0741bd0c19dd06909d3539159f6d66bef8c0945550cc858b1cf5921dfce0986605097ba34c2cf3fc279154dd25e161ea7b3d0f1c"),
            }
        ).build();

        let simulator = create_simulator(provider, entry_point, context);
        let res = simulator
            .simulate_validation(user_operation, false, B256::ZERO, None)
            .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_simulate_validation_trusted() {
        let (provider, mut entry_point, context) = create_base_config();
        let uo = UserOperationBuilder::new(
            &ChainSpec::default(),
            UserOperationRequiredFields::default(),
        )
        .build();

        entry_point.expect_simulate_validation().returning(|_, _| {
            Ok(Ok(ValidationOutput {
                return_info: ValidationReturnInfo::default(),
                sender_info: StakeInfo::default(),
                factory_info: StakeInfo::default(),
                paymaster_info: StakeInfo::default(),
                aggregator_info: None,
            }))
        });

        let simulator = create_simulator(provider, entry_point, context);
        let res = simulator
            .simulate_validation(uo, true, B256::ZERO, None)
            .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_gather_context_violations() {
        let (provider, mut entry_point, mut context_provider) = create_base_config();
        entry_point
            .expect_address()
            .return_const(address!("5ff137d4b0fdcd49dca30c7cf57e578a026d2789"));
        context_provider
            .expect_get_specific_violations()
            .returning(|_| Ok(vec![]));

        let mut context = get_test_context();

        // add forbidden opcodes and precompiles
        context.tracer_out.phases[1].forbidden_opcodes_used = vec![
            String::from("0xb856dbd4fa1a79a46d426f537455e7d3e79ab7c4:GASPRICE"),
            String::from("0xb856dbd4fa1a79a46d426f537455e7d3e79ab7c4:COINBASE"),
        ];
        context.tracer_out.phases[1].forbidden_precompiles_used = vec![String::from(
            "0xb856dbd4fa1a79a46d426f537455e7d3e79ab7c4:0x0000000000000000000000000000000000000019",
        )];

        // add a storage access for a random unrelated address
        let mut writes: HashMap<U256, u64> = HashMap::new();

        writes.insert(
            uint!(0xa3f946b7ed2f016739c6be6031c5579a53d3784a471c3b5f9c2a1f8706c65a4b_U256),
            1,
        );

        context.tracer_out.phases[1].storage_accesses.insert(
            address!("1c0e100fcf093c64cdaa545b425ad7ed8e8a0db6"),
            AccessInfo {
                reads: HashMap::new(),
                writes,
            },
        );

        let simulator = create_simulator(provider, entry_point, context_provider);
        let res = simulator.gather_context_violations(&mut context);

        assert_eq!(
            res.unwrap(),
            vec![
                SimulationViolation::UsedForbiddenOpcode(
                    Entity {
                        kind: EntityType::Account,
                        address: address!("b856dbd4fa1a79a46d426f537455e7d3e79ab7c4")
                    },
                    address!("b856dbd4fa1a79a46d426f537455e7d3e79ab7c4"),
                    ViolationOpCode(Opcode::GASPRICE),
                ),
                SimulationViolation::UsedForbiddenOpcode(
                    Entity {
                        kind: EntityType::Account,
                        address: address!("b856dbd4fa1a79a46d426f537455e7d3e79ab7c4")
                    },
                    address!("b856dbd4fa1a79a46d426f537455e7d3e79ab7c4"),
                    ViolationOpCode(Opcode::COINBASE),
                ),
                SimulationViolation::UsedForbiddenPrecompile(
                    Entity {
                        kind: EntityType::Account,
                        address: address!("b856dbd4fa1a79a46d426f537455e7d3e79ab7c4")
                    },
                    address!("b856dbd4fa1a79a46d426f537455e7d3e79ab7c4"),
                    address!("0000000000000000000000000000000000000019"),
                ),
                SimulationViolation::InvalidStorageAccess(
                    Entity {
                        kind: EntityType::Account,
                        address: address!("b856dbd4fa1a79a46d426f537455e7d3e79ab7c4")
                    },
                    StorageSlot {
                        address: address!("1c0e100fcf093c64cdaa545b425ad7ed8e8a0db6"),
                        slot: uint!(
                            0xa3f946b7ed2f016739c6be6031c5579a53d3784a471c3b5f9c2a1f8706c65a4b_U256
                        )
                    }
                ),
            ]
        );
    }

    #[tokio::test]
    async fn test_op_080() {
        let (provider, ep, mut context_provider) = create_base_config();
        context_provider
            .expect_get_specific_violations()
            .returning(|_| Ok(vec![]));

        let mut context = get_test_context();

        // add forbidden opcodes and precompiles
        context.tracer_out.phases[2].forbidden_opcodes_used = vec![
            String::from("0x8abb13360b87be5eeb1b98647a016add927a136c:SELFBALANCE"),
            String::from("0x8abb13360b87be5eeb1b98647a016add927a136c:BALANCE"),
        ];

        let simulator = create_simulator(provider, ep, context_provider);
        let res = simulator.gather_context_violations(&mut context);

        // unstaked causes errors
        assert_eq!(
            res.unwrap(),
            vec![
                SimulationViolation::UsedForbiddenOpcode(
                    Entity {
                        kind: EntityType::Paymaster,
                        address: address!("8abb13360b87be5eeb1b98647a016add927a136c"),
                    },
                    address!("8abb13360b87be5eeb1b98647a016add927a136c"),
                    ViolationOpCode(Opcode::SELFBALANCE)
                ),
                SimulationViolation::UsedForbiddenOpcode(
                    Entity {
                        kind: EntityType::Paymaster,
                        address: address!("8abb13360b87be5eeb1b98647a016add927a136c"),
                    },
                    address!("8abb13360b87be5eeb1b98647a016add927a136c"),
                    ViolationOpCode(Opcode::BALANCE)
                )
            ]
        );

        // staked causes no errors
        context.entity_infos.paymaster.as_mut().unwrap().is_staked = true;
        let res = simulator.gather_context_violations(&mut context);
        assert!(res.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_factory_staking() {
        let (provider, mut ep, mut context_provider) = create_base_config();
        ep.expect_address()
            .return_const(address!("5ff137d4b0fdcd49dca30c7cf57e578a026d2789"));
        context_provider
            .expect_get_specific_violations()
            .returning(|_| Ok(vec![]));

        let mut writes: HashMap<U256, u64> = HashMap::new();

        let sender_address = address!("b856dbd4fa1a79a46d426f537455e7d3e79ab7c4");

        let external_access_address = Address::random();

        let sender_bytes = U256::from_be_bytes(sender_address.into_word().into());

        writes.insert(sender_bytes, 1);

        let mut context = get_test_context();
        context.tracer_out.phases[1].storage_accesses.insert(
            external_access_address,
            AccessInfo {
                reads: HashMap::new(),
                writes,
            },
        );

        // Create the simulator using the provider and tracer
        let simulator = create_simulator(provider, ep, context_provider);
        let res = simulator.gather_context_violations(&mut context);
        let sender_as_slot = U256::from_be_bytes(sender_address.into_word().into());

        assert_eq!(
            res.unwrap(),
            vec![SimulationViolation::AssociatedStorageDuringDeploy(
                None,
                StorageSlot {
                    address: external_access_address,
                    slot: sender_as_slot
                }
            )]
        );

        // staked causes no errors
        context.entity_infos.factory.as_mut().unwrap().is_staked = true;
        let res = simulator.gather_context_violations(&mut context);
        assert!(res.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_paymaster_access_during_deploy() {
        let (provider, mut ep, mut context_provider) = create_base_config();
        ep.expect_address()
            .return_const(address!("5ff137d4b0fdcd49dca30c7cf57e578a026d2789"));
        context_provider
            .expect_get_specific_violations()
            .returning(|_| Ok(vec![]));

        let mut writes: HashMap<U256, u64> = HashMap::new();

        let sender_address = address!("b856dbd4fa1a79a46d426f537455e7d3e79ab7c4");
        let paymaster_address = address!("8abb13360b87be5eeb1b98647a016add927a136c");

        let external_access_address = Address::random();

        let sender_bytes = U256::from_be_bytes(sender_address.into_word().into());

        writes.insert(sender_bytes, 1);

        let mut context = get_test_context();
        context.tracer_out.phases[2].storage_accesses.insert(
            external_access_address,
            AccessInfo {
                reads: HashMap::new(),
                writes,
            },
        );

        // Create the simulator using the provider and tracer
        let simulator = create_simulator(provider, ep, context_provider);
        let res = simulator.gather_context_violations(&mut context);

        assert_eq!(
            res.unwrap(),
            vec![SimulationViolation::AssociatedStorageDuringDeploy(
                Some(Entity::paymaster(paymaster_address)),
                StorageSlot {
                    address: external_access_address,
                    slot: sender_bytes
                }
            )]
        );

        context.entity_infos.paymaster.as_mut().unwrap().is_staked = true;
        let res = simulator.gather_context_violations(&mut context);
        assert!(res.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_accessed_unsupported_contract() {
        let (provider, mut ep, mut context_provider) = create_base_config();
        ep.expect_address()
            .return_const(address!("5ff137d4b0fdcd49dca30c7cf57e578a026d2789"));
        context_provider
            .expect_get_specific_violations()
            .returning(|_| Ok(vec![]));

        let addr = Address::random();
        let mut context = get_test_context();
        context.tracer_out.accessed_contracts.insert(
            addr,
            ContractInfo {
                header: "0xEFF000".to_string(),
                opcode: Opcode::CALL,
                length: 32,
            },
        );

        let simulator = create_simulator(provider, ep, context_provider);
        let res = simulator.gather_context_violations(&mut context);

        assert_eq!(
            res.unwrap(),
            vec![SimulationViolation::AccessedUnsupportedContractType(
                "Arbitrum Stylus".to_string(),
                addr
            )]
        );
    }

    #[tokio::test]
    async fn test_aggregator_mismatch() {
        let (provider, mut ep, mut context_provider) = create_base_config();
        ep.expect_address()
            .return_const(address!("5ff137d4b0fdcd49dca30c7cf57e578a026d2789"));
        context_provider
            .expect_get_specific_violations()
            .returning(|_| Ok(vec![]));

        let actual_agg = Address::random();
        let bad_agg = Address::random();

        let mut context = get_test_context();
        context.op = context.op.transform_for_aggregator(
            &ChainSpec::default(),
            actual_agg,
            AggregatorCosts::default(),
            Bytes::new(),
        );
        context.entry_point_out.aggregator_info = Some(AggregatorInfo {
            address: bad_agg,
            stake_info: StakeInfo::default(),
        });

        let simulator = create_simulator(provider, ep, context_provider);
        let res = simulator.gather_context_violations(&mut context);

        assert_eq!(
            res.unwrap(),
            vec![SimulationViolation::AggregatorMismatch(actual_agg, bad_agg)]
        );
    }

    #[tokio::test]
    async fn test_aggregator_mismatch_zero() {
        let (provider, mut ep, mut context_provider) = create_base_config();
        ep.expect_address()
            .return_const(address!("5ff137d4b0fdcd49dca30c7cf57e578a026d2789"));
        context_provider
            .expect_get_specific_violations()
            .returning(|_| Ok(vec![]));

        let bad_agg = Address::random();

        let mut context = get_test_context();
        context.entry_point_out.aggregator_info = Some(AggregatorInfo {
            address: bad_agg,
            stake_info: StakeInfo::default(),
        });

        let simulator = create_simulator(provider, ep, context_provider);
        let res = simulator.gather_context_violations(&mut context);

        assert_eq!(
            res.unwrap(),
            vec![SimulationViolation::AggregatorMismatch(
                Address::ZERO,
                bad_agg
            )]
        );
    }

    #[tokio::test]
    async fn test_invalid_time_range() {
        let (provider, mut ep, mut context_provider) = create_base_config();
        ep.expect_address()
            .return_const(address!("5ff137d4b0fdcd49dca30c7cf57e578a026d2789"));
        context_provider
            .expect_get_specific_violations()
            .returning(|_| Ok(vec![]));

        let mut context = get_test_context();
        context.entry_point_out.return_info.valid_after = 0.into();
        context.entry_point_out.return_info.valid_until =
            Timestamp::now().sub(Duration::from_secs(10)); // invalid time range

        let simulator = create_simulator(provider, ep, context_provider);
        let res = simulator.gather_context_violations(&mut context);

        assert_eq!(
            res.unwrap(),
            vec![SimulationViolation::InvalidTimeRange(
                context.entry_point_out.return_info.valid_until,
                context.entry_point_out.return_info.valid_after,
            )]
        );
    }
}
