use std::{
    collections::{HashMap, HashSet},
    mem,
    ops::Deref,
    sync::Arc,
};

use anyhow::Context;
use ethers::{
    abi::AbiDecode,
    contract::ContractError,
    providers::{JsonRpcClient, Provider},
    types::{Address, BlockId, Bytes, Opcode, H256, U256},
};
use indexmap::IndexSet;
#[cfg(test)]
use mockall::automock;
use tonic::async_trait;

use super::{
    mempool::{match_mempools, MempoolMatchResult},
    tracer::parse_combined_tracer_str,
};
use crate::common::{
    contracts::{
        i_aggregator::IAggregator,
        i_entry_point::{FailedOp, IEntryPoint},
    },
    eth,
    mempool::MempoolConfig,
    tracer,
    tracer::{AssociatedSlotsByAddress, StorageAccess, TracerOutput},
    types::{
        Entity, EntityType, ExpectedStorage, ProviderLike, StakeInfo, UserOperation,
        ValidTimeRange, ValidationOutput, ValidationReturnInfo, ViolationError,
    },
};

#[derive(Clone, Debug, Default)]
pub struct SimulationSuccess {
    pub mempools: Vec<H256>,
    pub block_hash: H256,
    pub pre_op_gas: U256,
    pub valid_time_range: ValidTimeRange,
    pub aggregator: Option<AggregatorSimOut>,
    pub code_hash: H256,
    pub entities_needing_stake: Vec<EntityType>,
    pub account_is_staked: bool,
    pub accessed_addresses: HashSet<Address>,
    pub expected_storage: ExpectedStorage,
}

#[derive(Clone, Debug, Default)]
pub struct AggregatorSimOut {
    pub address: Address,
    pub signature: Bytes,
}

impl SimulationSuccess {
    pub fn aggregator_address(&self) -> Option<Address> {
        self.aggregator.as_ref().map(|agg| agg.address)
    }
}

pub type SimulationError = ViolationError<SimulationViolation>;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct StorageSlot {
    pub address: Address,
    pub slot: U256,
}

#[cfg_attr(test, automock)]
#[async_trait]
pub trait Simulator: Send + Sync + 'static {
    async fn simulate_validation(
        &self,
        op: UserOperation,
        block_hash: Option<H256>,
        expected_code_hash: Option<H256>,
    ) -> Result<SimulationSuccess, SimulationError>;
}

#[derive(Debug)]
pub struct SimulatorImpl<T: JsonRpcClient> {
    provider: Arc<Provider<T>>,
    entry_point: IEntryPoint<Provider<T>>,
    sim_settings: Settings,
    mempool_configs: HashMap<H256, MempoolConfig>,
}

impl<T> SimulatorImpl<T>
where
    T: JsonRpcClient + 'static,
{
    pub fn new(
        provider: Arc<Provider<T>>,
        entry_point_address: Address,
        sim_settings: Settings,
        mempool_configs: HashMap<H256, MempoolConfig>,
    ) -> Self {
        let entry_point = IEntryPoint::new(entry_point_address, provider.clone());
        Self {
            provider,
            entry_point,
            sim_settings,
            mempool_configs,
        }
    }

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
        let tracer_out = tracer::trace_simulate_validation(
            &self.entry_point,
            op.clone(),
            block_id,
            self.sim_settings.max_verification_gas,
        )
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
        let last_entity = EntityType::from_simulation_phase(tracer_out.phases.len() - 1).unwrap();

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
        let aggregator = IAggregator::new(aggregator_address, Arc::clone(&self.provider));
        match aggregator
            .validate_user_op_signature(op)
            .gas(gas_cap)
            .call()
            .await
        {
            Ok(sig) => Ok(AggregatorOut::SuccessWithInfo(AggregatorSimOut {
                address: aggregator_address,
                signature: sig,
            })),
            Err(ContractError::Revert(_)) => Ok(AggregatorOut::ValidationReverted),
            Err(error) => Err(error).context("should call aggregator to validate signature")?,
        }
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
            let kind = EntityType::from_simulation_phase(index).unwrap();
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
                for &slot in slots {
                    let restriction = get_storage_restriction(GetStorageRestrictionArgs {
                        slots_by_address: &tracer_out.associated_slots_by_address,
                        entity,
                        is_unstaked_wallet_creation,
                        entry_point_address: self.entry_point.address(),
                        entity_address: entity_info.address,
                        sender_address,
                        accessed_address: address,
                        slot,
                    });
                    match restriction {
                        StorageRestriction::Allowed => {}
                        StorageRestriction::NeedsStake => needs_stake = true,
                        StorageRestriction::Banned => {
                            banned_slots_accessed.insert(StorageSlot { address, slot });
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
                        self.entry_point.address(),
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
        let code_hash_future = eth::get_code_hash(
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
impl<T> Simulator for SimulatorImpl<T>
where
    T: JsonRpcClient + 'static,
{
    async fn simulate_validation(
        &self,
        op: UserOperation,
        block_hash: Option<H256>,
        expected_code_hash: Option<H256>,
    ) -> Result<SimulationSuccess, SimulationError> {
        let block_hash = match block_hash {
            Some(block_hash) => block_hash,
            None => self.provider.get_latest_block_hash().await?,
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
        })
    }
}

#[derive(Clone, Debug, parse_display::Display, Ord, Eq, PartialOrd, PartialEq)]
pub enum SimulationViolation {
    // Make sure to maintain the order here based on the importance
    // of the violation for converting to an JRPC error
    #[display("invalid signature")]
    InvalidSignature,
    #[display("reverted while simulating {0} validation: {1}")]
    UnintendedRevertWithMessage(EntityType, String, Option<Address>),
    #[display("{0.kind} uses banned opcode: {2} in contract {1:?}")]
    UsedForbiddenOpcode(Entity, Address, ViolationOpCode),
    #[display("{0.kind} uses banned precompile: {2:?} in contract {1:?}")]
    UsedForbiddenPrecompile(Entity, Address, Address),
    #[display("factory may only call CREATE2 once during initialization")]
    FactoryCalledCreate2Twice(Address),
    #[display("{0.kind} accessed forbidden storage at address {1:?} during validation")]
    InvalidStorageAccess(Entity, StorageSlot),
    #[display("{0.kind} must be staked")]
    NotStaked(Entity, U256, U256),
    #[display("reverted while simulating {0} validation")]
    UnintendedRevert(EntityType),
    #[display("simulateValidation did not revert. Make sure your EntryPoint is valid")]
    DidNotRevert,
    #[display("simulateValidation should have 3 parts but had {0} instead. Make sure your EntryPoint is valid")]
    WrongNumberOfPhases(u32),
    #[display("{0.kind} must not send ETH during validation (except from account to entry point)")]
    CallHadValue(Entity),
    #[display("ran out of gas during {0.kind} validation")]
    OutOfGas(Entity),
    #[display(
        "{0.kind} tried to access code at {1} during validation, but that address is not a contract"
    )]
    AccessedUndeployedContract(Entity, Address),
    #[display("{0.kind} called entry point method other than depositTo")]
    CalledBannedEntryPointMethod(Entity),
    #[display("code accessed by validation has changed since the last time validation was run")]
    CodeHashChanged,
    #[display("aggregator signature validation failed")]
    AggregatorValidationFailed,
}

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

impl EntityType {
    pub fn from_simulation_phase(i: usize) -> Option<Self> {
        match i {
            0 => Some(Self::Factory),
            1 => Some(Self::Account),
            2 => Some(Self::Paymaster),
            _ => None,
        }
    }
}

#[derive(Debug)]
struct ValidationContext {
    block_id: BlockId,
    entity_infos: EntityInfos,
    tracer_out: TracerOutput,
    entry_point_out: ValidationOutput,
    is_unstaked_wallet_creation: bool,
    entities_needing_stake: Vec<EntityType>,
    accessed_addresses: HashSet<Address>,
}

#[derive(Debug)]
enum AggregatorOut {
    NotNeeded,
    SuccessWithInfo(AggregatorSimOut),
    ValidationReverted,
}

#[derive(Clone, Copy, Debug)]
struct EntityInfo {
    pub address: Address,
    pub is_staked: bool,
}

#[derive(Clone, Copy, Debug)]
struct EntityInfos {
    factory: Option<EntityInfo>,
    sender: EntityInfo,
    paymaster: Option<EntityInfo>,
}

impl EntityInfos {
    pub fn new(
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

    pub fn get(self, entity: EntityType) -> Option<EntityInfo> {
        match entity {
            EntityType::Factory => self.factory,
            EntityType::Account => Some(self.sender),
            EntityType::Paymaster => self.paymaster,
            _ => None,
        }
    }

    pub fn sender_address(self) -> Address {
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
    entity: Entity,
    is_unstaked_wallet_creation: bool,
    entry_point_address: Address,
    entity_address: Address,
    sender_address: Address,
    accessed_address: Address,
    slot: U256,
}

fn get_storage_restriction(args: GetStorageRestrictionArgs) -> StorageRestriction {
    let GetStorageRestrictionArgs {
        slots_by_address,
        entity,
        is_unstaked_wallet_creation,
        entry_point_address,
        entity_address,
        sender_address,
        accessed_address,
        slot,
    } = args;
    if accessed_address == sender_address {
        StorageRestriction::Allowed
    } else if slots_by_address.is_associated_slot(sender_address, slot) {
        if is_unstaked_wallet_creation
            && entity.kind != EntityType::Account
            && accessed_address != entry_point_address
        {
            // We deviate from the letter of ERC-4337 to allow an unstaked
            // sender to access its own associated storage during account
            // creation, based on discussion with the ERC authors.
            //
            // We also deviate by allowing unstaked access to the sender's
            // associated storage on the entry point during account creation.
            // Without this, several spec tests fail because the `SimpleWallet`
            // used in the tests deposits in its constructor, which causes the
            // factory to access the sender's associated storage on the entry
            // point.
            StorageRestriction::NeedsStake
        } else {
            StorageRestriction::Allowed
        }
    } else if accessed_address == entity_address
        || slots_by_address.is_associated_slot(entity_address, slot)
    {
        StorageRestriction::NeedsStake
    } else {
        StorageRestriction::Banned
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Settings {
    pub min_unstake_delay: u32,
    pub min_stake_value: u128,
    pub max_simulate_handle_ops_gas: u64,
    pub max_verification_gas: u64,
}

impl Settings {
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
