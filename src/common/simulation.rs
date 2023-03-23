use super::types::Entity;
use crate::common::contracts::entry_point::{EntryPoint, FailedOp};
use crate::common::tracer::{
    AssociatedSlotsByAddress, ExpectedSlot, ExpectedStorage, StorageAccess, TracerOutput,
};
use crate::common::types::{
    ExpectedStorageSlot, StakeInfo, UserOperation, ValidTimeRange, ValidationOutput,
    ValidationReturnInfo,
};
use crate::common::{eth, tracer};
use ethers::abi::AbiDecode;
use ethers::providers::{Http, Provider};
use ethers::types::{Address, BlockId, BlockNumber, OpCode, H256, U256};
use indexmap::IndexSet;
use std::collections::HashSet;
use std::fmt::{Debug, Display, Formatter};
use std::mem;
use std::sync::Arc;
use tonic::async_trait;

#[derive(Clone, Debug)]
pub struct SimulationSuccess {
    pub block_hash: H256,
    pub pre_op_gas: U256,
    pub signature_failed: bool,
    pub valid_time_range: ValidTimeRange,
    pub aggregator_address: Option<Address>,
    pub code_hash: H256,
    pub entities_needing_stake: Vec<Entity>,
    pub accessed_addresses: HashSet<Address>,
    pub expected_storage_slots: Vec<ExpectedStorageSlot>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct StorageSlot {
    pub address: Address,
    pub slot: U256,
}

#[async_trait]
pub trait Simulator {
    async fn simulate_validation(
        &self,
        op: UserOperation,
        block_id: Option<BlockId>,
        expected_code_hash: Option<H256>,
    ) -> Result<SimulationSuccess, SimulationError>;
}

#[derive(Debug)]
pub struct SimulatorImpl {
    provider: Arc<Provider<Http>>,
    entry_point: EntryPoint<Provider<Http>>,
    sim_settings: Settings,
}

impl SimulatorImpl {
    pub fn new(
        provider: Arc<Provider<Http>>,
        entry_point_address: Address,
        sim_settings: Settings,
    ) -> Self {
        let entry_point = EntryPoint::new(entry_point_address, provider.clone());
        Self {
            provider,
            entry_point,
            sim_settings,
        }
    }

    async fn create_context(
        &self,
        op: UserOperation,
        block_id: BlockId,
    ) -> Result<ValidationContext, SimulationError> {
        let factory_address = op.factory();
        let sender_address = op.sender;
        let paymaster_address = op.paymaster();
        let is_wallet_creation = !op.init_code.is_empty();
        let tracer_out = tracer::trace_op_validation(&self.entry_point, op, block_id).await?;
        let num_phases = tracer_out.phases.len() as u32;
        // Check if there are too many phases here, then check too few at the
        // end. We are detecting cases where the entry point is broken. Too many
        // phases definitely means it's broken, but too few phases could still
        // mean the entry point is fine if one of the phases fails and it
        // doesn't reach the end of execution.
        if num_phases > 3 {
            Err(Violation::WrongNumberOfPhases(num_phases))?
        }
        let Some(ref revert_data) = tracer_out.revert_data else {
            Err(Violation::DidNotRevert)?
        };
        let last_entity = Entity::from_simulation_phase(tracer_out.phases.len() - 1).unwrap();
        if let Ok(failed_op) = FailedOp::decode_hex(revert_data) {
            let entity_addr = match last_entity {
                Entity::Factory => factory_address,
                Entity::Paymaster => paymaster_address,
                Entity::Account => Some(sender_address),
                _ => None,
            };
            Err(Violation::UnintendedRevertWithMessage(
                last_entity,
                failed_op.reason,
                entity_addr,
            ))?
        }
        let Ok(entry_point_out) = ValidationOutput::decode_hex(revert_data) else {
            Err(Violation::UnintendedRevert(last_entity))?
        };
        let entity_infos = EntityInfos::new(
            factory_address,
            sender_address,
            paymaster_address,
            &entry_point_out,
            self.sim_settings,
        );
        if num_phases < 3 {
            Err(Violation::WrongNumberOfPhases(num_phases))?
        };
        Ok(ValidationContext {
            entity_infos,
            tracer_out,
            entry_point_out,
            is_wallet_creation,
        })
    }
}

#[async_trait]
impl Simulator for SimulatorImpl {
    async fn simulate_validation(
        &self,
        op: UserOperation,
        block_id: Option<BlockId>,
        expected_code_hash: Option<H256>,
    ) -> Result<SimulationSuccess, SimulationError> {
        let block_hash = eth::get_block_hash(
            &self.provider,
            block_id.unwrap_or_else(|| BlockNumber::Latest.into()),
        )
        .await?;
        let block_id = block_hash.into();
        let context = match self.create_context(op, block_id).await {
            Ok(context) => context,
            error @ Err(_) => error?,
        };
        let ValidationContext {
            entity_infos,
            mut tracer_out,
            entry_point_out,
            is_wallet_creation,
        } = context;
        let sender_address = entity_infos.sender_address();
        let mut violations: Vec<Violation> = vec![];
        let mut entities_needing_stake = vec![];
        let mut accessed_addresses = HashSet::new();
        for (index, phase) in tracer_out.phases.iter().enumerate().take(3) {
            let entity = Entity::from_simulation_phase(index).unwrap();
            let Some(entity_info) = entity_infos.get(entity) else {
                continue;
            };
            for opcode in &phase.forbidden_opcodes_used {
                violations.push(Violation::UsedForbiddenOpcode(entity, opcode.clone()));
            }
            if phase.used_invalid_gas_opcode {
                violations.push(Violation::InvalidGasOpcode(entity));
            }
            let mut needs_stake = entity == Entity::Paymaster
                && !entry_point_out.return_info.paymaster_context.is_empty();
            let mut banned_addresses_accessed = IndexSet::<Address>::new();
            for StorageAccess { address, slots } in &phase.storage_accesses {
                let address = *address;
                accessed_addresses.insert(address);
                for &slot in slots {
                    let restriction = get_storage_restriction(GetStorageRestrictionArgs {
                        slots_by_address: &tracer_out.associated_slots_by_address,
                        is_wallet_creation,
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
                            banned_addresses_accessed.insert(address);
                        }
                    }
                }
            }
            if needs_stake {
                entities_needing_stake.push(entity);
                if !entity_info.is_staked {
                    violations.push(Violation::NotStaked(
                        entity,
                        entity_info.address,
                        self.sim_settings.min_stake_value.into(),
                        self.sim_settings.min_unstake_delay.into(),
                    ));
                }
            }
            for address in banned_addresses_accessed {
                violations.push(Violation::InvalidStorageAccess(entity, address));
            }
            if phase.called_with_value {
                violations.push(Violation::CallHadValue(entity));
            }
            if phase.ran_out_of_gas {
                violations.push(Violation::OutOfGas(entity));
            }
            for &address in &phase.undeployed_contract_accesses {
                violations.push(Violation::AccessedUndeployedContract(entity, address))
            }
            if phase.called_handle_ops {
                violations.push(Violation::CalledHandleOps(entity));
            }
        }
        if let Some(aggregator_info) = entry_point_out.aggregator_info {
            entities_needing_stake.push(Entity::Aggregator);
            if !is_staked(aggregator_info.stake_info, self.sim_settings) {
                violations.push(Violation::NotStaked(
                    Entity::Aggregator,
                    aggregator_info.address,
                    self.sim_settings.min_stake_value.into(),
                    self.sim_settings.min_unstake_delay.into(),
                ));
            }
        }
        if tracer_out.factory_called_create2_twice {
            violations.push(Violation::FactoryCalledCreate2Twice);
        }
        if !violations.is_empty() {
            Err(violations)?;
        }
        // To spare the Geth node, only check code hashes if there are no other
        // violations.
        let code_hash = eth::get_code_hash(
            &self.provider,
            mem::take(&mut tracer_out.accessed_contract_addresses),
            Some(block_id),
        )
        .await?;
        if let Some(expected_code_hash) = expected_code_hash {
            if expected_code_hash != code_hash {
                Err(vec![Violation::CodeHashChanged])?;
            }
        }
        let mut expected_storage_slots = vec![];
        for ExpectedStorage { address, slots } in &tracer_out.expected_storage {
            for &ExpectedSlot { slot, value } in slots {
                expected_storage_slots.push(ExpectedStorageSlot {
                    address: *address,
                    slot,
                    value,
                });
            }
        }
        let ValidationOutput {
            return_info,
            aggregator_info,
            ..
        } = entry_point_out;
        let ValidationReturnInfo {
            pre_op_gas,
            sig_failed,
            valid_after,
            valid_until,
            ..
        } = return_info;
        Ok(SimulationSuccess {
            block_hash,
            pre_op_gas,
            signature_failed: sig_failed,
            valid_time_range: ValidTimeRange::new(valid_after, valid_until),
            aggregator_address: aggregator_info.map(|info| info.address),
            code_hash,
            entities_needing_stake,
            accessed_addresses,
            expected_storage_slots,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SimulationError {
    Violations(Vec<Violation>),
    Other(#[from] anyhow::Error),
}

impl From<Vec<Violation>> for SimulationError {
    fn from(violations: Vec<Violation>) -> Self {
        Self::Violations(violations)
    }
}

impl From<Violation> for SimulationError {
    fn from(violation: Violation) -> Self {
        vec![violation].into()
    }
}

impl Display for SimulationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SimulationError::Violations(violations) => {
                if violations.len() == 1 {
                    Display::fmt(&violations[0], f)
                } else {
                    f.write_str("multiple violations during validation: ")?;
                    for violation in violations {
                        Display::fmt(violation, f)?;
                        f.write_str("; ")?;
                    }
                    Ok(())
                }
            }
            SimulationError::Other(error) => Display::fmt(error, f),
        }
    }
}

#[derive(Clone, Debug, parse_display::Display)]
pub enum Violation {
    #[display("reverted while simulating {0} validation")]
    UnintendedRevert(Entity),
    #[display("reverted while simulating {0} validation: {1}")]
    UnintendedRevertWithMessage(Entity, String, Option<Address>),
    #[display("simulateValidation did not revert. Make sure your EntryPoint is valid")]
    DidNotRevert,
    #[display("simulateValidation should have 3 parts but had {0} instead. Make sure your EntryPoint is valid")]
    WrongNumberOfPhases(u32),
    #[display("{0} uses banned opcode: {1:?}")]
    UsedForbiddenOpcode(Entity, OpCode),
    #[display("{0} uses banned opcode: GAS")]
    InvalidGasOpcode(Entity),
    #[display("{0} accessed forbidden storage at address {1:?} during validation")]
    InvalidStorageAccess(Entity, Address),
    #[display("{0} must be staked")]
    NotStaked(Entity, Address, U256, U256),
    #[display("{0} must not send ETH during validation (except to entry point)")]
    CallHadValue(Entity),
    #[display("ran out of gas during {0} validation")]
    OutOfGas(Entity),
    #[display(
        "{0} tried to access code at {1} during validation, but that address is not a contract"
    )]
    AccessedUndeployedContract(Entity, Address),
    #[display("{0} called handleOps on the entry point")]
    CalledHandleOps(Entity),
    #[display("code accessed by validation has changed since the last time validation was run")]
    CodeHashChanged,
    #[display("factory may only call CREATE2 once during initialization")]
    FactoryCalledCreate2Twice,
}

impl Entity {
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
    entity_infos: EntityInfos,
    tracer_out: TracerOutput,
    entry_point_out: ValidationOutput,
    is_wallet_creation: bool,
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

    pub fn get(self, entity: Entity) -> Option<EntityInfo> {
        match entity {
            Entity::Factory => self.factory,
            Entity::Account => Some(self.sender),
            Entity::Paymaster => self.paymaster,
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
    is_wallet_creation: bool,
    entry_point_address: Address,
    entity_address: Address,
    sender_address: Address,
    accessed_address: Address,
    slot: U256,
}

fn get_storage_restriction(args: GetStorageRestrictionArgs) -> StorageRestriction {
    let GetStorageRestrictionArgs {
        slots_by_address,
        is_wallet_creation,
        entry_point_address,
        entity_address,
        sender_address,
        accessed_address,
        slot,
    } = args;
    if accessed_address == sender_address {
        StorageRestriction::Allowed
    } else if slots_by_address.is_associated_slot(sender_address, slot) {
        if is_wallet_creation && accessed_address != entry_point_address {
            // We deviate from the letter of ERC-4337 to allow unstaked access
            // during wallet creation to the sender's associated storage on
            // the entry point. Otherwise, the sender can't call depositTo() to
            // pay for its own gas!
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
    pub min_stake_value: u64,
}

impl Settings {
    pub fn new(min_unstake_delay: u32, min_stake_value: u64) -> Self {
        Self {
            min_unstake_delay,
            min_stake_value,
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
        }
    }
}
