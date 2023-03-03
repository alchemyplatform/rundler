use crate::common::contracts::entry_point::{EntryPoint, ValidationResult};
use crate::common::tracer::{AssociatedSlotsByAddress, SlotAccess, StorageAccess, TracerOutput};
use crate::common::types::{EntryPointOutput, StakeInfo, UserOperation};
use crate::common::{eth, tracer};
use ethers::abi::AbiDecode;
use ethers::providers::{Http, Middleware, Provider};
use ethers::types::{Address, BlockId, OpCode, U256};
use indexmap::IndexSet;
use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Display, Formatter};
use std::mem;
use std::sync::Arc;

// One day in seconds. Specified in ERC-4337.
const MIN_UNSTAKE_DELAY: u32 = 84600;

#[derive(Clone, Debug)]
pub struct SimulationSuccess {
    signature_failed: bool,
    valid_after: u64,
    valid_until: u64,
    code_hash: [u8; 32],
    storage_accesses_with_expected_values: HashMap<StorageSlot, Option<U256>>,
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct StorageSlot {
    address: Address,
    slot: U256,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Entity {
    Factory = 0,
    Account = 1,
    Paymaster = 2,
}

impl Entity {
    pub fn index(self) -> usize {
        self as usize
    }

    pub fn from_index(i: usize) -> Option<Self> {
        match i {
            0 => Some(Self::Factory),
            1 => Some(Self::Account),
            2 => Some(Self::Paymaster),
            _ => None,
        }
    }
}

impl Display for Entity {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Entity::Factory => "factory",
            Entity::Account => "account",
            Entity::Paymaster => "paymaster",
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
    #[display("unexpected revert while simulating {0} validation")]
    UnintendedRevert(Entity),
    #[display("simulateValidation did not revert. Make sure your EntryPoint is valid")]
    DidNotRevert,
    #[display("simulateValidation should have 3 parts but had {0} instead. Make sure your EntryPoint is valid")]
    WrongNumberOfPhases(u32),
    #[display("{0} used forbidden opcode {1:?} during validation")]
    UsedForbiddenOpcode(Entity, OpCode),
    #[display(
        "{0} used GAS opcode and did not immediately follow with a call opcode during validation"
    )]
    InvalidGasOpcode(Entity),
    #[display("{0} accessed forbidden storage at address {1:?} during validation")]
    InvalidStorageAccess(Entity, Address),
    #[display("{0} must be staked")]
    NotStaked(Entity),
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

pub async fn simulate_validation(
    provider: &Arc<Provider<Http>>,
    entry_point: &EntryPoint<impl Middleware>,
    op: UserOperation,
    expected_code_hash: Option<[u8; 32]>,
    min_stake_value: U256,
) -> Result<SimulationSuccess, SimulationError> {
    let context = match ValidationContext::new_for_op(entry_point, op, min_stake_value).await {
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
    let mut storage_accesses_with_expected_values = HashMap::new();
    for (index, phase) in tracer_out.phases.iter().enumerate().take(3) {
        let entity = Entity::from_index(index).unwrap();
        let entity_info = match entity_infos.get(entity) {
            Some(info) => info,
            None => continue,
        };
        for opcode in &phase.banned_opcodes_used {
            violations.push(Violation::UsedForbiddenOpcode(entity, opcode.clone()));
        }
        if phase.used_invalid_gas_opcode {
            violations.push(Violation::InvalidGasOpcode(entity));
        }
        let mut needs_stake = false;
        let mut banned_addresses_accessed = IndexSet::<Address>::new();
        for StorageAccess { address, accesses } in &phase.storage_accesses {
            let address = *address;
            for access in accesses {
                storage_accesses_with_expected_values.insert(
                    StorageSlot {
                        address,
                        slot: access.slot,
                    },
                    access.initial_value,
                );
                let restriction = get_storage_restriction(GetStorageRestrictionArgs {
                    slots_by_address: &tracer_out.associated_slots_by_address,
                    is_wallet_creation,
                    entity_address: entity_info.address,
                    sender_address,
                    accessed_address: address,
                    slot: access.slot,
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
        if needs_stake && !entity_info.is_staked {
            violations.push(Violation::NotStaked(entity));
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
        if phase.called_entry_point {
            violations.push(Violation::CalledHandleOps(entity));
        }
        if entity == Entity::Factory {
            if phase.create2_count > 1 {
                violations.push(Violation::FactoryCalledCreate2Twice);
            }
        } else {
            if phase.create2_count > 0 {
                violations.push(Violation::UsedForbiddenOpcode(entity, OpCode::CREATE2));
            }
        }
    }
    let code_hash = eth::get_code_hash(
        provider,
        mem::take(&mut tracer_out.accessed_contract_addresses),
        Some(BlockId::Hash(tracer_out.block_hash)),
    )
    .await?;
    if let Some(expected_code_hash) = expected_code_hash {
        if expected_code_hash != code_hash {
            violations.push(Violation::CodeHashChanged);
        }
    }
    if !violations.is_empty() {
        Err(violations)?
    }
    Ok(SimulationSuccess {
        signature_failed: entry_point_out.return_info.sig_failed,
        valid_after: entry_point_out.return_info.valid_after,
        valid_until: entry_point_out.return_info.valid_until,
        code_hash,
        storage_accesses_with_expected_values,
    })
}

#[derive(Debug)]
struct ValidationContext {
    entity_infos: EntityInfos,
    tracer_out: TracerOutput,
    entry_point_out: EntryPointOutput,
    is_wallet_creation: bool,
}

impl ValidationContext {
    async fn new_for_op(
        entry_point: &EntryPoint<impl Middleware>,
        op: UserOperation,
        min_stake_value: U256,
    ) -> Result<Self, SimulationError> {
        let factory_address = op.factory();
        let sender_address = op.sender;
        let paymaster_address = op.paymaster();
        let is_wallet_creation = !op.init_code.is_empty();
        let tracer_out = tracer::trace_op_validation(entry_point, op).await?;
        let num_phases = tracer_out.phases.len() as u32;
        if num_phases > 3 {
            Err(Violation::WrongNumberOfPhases(num_phases))?
        }
        let entry_point_out = match ValidationResult::decode_hex(&tracer_out.revert_data) {
            Ok(out) => EntryPointOutput::from(out),
            Err(_) => {
                let last_entity = Entity::from_index(tracer_out.phases.len()).unwrap();
                Err(Violation::UnintendedRevert(last_entity))?
            }
        };
        let entity_infos = EntityInfos::new(
            factory_address,
            sender_address,
            paymaster_address,
            &entry_point_out,
            min_stake_value,
        );
        if num_phases < 3 {
            Err(Violation::WrongNumberOfPhases(num_phases))?
        };
        Ok(Self {
            entity_infos,
            tracer_out,
            entry_point_out,
            is_wallet_creation,
        })
    }
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
        entry_point_out: &EntryPointOutput,
        min_stake_value: U256,
    ) -> Self {
        let factory = factory_address.map(|address| EntityInfo {
            address,
            is_staked: is_staked(entry_point_out.factory_info, min_stake_value),
        });
        let sender = EntityInfo {
            address: sender_address,
            is_staked: is_staked(entry_point_out.sender_info, min_stake_value),
        };
        let paymaster = paymaster_address.map(|address| EntityInfo {
            address,
            is_staked: is_staked(entry_point_out.paymaster_info, min_stake_value),
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
        }
    }

    pub fn sender_address(self) -> Address {
        self.sender.address
    }
}

fn is_staked(info: StakeInfo, min_stake_value: U256) -> bool {
    info.stake > min_stake_value && info.unstake_delay_sec > MIN_UNSTAKE_DELAY.into()
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum StorageRestriction {
    Allowed,
    NeedsStake,
    Banned,
}

#[derive(Copy, Clone, Debug)]
struct GetStorageRestrictionArgs<'a> {
    slots_by_address: &'a AssociatedSlotsByAddress,
    is_wallet_creation: bool,
    entity_address: Address,
    sender_address: Address,
    accessed_address: Address,
    slot: U256,
}

fn get_storage_restriction(args: GetStorageRestrictionArgs) -> StorageRestriction {
    let GetStorageRestrictionArgs {
        slots_by_address,
        is_wallet_creation,
        entity_address,
        sender_address,
        accessed_address,
        slot,
    } = args;
    if accessed_address == sender_address {
        StorageRestriction::Allowed
    } else if slots_by_address.is_associated_slot(sender_address, slot) {
        if is_wallet_creation {
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
