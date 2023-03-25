use std::{collections::HashSet, mem, sync::Arc};

use anyhow::Context;
use ethers::{
    abi::AbiDecode,
    contract::ContractError,
    providers::{JsonRpcClient, Provider},
    types::{Address, BlockId, BlockNumber, Bytes, Opcode, H256, U256},
};
use indexmap::IndexSet;
#[cfg(test)]
use mockall::automock;
use tonic::async_trait;

use crate::common::{
    contracts::{
        i_aggregator::IAggregator,
        i_entry_point::{FailedOp, IEntryPoint, IEntryPointErrors},
    },
    eth, tracer,
    tracer::{
        AssociatedSlotsByAddress, ExpectedSlot, ExpectedStorage, StorageAccess, TracerOutput,
    },
    types::{
        Entity, ExpectedStorageSlot, ProviderLike, StakeInfo, UserOperation, ValidTimeRange,
        ValidationOutput, ValidationReturnInfo, ViolationError,
    },
};

#[derive(Clone, Debug, Default)]
pub struct SimulationSuccess {
    pub block_hash: H256,
    pub pre_op_gas: U256,
    pub signature_failed: bool,
    pub valid_time_range: ValidTimeRange,
    pub aggregator: Option<AggregatorSimOut>,
    pub code_hash: H256,
    pub entities_needing_stake: Vec<Entity>,
    pub account_is_staked: bool,
    pub accessed_addresses: HashSet<Address>,
    pub expected_storage_slots: Vec<ExpectedStorageSlot>,
}

#[derive(Clone, Debug, Default)]
pub struct AggregatorSimOut {
    pub address: Address,
    pub signature: Bytes,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, ethers::contract::EthError)]
#[etherror(name = "Error", abi = "Error(string)")]
/// This is the abi for what happens when you just revert("message") in a contract
pub struct ContractRevertError {
    pub reason: String,
}

#[derive(Clone, Debug)]
pub struct GasSimulationSuccess {
    /// This is the gas used by the entry point in actually executing the user op
    pub call_gas: U256,
    /// this is the gas cost of validating the user op. It does NOT include the preOp verification cost
    pub verification_gas: U256,
}

pub type SimulationError = ViolationError<SimulationViolation>;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct StorageSlot {
    pub address: Address,
    pub slot: U256,
}

#[cfg_attr(test, automock)]
#[async_trait]
pub trait Simulator: Send + Sync {
    async fn simulate_validation(
        &self,
        op: UserOperation,
        block_hash: Option<H256>,
        expected_code_hash: Option<H256>,
    ) -> Result<SimulationSuccess, SimulationError>;

    async fn simulate_handle_op(
        &self,
        op: UserOperation,
    ) -> Result<GasSimulationSuccess, GasSimulationError>;
}

#[derive(Debug)]
pub struct SimulatorImpl<T: JsonRpcClient> {
    provider: Arc<Provider<T>>,
    entry_point: IEntryPoint<Provider<T>>,
    sim_settings: Settings,
}

impl<T> SimulatorImpl<T>
where
    T: JsonRpcClient + 'static,
{
    pub fn new(
        provider: Arc<Provider<T>>,
        entry_point_address: Address,
        sim_settings: Settings,
    ) -> Self {
        let entry_point = IEntryPoint::new(entry_point_address, provider.clone());
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
        let tracer_out = tracer::trace_simulate_validation(&self.entry_point, op, block_id).await?;
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
        let last_entity = Entity::from_simulation_phase(tracer_out.phases.len() - 1).unwrap();
        if let Ok(failed_op) = FailedOp::decode_hex(revert_data) {
            let entity_addr = match last_entity {
                Entity::Factory => factory_address,
                Entity::Paymaster => paymaster_address,
                Entity::Account => Some(sender_address),
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
        if num_phases < 3 {
            Err(vec![SimulationViolation::WrongNumberOfPhases(num_phases)])?
        };
        Ok(ValidationContext {
            entity_infos,
            tracer_out,
            entry_point_out,
            is_wallet_creation,
        })
    }

    async fn validate_aggregator_signature(
        &self,
        op: UserOperation,
        aggregator_address: Option<Address>,
    ) -> anyhow::Result<AggregatorOut> {
        let Some(aggregator_address) = aggregator_address else {
            return Ok(AggregatorOut::NotNeeded);
        };
        let aggregator = IAggregator::new(aggregator_address, Arc::clone(&self.provider));
        // TODO: Add gas limit to prevent DoS?
        match aggregator.validate_user_op_signature(op).call().await {
            Ok(sig) => Ok(AggregatorOut::SuccerssWithInfo(AggregatorSimOut {
                address: aggregator_address,
                signature: sig,
            })),
            Err(ContractError::Revert(_)) => Ok(AggregatorOut::ValidationReverted),
            Err(error) => Err(error).context("should call aggregator to validate signature")?,
        }
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
            None => ProviderLike::get_latest_block_hash(&self.provider).await?,
        };
        let block_id = block_hash.into();
        let context = match self.create_context(op.clone(), block_id).await {
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
        let mut violations: Vec<SimulationViolation> = vec![];
        let mut entities_needing_stake = vec![];
        let mut accessed_addresses = HashSet::new();
        for (index, phase) in tracer_out.phases.iter().enumerate().take(3) {
            let entity = Entity::from_simulation_phase(index).unwrap();
            let Some(entity_info) = entity_infos.get(entity) else {
                continue;
            };
            for opcode in &phase.forbidden_opcodes_used {
                violations.push(SimulationViolation::UsedForbiddenOpcode(
                    entity,
                    ViolationOpCode(*opcode),
                ));
            }
            if phase.used_invalid_gas_opcode {
                violations.push(SimulationViolation::InvalidGasOpcode(entity));
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
                        entity,
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
                    violations.push(SimulationViolation::NotStaked(
                        entity,
                        entity_info.address,
                        self.sim_settings.min_stake_value.into(),
                        self.sim_settings.min_unstake_delay.into(),
                    ));
                }
            }
            for address in banned_addresses_accessed {
                violations.push(SimulationViolation::InvalidStorageAccess(entity, address));
            }
            if phase.called_with_value {
                violations.push(SimulationViolation::CallHadValue(entity));
            }
            if phase.ran_out_of_gas {
                violations.push(SimulationViolation::OutOfGas(entity));
            }
            for &address in &phase.undeployed_contract_accesses {
                violations.push(SimulationViolation::AccessedUndeployedContract(
                    entity, address,
                ))
            }
            if phase.called_banned_entry_point_method {
                violations.push(SimulationViolation::CalledBannedEntryPointMethod(entity));
            }
        }
        if let Some(aggregator_info) = entry_point_out.aggregator_info {
            entities_needing_stake.push(Entity::Aggregator);
            if !is_staked(aggregator_info.stake_info, self.sim_settings) {
                violations.push(SimulationViolation::NotStaked(
                    Entity::Aggregator,
                    aggregator_info.address,
                    self.sim_settings.min_stake_value.into(),
                    self.sim_settings.min_unstake_delay.into(),
                ));
            }
        }
        if tracer_out.factory_called_create2_twice {
            violations.push(SimulationViolation::FactoryCalledCreate2Twice);
        }
        // To spare the Geth node, only check code hashes and validate with
        // aggregator if there are no other violations.
        if !violations.is_empty() {
            return Err(violations.into());
        }
        let aggregator_address = entry_point_out.aggregator_info.map(|info| info.address);
        let code_hash_future = eth::get_code_hash(
            &self.provider,
            mem::take(&mut tracer_out.accessed_contract_addresses),
            Some(block_id),
        );
        let aggregator_signature_future =
            self.validate_aggregator_signature(op, aggregator_address);
        let (code_hash, aggregator_out) =
            tokio::try_join!(code_hash_future, aggregator_signature_future)?;
        if let Some(expected_code_hash) = expected_code_hash {
            if expected_code_hash != code_hash {
                violations.push(SimulationViolation::CodeHashChanged)
            }
        }
        let aggregator = match aggregator_out {
            AggregatorOut::NotNeeded => None,
            AggregatorOut::SuccerssWithInfo(info) => Some(info),
            AggregatorOut::ValidationReverted => {
                violations.push(SimulationViolation::AggregatorValidationFailed);
                None
            }
        };
        if !violations.is_empty() {
            return Err(violations.into());
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
            sender_info,
            ..
        } = entry_point_out;
        let account_is_staked = is_staked(sender_info, self.sim_settings);
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
            aggregator,
            code_hash,
            entities_needing_stake,
            account_is_staked,
            accessed_addresses,
            expected_storage_slots,
        })
    }

    async fn simulate_handle_op(
        &self,
        op: UserOperation,
    ) -> Result<GasSimulationSuccess, GasSimulationError> {
        let tracer_out = tracer::trace_simulate_handle_op(
            &self.entry_point,
            op,
            BlockNumber::Latest.into(),
            self.sim_settings.max_simulate_handle_ops_gas,
        )
        .await?;

        let Some(ref revert_data) = tracer_out.revert_data else {
            return Err(GasSimulationError::DidNotRevert);
        };

        let ep_error = IEntryPointErrors::decode_hex(revert_data)
            .map_err(|e| GasSimulationError::Other(e.into()))?;

        // we don't use the verification gas returned here because it adds the preVerificationGas passed in from the UserOperation
        // that value *should* be 0 but might not be, so we won't use it here and just use the gas from tracing
        // we just want to make sure we completed successfully
        match ep_error {
            IEntryPointErrors::ExecutionResult(_) => (),
            _ => {
                return Err(GasSimulationError::DidNotRevertWithExecutionResult(
                    ep_error,
                ))
            }
        };

        // This should be 3 phases (actually there are 5, but we merge the first 3 as one since that's the validation phase)
        if tracer_out.phases.len() != 3 {
            return Err(GasSimulationError::IncorrectPhaseCount(
                tracer_out.phases.len(),
            ));
        }

        if let Some(inner_revert) = &tracer_out.phases[1].account_revert_data {
            match ContractRevertError::decode_hex(inner_revert) {
                Ok(error) => {
                    return Err(GasSimulationError::AccountExecutionReverted(error.reason))
                }
                // Inner revert was a different type that we don't know know how to decode
                // just return that body for now
                _ => {
                    return Err(GasSimulationError::AccountExecutionReverted(
                        inner_revert.clone(),
                    ))
                }
            };
        };

        Ok(GasSimulationSuccess {
            call_gas: tracer_out.phases[1].gas_used.into(),
            verification_gas: tracer_out.phases[0].gas_used.into(),
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GasSimulationError {
    #[error("handle op simulation did not revert")]
    DidNotRevert,
    #[error("handle op simulation should have reverted with exection result: {0}")]
    DidNotRevertWithExecutionResult(IEntryPointErrors),
    #[error("account execution reverted: {0}")]
    AccountExecutionReverted(String),
    #[error("handle op simulation should have had 5 phases, but had {0}")]
    IncorrectPhaseCount(usize),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[derive(Clone, Debug, parse_display::Display, Ord, Eq, PartialOrd, PartialEq)]
pub enum SimulationViolation {
    // Make sure to maintain the order here based on the importance
    // of the violation for converting to an JRPC error
    #[display("reverted while simulating {0} validation: {1}")]
    UnintendedRevertWithMessage(Entity, String, Option<Address>),
    #[display("{0} uses banned opcode: {1}")]
    UsedForbiddenOpcode(Entity, ViolationOpCode),
    #[display("{0} uses banned opcode: GAS")]
    InvalidGasOpcode(Entity),
    #[display("factory may only call CREATE2 once during initialization")]
    FactoryCalledCreate2Twice,
    #[display("{0} accessed forbidden storage at address {1:?} during validation")]
    InvalidStorageAccess(Entity, Address),
    #[display("{0} must be staked")]
    NotStaked(Entity, Address, U256, U256),
    #[display("reverted while simulating {0} validation")]
    UnintendedRevert(Entity),
    #[display("simulateValidation did not revert. Make sure your EntryPoint is valid")]
    DidNotRevert,
    #[display("simulateValidation should have 3 parts but had {0} instead. Make sure your EntryPoint is valid")]
    WrongNumberOfPhases(u32),
    #[display("{0} must not send ETH during validation (except to entry point)")]
    CallHadValue(Entity),
    #[display("ran out of gas during {0} validation")]
    OutOfGas(Entity),
    #[display(
        "{0} tried to access code at {1} during validation, but that address is not a contract"
    )]
    AccessedUndeployedContract(Entity, Address),
    #[display("{0} called entry point method other than depositTo")]
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

#[derive(Debug)]
enum AggregatorOut {
    NotNeeded,
    SuccerssWithInfo(AggregatorSimOut),
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
    entity: Entity,
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
        entity,
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
        if is_wallet_creation
            && entity != Entity::Account
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
    pub min_stake_value: u64,
    pub max_simulate_handle_ops_gas: u64,
}

impl Settings {
    pub fn new(
        min_unstake_delay: u32,
        min_stake_value: u64,
        max_simulate_handle_ops_gas: u64,
    ) -> Self {
        Self {
            min_unstake_delay,
            min_stake_value,
            max_simulate_handle_ops_gas,
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
        }
    }
}
