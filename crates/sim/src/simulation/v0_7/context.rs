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
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    sync::Arc,
};

use anyhow::{bail, Context};
use ethers::{
    abi::AbiDecode,
    types::{Address, BlockId, Bytes, Opcode, H160, U256},
    utils::{hex::FromHex, keccak256},
};
use rundler_provider::{EntryPoint, Provider, SimulationProvider};
use rundler_types::{
    contracts::v0_7::{
        entry_point_simulations::{FailedOpWithRevert, SimulateValidationReturn},
        i_entry_point::FailedOp,
    },
    pool::SimulationViolation,
    v0_7::UserOperation,
    EntityType, UserOperation as UserOperationTrait, ValidationOutput, ValidationRevert,
};
use rundler_utils::eth::ContractRevertError;

use super::tracer::{
    CallInfo, ExitType, MethodInfo, SimulateValidationTracer, SimulateValidationTracerImpl,
    TopLevelCallInfo, TracerOutput,
};
use crate::{
    simulation::context::{
        self as sim_context, AccessInfo, AssociatedSlotsByAddress, Phase,
        TracerOutput as ContextTracerOutput, ValidationContext,
        ValidationContextProvider as ValidationContextProviderTrait,
    },
    ExpectedStorage, SimulationSettings, ViolationError,
};

// Banned opcodes
//
// Some banned opcodes (i.e. CREATE2) have special handling and aren't on this list.
const BANNED_OPCODES: &[Opcode] = &[
    Opcode::GAS,
    Opcode::GASPRICE,
    Opcode::GASLIMIT,
    Opcode::DIFFICULTY,
    Opcode::TIMESTAMP,
    Opcode::BASEFEE,
    Opcode::BLOCKHASH,
    Opcode::NUMBER,
    Opcode::SELFBALANCE,
    Opcode::BALANCE,
    Opcode::ORIGIN,
    Opcode::CREATE,
    Opcode::COINBASE,
    Opcode::SELFDESTRUCT,
];

// Pre calculated method signatures
const SIMULATE_VALIDATION_METHOD: &str = "0xee219423";
const CREATE_SENDER_METHOD: &str = "0x570e1a36";
const VALIDATE_USER_OP_METHOD: &str = "0x19822f7c";
const VALIDATE_PAYMASTER_USER_OP_METHOD: &str = "0x52b7512c";
const DEPOSIT_TO_METHOD: &str = "0xb760faf9";
// Max precompile address 0x10000
const MAX_PRECOMPILE_ADDRESS: Address =
    H160([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0]);

/// A provider for creating `ValidationContext` for entry point v0.7.
pub(crate) struct ValidationContextProvider<T> {
    simulate_validation_tracer: T,
    sim_settings: SimulationSettings,
    entry_point_address: Address,
}

#[async_trait::async_trait]
impl<T> ValidationContextProviderTrait for ValidationContextProvider<T>
where
    T: SimulateValidationTracer,
{
    type UO = UserOperation;

    async fn get_context(
        &self,
        op: Self::UO,
        block_id: BlockId,
    ) -> Result<ValidationContext<Self::UO>, ViolationError<SimulationViolation>> {
        let tracer_out = self
            .simulate_validation_tracer
            .trace_simulate_validation(op.clone(), block_id, self.sim_settings.max_verification_gas)
            .await?;

        let call_stack = self.parse_call_stack(tracer_out.calls.clone())?;

        let top = call_stack
            .get(&self.entry_point_address)
            .context("No calls to entry point in call stack")?
            .iter()
            .find(|call| call.method == SIMULATE_VALIDATION_METHOD)
            .context("No top level call found in call stack")?;

        let mut entry_point_out = match self.parse_top_call(top)? {
            Ok(validation_output) => validation_output,
            Err(revert) => Err(ViolationError::Violations(vec![
                SimulationViolation::ValidationRevert(revert),
            ]))?,
        };
        if entry_point_out.return_info.valid_until == 0.into() {
            entry_point_out.return_info.valid_until = u64::MAX.into();
        }

        let entity_infos = sim_context::infos_from_validation_output(
            op.factory(),
            op.sender(),
            op.paymaster(),
            &entry_point_out,
            self.sim_settings,
        );

        let mut tracer_out = self.parse_tracer_out(&op, tracer_out)?;

        // Check the call stack for calls with value or to the entry point
        for calls in call_stack.values() {
            for call in calls {
                // TODO(danc): try to attribute the call to the correct entity
                if call.to == self.entry_point_address
                    && (call.from != self.entry_point_address && call.from != Address::zero())
                {
                    // [OP-053] - can only call fallback from sender
                    if call.method == "0x" && call.from == op.sender() {
                        continue;
                    }
                    // [OP-052] - can only call depositTo() from sender or factory
                    if call.method == DEPOSIT_TO_METHOD
                        && (call.from == op.sender() || Some(call.from) == op.factory())
                    {
                        continue;
                    }

                    // [OP-054] all other calls to entry point are banned
                    tracer_out.phases[1].called_banned_entry_point_method = true;
                }

                // [OP-061] calls with value are banned, except for the calls above
                if call.value.is_some_and(|v| v != U256::zero()) {
                    tracer_out.phases[1].called_non_entry_point_with_value = true;
                }
            }
        }

        Ok(ValidationContext {
            has_factory: op.factory().is_some(),
            op,
            block_id,
            entity_infos,
            entry_point_out,
            entities_needing_stake: vec![],
            accessed_addresses: HashSet::new(),
            associated_addresses: tracer_out.associated_slots_by_address.addresses(),
            tracer_out,
        })
    }

    /// Get the violations specific to the particular entry point this provider targets.
    fn get_specific_violations(
        &self,
        context: &ValidationContext<Self::UO>,
    ) -> Vec<SimulationViolation> {
        let mut violations = vec![];

        let &ValidationContext {
            entry_point_out, ..
        } = &context;

        if entry_point_out.return_info.account_sig_failed {
            violations.push(SimulationViolation::InvalidAccountSignature);
        }
        if entry_point_out.return_info.paymaster_sig_failed {
            violations.push(SimulationViolation::InvalidPaymasterSignature);
        }

        violations
    }
}

#[derive(Debug)]
#[allow(unused)]
struct CallWithResult {
    call_type: Opcode,
    method: String,
    to: Address,
    from: Address,
    value: Option<U256>,
    gas: u64,
    gas_used: u64,
    exit_type: ExitType,
    exit_data: String,
}

impl<T> ValidationContextProvider<T> {
    fn parse_call_stack(
        &self,
        mut calls: Vec<CallInfo>,
    ) -> anyhow::Result<HashMap<Address, Vec<CallWithResult>>> {
        let mut call_stack = Vec::new();
        let mut ret: HashMap<Address, Vec<CallWithResult>> = HashMap::new();
        let last_exit_info = calls.pop().context("call stack had no calls")?;
        for call in calls {
            match call {
                CallInfo::Exit(exit_info) => {
                    let method_info: MethodInfo = call_stack
                        .pop()
                        .context("unbalanced call stack, exit without method call")?;
                    ret.entry(method_info.to).or_default().push(CallWithResult {
                        call_type: method_info.method_type,
                        method: method_info.method,
                        to: method_info.to,
                        from: method_info.from,
                        value: method_info.value,
                        gas: method_info.gas,
                        gas_used: exit_info.gas_used,
                        exit_type: exit_info.exit_type,
                        exit_data: exit_info.data,
                    });
                }
                CallInfo::Method(info) => {
                    call_stack.push(info);
                }
            }
        }

        // final call is simulate handle ops, but is not part of the call stack
        match last_exit_info {
            CallInfo::Exit(exit_info) => {
                ret.entry(self.entry_point_address)
                    .or_default()
                    .push(CallWithResult {
                        call_type: Opcode::CALL,
                        method: SIMULATE_VALIDATION_METHOD.to_string(),
                        to: self.entry_point_address,
                        from: Address::zero(),
                        value: None,
                        gas: 0,
                        gas_used: exit_info.gas_used,
                        exit_type: exit_info.exit_type,
                        exit_data: exit_info.data,
                    });
            }
            CallInfo::Method(info) => {
                bail!("Final call stack entry is not an exit: {info:?}")
            }
        }

        Ok(ret)
    }

    fn parse_top_call(
        &self,
        top: &CallWithResult,
    ) -> anyhow::Result<Result<ValidationOutput, ValidationRevert>> {
        match top.exit_type {
            ExitType::Revert => {
                if let Ok(result) = FailedOpWithRevert::decode_hex(top.exit_data.clone()) {
                    if let Ok(inner_result) = ContractRevertError::decode(&result.inner) {
                        Ok(Err(ValidationRevert::Operation(
                            format!("{} : {}", result.reason, inner_result.reason),
                            Bytes::default(),
                        )))
                    } else {
                        Ok(Err(ValidationRevert::Operation(
                            result.reason,
                            result.inner,
                        )))
                    }
                } else if let Ok(failed_op) = FailedOp::decode_hex(top.exit_data.clone()) {
                    Ok(Err(ValidationRevert::EntryPoint(failed_op.reason)))
                } else if let Ok(err) = ContractRevertError::decode_hex(top.exit_data.clone()) {
                    Ok(Err(ValidationRevert::EntryPoint(err.reason)))
                } else {
                    Ok(Err(ValidationRevert::Unknown(
                        Bytes::from_hex(top.exit_data.clone())
                            .context("failed to parse exit data has hex")?,
                    )))
                }
            }
            ExitType::Return => {
                let b = Bytes::from_hex(top.exit_data.clone())
                    .context("faled to parse exit data as hex")?;
                if let Ok(res) = SimulateValidationReturn::decode(&b) {
                    Ok(Ok(res.0.into()))
                } else {
                    bail!("Failed to decode validation output {}", top.exit_data);
                }
            }
        }
    }

    fn parse_tracer_out(
        &self,
        op: &UserOperation,
        tracer_out: TracerOutput,
    ) -> anyhow::Result<ContextTracerOutput> {
        let mut phases = vec![Phase::default(); 3];
        let mut factory_called_create2_twice = false;
        let mut expected_storage: BTreeMap<Address, BTreeMap<U256, U256>> = BTreeMap::new();

        // Check factory
        if let Some(call_from_entry_point) = tracer_out
            .calls_from_entry_point
            .iter()
            .find(|c| c.top_level_method_sig == CREATE_SENDER_METHOD)
        {
            phases[0] = Self::parse_call_to_phase(
                call_from_entry_point,
                &mut expected_storage,
                EntityType::Factory,
            );
            // [OP-031] - create call can only be called once
            if let Some(count) = call_from_entry_point.opcodes.get(&Opcode::CREATE2) {
                if *count > 1 {
                    factory_called_create2_twice = true;
                }
            }
        }

        // Check account
        if let Some(call_from_entry_point) = tracer_out
            .calls_from_entry_point
            .iter()
            .find(|c| c.top_level_method_sig == VALIDATE_USER_OP_METHOD)
        {
            phases[1] = Self::parse_call_to_phase(
                call_from_entry_point,
                &mut expected_storage,
                EntityType::Account,
            );
        }

        // Check paymaster
        if let Some(call_from_entry_point) = tracer_out
            .calls_from_entry_point
            .iter()
            .find(|c| c.top_level_method_sig == VALIDATE_PAYMASTER_USER_OP_METHOD)
        {
            phases[2] = Self::parse_call_to_phase(
                call_from_entry_point,
                &mut expected_storage,
                EntityType::Paymaster,
            );
        }

        // Accessed contracts
        let accessed_contract_addresses = tracer_out
            .calls_from_entry_point
            .iter()
            .flat_map(|call| call.contract_size.keys().cloned())
            .collect();

        // Associated slots
        let factory = op
            .factory()
            .map(|f| (f, format!("0x000000000000000000000000{f:x}")));
        let paymaster = op
            .paymaster()
            .map(|p| (p, format!("0x000000000000000000000000{p:x}")));
        let sender = (
            op.sender(),
            format!("0x000000000000000000000000{:x}", op.sender()),
        );

        let mut associated_slots_by_address: HashMap<Address, BTreeSet<U256>> = HashMap::new();
        for k in &tracer_out.keccak {
            if let Some((f, addr)) = &factory {
                Self::check_associated_slot(addr, *f, k, &mut associated_slots_by_address)?;
            }
            if let Some((p, addr)) = &paymaster {
                Self::check_associated_slot(addr, *p, k, &mut associated_slots_by_address)?;
            }
            Self::check_associated_slot(&sender.1, sender.0, k, &mut associated_slots_by_address)?;
        }

        Ok(ContextTracerOutput {
            phases,
            revert_data: None,
            accessed_contract_addresses,
            associated_slots_by_address: AssociatedSlotsByAddress(associated_slots_by_address),
            factory_called_create2_twice,
            expected_storage: ExpectedStorage(expected_storage),
        })
    }

    fn parse_call_to_phase(
        call: &TopLevelCallInfo,
        expected_storage: &mut BTreeMap<Address, BTreeMap<U256, U256>>,
        entity_type: EntityType,
    ) -> Phase {
        // [OP-011] - banned opcodes
        // [OP-012] - tracer will not add GAS to list if followed by *CALL
        let mut forbidden_opcodes_used = vec![];
        for opcode in call.opcodes.keys() {
            if BANNED_OPCODES.contains(opcode)
                || (*opcode == Opcode::CREATE2 && entity_type != EntityType::Factory)
            // [OP-031] - CREATE2 allowed by factory
            {
                forbidden_opcodes_used
                    .push(format!("{}:{}", call.top_level_target_address, opcode));
            }
        }

        let storage_accesses = call
            .access
            .iter()
            .map(|(address, info)| {
                let reads = info.reads.iter().map(|(slot, value)| {
                    expected_storage
                        .entry(*address)
                        .or_default()
                        .insert(*slot, *value);
                    (*slot, *value)
                });
                let writes = info.writes.iter().map(|(slot, count)| (*slot, *count));
                (
                    *address,
                    AccessInfo {
                        reads: reads.collect(),
                        writes: writes.collect(),
                    },
                )
            })
            .collect();

        let mut forbidden_precompiles_used = vec![];
        let mut undeployed_contract_accesses = vec![];
        call.contract_size.iter().for_each(|(address, info)| {
            if info.contract_size == 0 {
                if *address < MAX_PRECOMPILE_ADDRESS {
                    // [OP-062] - banned precompiles
                    // The tracer catches any allowed precompiles and does not add them to this list
                    forbidden_precompiles_used
                        .push(format!("{}:{}", call.top_level_target_address, *address,));
                } else {
                    // [OP-041]
                    undeployed_contract_accesses.push(*address);
                }
            }
        });

        Phase {
            forbidden_opcodes_used,
            forbidden_precompiles_used,
            storage_accesses,
            called_banned_entry_point_method: false, // set during call stack parsing
            called_non_entry_point_with_value: false, // set during call stack parsing
            // [OP-020]
            ran_out_of_gas: call.oog.unwrap_or(false),
            undeployed_contract_accesses,
            ext_code_access_info: call.ext_code_access_info.clone(),
        }
    }

    fn check_associated_slot(
        addr_str: &str,
        addr: Address,
        k: &str,
        associated_slots: &mut HashMap<Address, BTreeSet<U256>>,
    ) -> anyhow::Result<()> {
        if k.starts_with(addr_str) {
            associated_slots.entry(addr).or_default().insert(
                keccak256(Bytes::from_hex(k).context("failed to parse keccak as hex")?).into(),
            );
        }
        Ok(())
    }
}

impl<P, E> ValidationContextProvider<SimulateValidationTracerImpl<P, E>>
where
    P: Provider,
    E: EntryPoint + SimulationProvider<UO = UserOperation>,
{
    /// Creates a new `ValidationContextProvider` for entry point v0.7 with the given provider and entry point.
    pub(crate) fn new(provider: Arc<P>, entry_point: E, sim_settings: SimulationSettings) -> Self {
        Self {
            entry_point_address: entry_point.address(),
            simulate_validation_tracer: SimulateValidationTracerImpl::new(provider, entry_point),
            sim_settings,
        }
    }
}
