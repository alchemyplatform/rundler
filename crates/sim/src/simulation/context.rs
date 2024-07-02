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

use anyhow::Context;
use ethers::types::{Address, BlockId, U256};
use rundler_types::{
    pool::SimulationViolation, EntityInfos, EntityType, Opcode, StakeInfo, UserOperation,
    ValidationOutput,
};
use serde::{Deserialize, Serialize};

use super::Settings;
use crate::{ExpectedStorage, ViolationError};

#[derive(Clone, Debug)]
pub struct ValidationContext<UO> {
    pub(crate) op: UO,
    pub(crate) block_id: BlockId,
    pub(crate) entity_infos: EntityInfos,
    pub(crate) tracer_out: TracerOutput,
    pub(crate) entry_point_out: ValidationOutput,
    pub(crate) accessed_addresses: HashSet<Address>,
    pub(crate) has_factory: bool,
    pub(crate) associated_addresses: HashSet<Address>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TracerOutput {
    pub(crate) phases: Vec<Phase>,
    pub(crate) revert_data: Option<String>,
    pub(crate) accessed_contracts: HashMap<Address, ContractInfo>,
    pub(crate) associated_slots_by_address: AssociatedSlotsByAddress,
    pub(crate) factory_called_create2_twice: bool,
    pub(crate) expected_storage: ExpectedStorage,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Phase {
    pub(crate) forbidden_opcodes_used: Vec<String>,
    pub(crate) forbidden_precompiles_used: Vec<String>,
    pub(crate) storage_accesses: HashMap<Address, AccessInfo>,
    pub(crate) called_banned_entry_point_method: bool,
    pub(crate) called_non_entry_point_with_value: bool,
    pub(crate) ran_out_of_gas: bool,
    pub(crate) undeployed_contract_accesses: Vec<Address>,
    pub(crate) ext_code_access_info: HashMap<Address, Opcode>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ContractInfo {
    pub(crate) header: String,
    pub(crate) opcode: Opcode,
    pub(crate) length: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct AccessInfo {
    // slot value, just prior this current operation
    pub(crate) reads: HashMap<U256, U256>,
    // count of writes.
    pub(crate) writes: HashMap<U256, u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct AssociatedSlotsByAddress(pub(crate) HashMap<Address, BTreeSet<U256>>);

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

/// Trait for providing the validation context for a user operation.
#[async_trait::async_trait]
pub trait ValidationContextProvider: Send + Sync + 'static {
    /// The user operation type this provider targets.
    type UO: UserOperation;

    /// Get the validation context for a user operation.
    async fn get_context(
        &self,
        op: Self::UO,
        block_id: BlockId,
    ) -> Result<ValidationContext<Self::UO>, ViolationError<SimulationViolation>>;

    /// Get the violations specific to the particular entry point this provider targets.
    fn get_specific_violations(
        &self,
        _context: &ValidationContext<Self::UO>,
    ) -> Vec<SimulationViolation>;
}

pub(crate) fn entity_type_from_simulation_phase(i: usize) -> Option<EntityType> {
    match i {
        0 => Some(EntityType::Factory),
        1 => Some(EntityType::Account),
        2 => Some(EntityType::Paymaster),
        _ => None,
    }
}

pub(crate) fn infos_from_validation_output(
    factory_address: Option<Address>,
    sender_address: Address,
    paymaster_address: Option<Address>,
    entry_point_out: &ValidationOutput,
    sim_settings: &Settings,
) -> EntityInfos {
    let mut ei = EntityInfos::default();
    ei.set_sender(
        sender_address,
        is_staked(entry_point_out.sender_info, sim_settings),
    );
    if let Some(factory_address) = factory_address {
        ei.set_factory(
            factory_address,
            is_staked(entry_point_out.factory_info, sim_settings),
        );
    }
    if let Some(paymaster_address) = paymaster_address {
        ei.set_paymaster(
            paymaster_address,
            is_staked(entry_point_out.paymaster_info, sim_settings),
        );
    }
    if let Some(aggregator_info) = entry_point_out.aggregator_info {
        ei.set_aggregator(
            aggregator_info.address,
            is_staked(aggregator_info.stake_info, sim_settings),
        );
    }

    ei
}

pub(crate) fn is_staked(info: StakeInfo, sim_settings: &Settings) -> bool {
    info.stake >= sim_settings.min_stake_value.into()
        && info.unstake_delay_sec >= sim_settings.min_unstake_delay.into()
}

pub(crate) fn parse_combined_context_str<A, B>(combined: &str) -> anyhow::Result<(A, B)>
where
    A: std::str::FromStr,
    B: std::str::FromStr,
    <A as std::str::FromStr>::Err: std::error::Error + Send + Sync + 'static,
    <B as std::str::FromStr>::Err: std::error::Error + Send + Sync + 'static,
{
    let (a, b) = combined
        .split_once(':')
        .context("tracer combined should contain two parts")?;
    Ok((a.parse()?, b.parse()?))
}
