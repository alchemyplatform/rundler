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

use alloy_primitives::{Address, U256};
use anyhow::Context;
use rundler_provider::BlockId;
use rundler_types::{
    EntityInfo, EntityInfos, EntityType, ExpectedStorage, Opcode, StakeInfo, UserOperation,
    ValidationOutput, pool::SimulationViolation,
};
use serde::{Deserialize, Serialize};

use super::Settings;
use crate::ViolationError;

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
        if slot == U256::from_be_bytes(address.into_word().into()) {
            return true;
        }
        let Some(associated_slots) = self.0.get(&address) else {
            return false;
        };
        let Some(&next_smallest_slot) =
            associated_slots.range(..(slot + U256::from(1))).next_back()
        else {
            return false;
        };
        (slot - next_smallest_slot) < U256::from(128)
    }

    pub(crate) fn addresses(&self) -> HashSet<Address> {
        self.0.clone().into_keys().collect()
    }
}

/// Trait for providing the validation context for a user operation.
#[async_trait::async_trait]
pub trait ValidationContextProvider: Send + Sync {
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
    ) -> anyhow::Result<Vec<SimulationViolation>>;
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
        ei.set_aggregator(aggregator_info.address);
    }

    ei
}

pub(crate) fn is_staked(info: StakeInfo, sim_settings: &Settings) -> bool {
    info.stake >= sim_settings.min_stake_value
        && info.unstake_delay_sec >= sim_settings.min_unstake_delay
}

pub(crate) fn override_is_staked(ei: &mut EntityInfo, allow_unstaked_addresses: &HashSet<Address>) {
    ei.is_staked = allow_unstaked_addresses.contains(&ei.entity.address) || ei.is_staked;
}

pub(crate) fn override_infos_staked(
    eis: &mut EntityInfos,
    allow_unstaked_addresses: &HashSet<Address>,
) {
    override_is_staked(&mut eis.sender, allow_unstaked_addresses);

    if let Some(factory) = &mut eis.factory {
        override_is_staked(factory, allow_unstaked_addresses);
    }
    if let Some(paymaster) = &mut eis.paymaster {
        override_is_staked(paymaster, allow_unstaked_addresses);
    }
    if let Some(aggregator) = &mut eis.aggregator {
        override_is_staked(aggregator, allow_unstaked_addresses);
    }
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

#[cfg(test)]
mod tests {
    use alloy_primitives::address;
    use rundler_types::{Entity, EntityInfo, EntityInfos};

    use super::*;

    fn create_entity_info(entity: Entity, is_staked: bool) -> EntityInfo {
        EntityInfo::new(entity, is_staked)
    }

    #[test]
    fn test_override_is_staked_when_in_allow_list() {
        let addr = address!("0x1111111111111111111111111111111111111111");
        let mut entity_info = create_entity_info(Entity::account(addr), false);
        let allow_unstaked = HashSet::from([addr]);

        override_is_staked(&mut entity_info, &allow_unstaked);

        assert!(entity_info.is_staked);
    }

    #[test]
    fn test_override_is_staked_when_not_in_allow_list() {
        let addr = address!("0x1111111111111111111111111111111111111111");
        let other_addr = address!("0x2222222222222222222222222222222222222222");
        let mut entity_info = create_entity_info(Entity::account(addr), false);
        let allow_unstaked = HashSet::from([other_addr]);

        override_is_staked(&mut entity_info, &allow_unstaked);

        assert!(!entity_info.is_staked);
    }

    #[test]
    fn test_override_is_staked_preserves_already_staked() {
        let addr = address!("0x1111111111111111111111111111111111111111");
        let mut entity_info = create_entity_info(Entity::account(addr), true);
        let allow_unstaked = HashSet::new();

        override_is_staked(&mut entity_info, &allow_unstaked);

        assert!(entity_info.is_staked);
    }

    #[test]
    fn test_override_infos_staked_sender_only() {
        let sender_addr = address!("0x1111111111111111111111111111111111111111");
        let mut entity_infos = EntityInfos {
            sender: create_entity_info(Entity::account(sender_addr), false),
            factory: None,
            paymaster: None,
            aggregator: None,
        };
        let allow_unstaked = HashSet::from([sender_addr]);

        override_infos_staked(&mut entity_infos, &allow_unstaked);

        assert!(entity_infos.sender.is_staked);
    }

    #[test]
    fn test_override_infos_staked_all_entities() {
        let sender_addr = address!("0x1111111111111111111111111111111111111111");
        let factory_addr = address!("0x2222222222222222222222222222222222222222");
        let paymaster_addr = address!("0x3333333333333333333333333333333333333333");
        let aggregator_addr = address!("0x4444444444444444444444444444444444444444");

        let mut entity_infos = EntityInfos {
            sender: create_entity_info(Entity::account(sender_addr), false),
            factory: Some(create_entity_info(Entity::factory(factory_addr), false)),
            paymaster: Some(create_entity_info(Entity::paymaster(paymaster_addr), false)),
            aggregator: Some(create_entity_info(
                Entity::aggregator(aggregator_addr),
                false,
            )),
        };

        // Only allow sender and paymaster
        let allow_unstaked = HashSet::from([sender_addr, paymaster_addr]);

        override_infos_staked(&mut entity_infos, &allow_unstaked);

        assert!(entity_infos.sender.is_staked);
        assert!(!entity_infos.factory.unwrap().is_staked);
        assert!(entity_infos.paymaster.unwrap().is_staked);
        assert!(!entity_infos.aggregator.unwrap().is_staked);
    }

    #[test]
    fn test_override_infos_staked_empty_allow_list() {
        let sender_addr = address!("0x1111111111111111111111111111111111111111");
        let factory_addr = address!("0x2222222222222222222222222222222222222222");

        let mut entity_infos = EntityInfos {
            sender: create_entity_info(Entity::account(sender_addr), false),
            factory: Some(create_entity_info(Entity::factory(factory_addr), true)), // already staked
            paymaster: None,
            aggregator: None,
        };

        let allow_unstaked = HashSet::new();

        override_infos_staked(&mut entity_infos, &allow_unstaked);

        assert!(!entity_infos.sender.is_staked);
        assert!(entity_infos.factory.unwrap().is_staked); // should remain staked
    }
}
