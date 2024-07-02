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

use std::{collections::HashSet, sync::Arc};

use ethers::{abi::AbiDecode, types::BlockId};
use rundler_provider::{Provider, SimulationProvider};
use rundler_types::{
    contracts::v0_6::i_entry_point::FailedOp, pool::SimulationViolation, v0_6::UserOperation,
    EntityType, UserOperation as UserOperationTrait, ValidationOutput,
};

use super::{
    tracer::{SimulateValidationTracer, SimulateValidationTracerImpl},
    REQUIRED_VERIFICATION_GAS_LIMIT_BUFFER,
};
use crate::{
    simulation::context::{
        self as sim_context, ValidationContext,
        ValidationContextProvider as ValidationContextProviderTrait,
    },
    SimulationSettings, ViolationError,
};

/// A provider for creating `ValidationContext` for entry point v0.6.
pub(crate) struct ValidationContextProvider<T> {
    simulate_validation_tracer: T,
    sim_settings: SimulationSettings,
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
        let factory_address = op.factory();
        let sender_address = op.sender;
        let paymaster_address = op.paymaster();
        let tracer_out = self
            .simulate_validation_tracer
            .trace_simulate_validation(op.clone(), block_id)
            .await?;
        let num_phases = tracer_out.phases.len() as u32;
        // Check if there are too many phases here, then check too few at the
        // end. We are detecting cases where the entry point is broken. Too many
        // phases definitely means it's broken, but too few phases could still
        // mean the entry point is fine if one of the phases fails and it
        // doesn't reach the end of execution.
        if num_phases > 3 {
            Err(ViolationError::Violations(vec![
                SimulationViolation::WrongNumberOfPhases(num_phases),
            ]))?
        }
        let Some(ref revert_data) = tracer_out.revert_data else {
            Err(ViolationError::Violations(vec![
                SimulationViolation::DidNotRevert,
            ]))?
        };
        let last_entity_type =
            sim_context::entity_type_from_simulation_phase(tracer_out.phases.len() - 1).unwrap();

        if let Ok(failed_op) = FailedOp::decode_hex(revert_data) {
            let entity_addr = match last_entity_type {
                EntityType::Factory => factory_address,
                EntityType::Paymaster => paymaster_address,
                EntityType::Account => Some(sender_address),
                _ => None,
            };
            Err(ViolationError::Violations(vec![
                SimulationViolation::UnintendedRevertWithMessage(
                    last_entity_type,
                    failed_op.reason,
                    entity_addr,
                ),
            ]))?
        }
        let Ok(entry_point_out) = ValidationOutput::decode_v0_6_hex(revert_data) else {
            let entity_addr = match last_entity_type {
                EntityType::Factory => factory_address,
                EntityType::Paymaster => paymaster_address,
                EntityType::Account => Some(sender_address),
                _ => None,
            };
            Err(ViolationError::Violations(vec![
                SimulationViolation::UnintendedRevert(last_entity_type, entity_addr),
            ]))?
        };
        let entity_infos = sim_context::infos_from_validation_output(
            factory_address,
            sender_address,
            paymaster_address,
            &entry_point_out,
            &self.sim_settings,
        );

        let associated_addresses = tracer_out.associated_slots_by_address.addresses();
        let has_factory = op.factory().is_some();
        Ok(ValidationContext {
            op,
            block_id,
            entity_infos,
            tracer_out,
            entry_point_out,
            associated_addresses,
            accessed_addresses: HashSet::new(),
            has_factory,
        })
    }

    fn get_specific_violations(
        &self,
        context: &ValidationContext<Self::UO>,
    ) -> Vec<SimulationViolation> {
        let mut violations = vec![];

        let &ValidationContext {
            entry_point_out,
            op,
            ..
        } = &context;

        if context.op.paymaster().is_some()
            && !entry_point_out.return_info.paymaster_context.is_empty()
            && !context.entity_infos.paymaster.unwrap().is_staked
        {
            // [EREP-050] (only v0.6)
            violations.push(SimulationViolation::UnstakedPaymasterContext);
        }

        // v0.6 doesn't distinguish between the different types of signature failures
        // both of these will be set to true if the signature failed.
        if entry_point_out.return_info.account_sig_failed
            || entry_point_out.return_info.paymaster_sig_failed
        {
            violations.push(SimulationViolation::InvalidSignature);
        }

        // This is a special case to cover a bug in the 0.6 entrypoint contract where a specially
        // crafted UO can use extra verification gas that isn't caught during simulation, but when
        // it runs on chain causes the transaction to revert.
        let verification_gas_used = entry_point_out
            .return_info
            .pre_op_gas
            .saturating_sub(op.pre_verification_gas());
        let verification_buffer = op
            .total_verification_gas_limit()
            .saturating_sub(verification_gas_used);
        if verification_buffer < REQUIRED_VERIFICATION_GAS_LIMIT_BUFFER {
            violations.push(SimulationViolation::VerificationGasLimitBufferTooLow(
                op.total_verification_gas_limit(),
                verification_gas_used + REQUIRED_VERIFICATION_GAS_LIMIT_BUFFER,
            ));
        }

        violations
    }
}

impl<P, E> ValidationContextProvider<SimulateValidationTracerImpl<P, E>>
where
    P: Provider,
    E: SimulationProvider<UO = UserOperation>,
{
    /// Creates a new `ValidationContextProvider` for entry point v0.6 with the given provider and entry point.
    pub(crate) fn new(provider: Arc<P>, entry_point: E, sim_settings: SimulationSettings) -> Self {
        Self {
            simulate_validation_tracer: SimulateValidationTracerImpl::new(
                provider,
                entry_point,
                sim_settings.max_verification_gas,
                sim_settings.tracer_timeout.clone(),
            ),
            sim_settings,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, str::FromStr};

    use ethers::{
        abi::AbiEncode,
        types::{Address, Bytes, U256},
        utils::hex,
    };
    use rundler_types::{contracts::v0_6::i_entry_point::FailedOp, v0_6::UserOperation, Opcode};
    use sim_context::ContractInfo;

    use super::*;
    use crate::simulation::context::{Phase, TracerOutput};

    fn get_test_tracer_output() -> TracerOutput {
        TracerOutput {
            accessed_contracts: HashMap::from([
                (
                    Address::from_str("0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789").unwrap(),
                    ContractInfo {
                        header: "0x608060".to_string(),
                        opcode: Opcode::CALL,
                        length: 32,
                    }
                ),
                (
                    Address::from_str("0xb856dbd4fa1a79a46d426f537455e7d3e79ab7c4").unwrap(),
                    ContractInfo {
                        header: "0x608060".to_string(),
                        opcode: Opcode::CALL,
                        length: 32,
                    }
                ),
                (
                    Address::from_str("0x8abb13360b87be5eeb1b98647a016add927a136c").unwrap(),
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
                    called_non_entry_point_with_value: true,
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
        }
    }

    mockall::mock! {
        Tracer {}

        #[async_trait::async_trait]
        impl SimulateValidationTracer for Tracer {
            async fn trace_simulate_validation(
                &self,
                op: UserOperation,
                block_id: BlockId,
            ) -> anyhow::Result<TracerOutput>;
        }
    }

    #[tokio::test]
    async fn test_create_context_two_phases_unintended_revert() {
        let mut tracer = MockTracer::new();

        tracer.expect_trace_simulate_validation().returning(|_, _| {
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

        let context = ValidationContextProvider {
            simulate_validation_tracer: tracer,
            sim_settings: Default::default(),
        };

        let res = context
            .get_context(user_operation.clone(), BlockId::Number(0.into()))
            .await;

        assert!(matches!(
            res,
            Err(ViolationError::Violations(violations)) if matches!(
                violations.first(),
                Some(&SimulationViolation::UnintendedRevertWithMessage(
                    EntityType::Paymaster,
                    ref reason,
                    _
                )) if reason == "AA23 reverted (or OOG)"
            )
        ));
    }
}
