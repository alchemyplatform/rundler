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

use std::marker::PhantomData;

use alloy_primitives::B256;
use rundler_provider::{AggregatorOut, EntryPoint, SignatureAggregator, SimulationProvider};
use rundler_types::{pool::SimulationViolation, EntityInfos, UserOperation, ValidTimeRange};

use crate::{SimulationError, SimulationResult, Simulator, ViolationError};

/// An unsafe simulator that can be used in place of a regular simulator
/// to extract the information needed from simulation while avoiding the use
/// of debug_traceCall.
///
/// WARNING: This is "unsafe" for a reason. None of the ERC-7562 checks are
/// performed.
pub struct UnsafeSimulator<UO, E> {
    entry_point: E,
    _uo_type: PhantomData<UO>,
}

impl<UO, E> UnsafeSimulator<UO, E> {
    /// Creates a new unsafe simulator
    pub fn new(entry_point: E) -> Self {
        Self {
            entry_point,
            _uo_type: PhantomData,
        }
    }
}

#[async_trait::async_trait]
impl<UO, E> Simulator for UnsafeSimulator<UO, E>
where
    UO: UserOperation,
    E: EntryPoint + SimulationProvider<UO = UO> + SignatureAggregator<UO = UO> + Clone,
{
    type UO = UO;

    // Run an unsafe simulation
    //
    // The only validation checks that are performed are signature checks
    async fn simulate_validation(
        &self,
        op: UO,
        block_hash: B256,
        _expected_code_hash: Option<B256>,
    ) -> Result<SimulationResult, SimulationError> {
        tracing::info!("Performing unsafe simulation");

        // simulate the validation
        let validation_result = self
            .entry_point
            .simulate_validation(op.clone(), Some(block_hash.into()))
            .await?;

        let validation_result = match validation_result {
            Ok(res) => res,
            Err(err) => {
                return Err(SimulationError {
                    violation_error: vec![SimulationViolation::ValidationRevert(err)].into(),
                    entity_infos: None,
                });
            }
        };

        let valid_until = if validation_result.return_info.valid_until == 0.into() {
            u64::MAX.into()
        } else {
            validation_result.return_info.valid_until
        };

        let pre_op_gas = validation_result.return_info.pre_op_gas;
        let valid_time_range =
            ValidTimeRange::new(validation_result.return_info.valid_after, valid_until);
        let requires_post_op = !validation_result.return_info.paymaster_context.is_empty();

        let mut entity_infos = EntityInfos::default();
        entity_infos.set_sender(op.sender(), false);
        if let Some(f) = op.factory() {
            entity_infos.set_factory(f, false);
        }
        if let Some(p) = op.paymaster() {
            entity_infos.set_paymaster(p, false);
        }
        if let Some(a) = validation_result.aggregator_info {
            entity_infos.set_aggregator(a.address, false);
        }

        let mut violations = vec![];

        let aggregator = if let Some(aggregator_info) = validation_result.aggregator_info {
            let agg_out = self
                .entry_point
                .validate_user_op_signature(aggregator_info.address, op)
                .await?;

            match agg_out {
                AggregatorOut::NotNeeded => None,
                AggregatorOut::SuccessWithInfo(info) => Some(info),
                AggregatorOut::ValidationReverted => {
                    violations.push(SimulationViolation::AggregatorValidationFailed);
                    None
                }
            }
        } else {
            None
        };

        if validation_result.return_info.account_sig_failed {
            violations.push(SimulationViolation::InvalidAccountSignature);
        }

        if validation_result.return_info.paymaster_sig_failed {
            violations.push(SimulationViolation::InvalidPaymasterSignature);
        }

        if !violations.is_empty() {
            Err(SimulationError {
                violation_error: ViolationError::Violations(violations),
                entity_infos: Some(entity_infos),
            })?
        } else {
            Ok(SimulationResult {
                mempools: vec![B256::ZERO],
                pre_op_gas,
                valid_time_range,
                requires_post_op,
                entity_infos,
                aggregator,
                ..Default::default()
            })
        }
    }
}
