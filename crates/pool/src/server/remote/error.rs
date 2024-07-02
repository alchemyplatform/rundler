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

use anyhow::{bail, Context};
use rundler_task::grpc::protos::{from_bytes, ToProtoBytes};
use rundler_types::{
    pool::{
        MempoolError, NeedsStakeInformation, PoolError, PrecheckViolation, SimulationViolation,
    },
    Opcode, StorageSlot, Timestamp, ValidationRevert, ViolationOpCode,
};

use super::protos::{
    mempool_error, precheck_violation_error, simulation_violation_error, validation_revert,
    AccessedUndeployedContract, AccessedUnsupportedContractType, AggregatorValidationFailed,
    AssociatedStorageDuringDeploy, AssociatedStorageIsAlternateSender, CallGasLimitTooLow,
    CallHadValue, CalledBannedEntryPointMethod, CodeHashChanged, DidNotRevert,
    DiscardedOnInsertError, Entity, EntityThrottledError, EntityType, EntryPointRevert,
    ExistingSenderWithInitCode, FactoryCalledCreate2Twice, FactoryIsNotContract,
    InvalidAccountSignature, InvalidPaymasterSignature, InvalidSignature, InvalidStorageAccess,
    InvalidTimeRange, MaxFeePerGasTooLow, MaxOperationsReachedError, MaxPriorityFeePerGasTooLow,
    MempoolError as ProtoMempoolError, MultipleRolesViolation, NotStaked,
    OperationAlreadyKnownError, OperationDropTooSoon, OperationRevert, OutOfGas,
    PaymasterBalanceTooLow, PaymasterDepositTooLow, PaymasterIsNotContract,
    PreVerificationGasTooLow, PrecheckViolationError as ProtoPrecheckViolationError,
    ReplacementUnderpricedError, SenderAddressUsedAsAlternateEntity, SenderFundsTooLow,
    SenderIsNotContractAndNoInitCode, SimulationViolationError as ProtoSimulationViolationError,
    TotalGasLimitTooHigh, UnintendedRevert, UnintendedRevertWithMessage, UnknownEntryPointError,
    UnknownRevert, UnstakedAggregator, UnstakedPaymasterContext, UnsupportedAggregatorError,
    UsedForbiddenOpcode, UsedForbiddenPrecompile, ValidationRevert as ProtoValidationRevert,
    VerificationGasLimitBufferTooLow, VerificationGasLimitTooHigh, WrongNumberOfPhases,
};

impl TryFrom<ProtoMempoolError> for PoolError {
    type Error = anyhow::Error;

    fn try_from(value: ProtoMempoolError) -> Result<Self, Self::Error> {
        Ok(PoolError::MempoolError(value.try_into()?))
    }
}

impl From<PoolError> for ProtoMempoolError {
    fn from(value: PoolError) -> Self {
        match value {
            PoolError::MempoolError(e) => e.into(),
            PoolError::UnexpectedResponse => ProtoMempoolError {
                error: Some(mempool_error::Error::Internal(
                    "unexpected response from pool server".to_string(),
                )),
            },
            PoolError::Other(e) => ProtoMempoolError {
                error: Some(mempool_error::Error::Internal(e.to_string())),
            },
        }
    }
}

impl TryFrom<ProtoMempoolError> for MempoolError {
    type Error = anyhow::Error;

    fn try_from(value: ProtoMempoolError) -> Result<Self, Self::Error> {
        Ok(match value.error {
            Some(mempool_error::Error::Internal(e)) => MempoolError::Other(anyhow::Error::msg(e)),
            Some(mempool_error::Error::OperationAlreadyKnown(_)) => {
                MempoolError::OperationAlreadyKnown
            }
            Some(mempool_error::Error::ReplacementUnderpriced(e)) => {
                MempoolError::ReplacementUnderpriced(
                    from_bytes(&e.current_fee)?,
                    from_bytes(&e.current_priority_fee)?,
                )
            }
            Some(mempool_error::Error::MaxOperationsReached(e)) => {
                MempoolError::MaxOperationsReached(
                    e.num_ops as usize,
                    (&e.entity.context("should have entity in error")?).try_into()?,
                )
            }
            Some(mempool_error::Error::EntityThrottled(e)) => MempoolError::EntityThrottled(
                (&e.entity.context("should have entity in error")?).try_into()?,
            ),
            Some(mempool_error::Error::DiscardedOnInsert(_)) => MempoolError::DiscardedOnInsert,
            Some(mempool_error::Error::PrecheckViolation(e)) => {
                MempoolError::PrecheckViolation(e.try_into()?)
            }
            Some(mempool_error::Error::SimulationViolation(e)) => {
                MempoolError::SimulationViolation(e.try_into()?)
            }
            Some(mempool_error::Error::UnsupportedAggregator(e)) => {
                MempoolError::UnsupportedAggregator(from_bytes(&e.aggregator_address)?)
            }
            Some(mempool_error::Error::UnknownEntryPoint(e)) => {
                MempoolError::UnknownEntryPoint(from_bytes(&e.entry_point)?)
            }
            Some(mempool_error::Error::InvalidSignature(_)) => {
                MempoolError::SimulationViolation(SimulationViolation::InvalidSignature)
            }
            Some(mempool_error::Error::PaymasterBalanceTooLow(e)) => {
                MempoolError::PaymasterBalanceTooLow(
                    from_bytes(&e.current_balance)?,
                    from_bytes(&e.required_balance)?,
                )
            }
            Some(mempool_error::Error::AssociatedStorageIsAlternateSender(_)) => {
                MempoolError::AssociatedStorageIsAlternateSender
            }
            Some(mempool_error::Error::SenderAddressUsedAsAlternateEntity(e)) => {
                MempoolError::SenderAddressUsedAsAlternateEntity(from_bytes(&e.sender_address)?)
            }
            Some(mempool_error::Error::MultipleRolesViolation(e)) => {
                MempoolError::MultipleRolesViolation(
                    (&e.entity.context("should have entity in error")?).try_into()?,
                )
            }
            Some(mempool_error::Error::OperationDropTooSoon(e)) => {
                MempoolError::OperationDropTooSoon(e.added_at, e.attempted_at, e.must_wait)
            }
            None => bail!("unknown proto mempool error"),
        })
    }
}

impl From<MempoolError> for ProtoMempoolError {
    fn from(value: MempoolError) -> Self {
        match value {
            MempoolError::Other(e) => ProtoMempoolError {
                error: Some(mempool_error::Error::Internal(e.to_string())),
            },
            MempoolError::OperationAlreadyKnown => ProtoMempoolError {
                error: Some(mempool_error::Error::OperationAlreadyKnown(
                    OperationAlreadyKnownError {},
                )),
            },
            MempoolError::MultipleRolesViolation(entity) => ProtoMempoolError {
                error: Some(mempool_error::Error::MultipleRolesViolation(
                    MultipleRolesViolation {
                        entity: Some((&entity).into()),
                    },
                )),
            },
            MempoolError::AssociatedStorageIsAlternateSender => ProtoMempoolError {
                error: Some(mempool_error::Error::AssociatedStorageIsAlternateSender(
                    AssociatedStorageIsAlternateSender {},
                )),
            },
            MempoolError::SenderAddressUsedAsAlternateEntity(addr) => ProtoMempoolError {
                error: Some(mempool_error::Error::SenderAddressUsedAsAlternateEntity(
                    SenderAddressUsedAsAlternateEntity {
                        sender_address: addr.to_proto_bytes(),
                    },
                )),
            },
            MempoolError::ReplacementUnderpriced(fee, priority_fee) => ProtoMempoolError {
                error: Some(mempool_error::Error::ReplacementUnderpriced(
                    ReplacementUnderpricedError {
                        current_fee: fee.to_proto_bytes(),
                        current_priority_fee: priority_fee.to_proto_bytes(),
                    },
                )),
            },
            MempoolError::MaxOperationsReached(ops, entity) => ProtoMempoolError {
                error: Some(mempool_error::Error::MaxOperationsReached(
                    MaxOperationsReachedError {
                        num_ops: ops as u64,
                        entity: Some((&entity).into()),
                    },
                )),
            },
            MempoolError::EntityThrottled(entity) => ProtoMempoolError {
                error: Some(mempool_error::Error::EntityThrottled(
                    EntityThrottledError {
                        entity: Some((&entity).into()),
                    },
                )),
            },
            MempoolError::DiscardedOnInsert => ProtoMempoolError {
                error: Some(mempool_error::Error::DiscardedOnInsert(
                    DiscardedOnInsertError {},
                )),
            },
            MempoolError::PaymasterBalanceTooLow(current_balance, required_balance) => {
                ProtoMempoolError {
                    error: Some(mempool_error::Error::PaymasterBalanceTooLow(
                        PaymasterBalanceTooLow {
                            current_balance: current_balance.to_proto_bytes(),
                            required_balance: required_balance.to_proto_bytes(),
                        },
                    )),
                }
            }
            MempoolError::PrecheckViolation(violation) => ProtoMempoolError {
                error: Some(mempool_error::Error::PrecheckViolation(violation.into())),
            },
            MempoolError::SimulationViolation(violation) => ProtoMempoolError {
                error: Some(mempool_error::Error::SimulationViolation(violation.into())),
            },
            MempoolError::UnsupportedAggregator(agg) => ProtoMempoolError {
                error: Some(mempool_error::Error::UnsupportedAggregator(
                    UnsupportedAggregatorError {
                        aggregator_address: agg.to_proto_bytes(),
                    },
                )),
            },
            MempoolError::UnknownEntryPoint(entry_point) => ProtoMempoolError {
                error: Some(mempool_error::Error::UnknownEntryPoint(
                    UnknownEntryPointError {
                        entry_point: entry_point.to_proto_bytes(),
                    },
                )),
            },
            MempoolError::OperationDropTooSoon(added_at, attempted_at, must_wait) => {
                ProtoMempoolError {
                    error: Some(mempool_error::Error::OperationDropTooSoon(
                        OperationDropTooSoon {
                            added_at,
                            attempted_at,
                            must_wait,
                        },
                    )),
                }
            }
        }
    }
}

impl From<PrecheckViolation> for ProtoPrecheckViolationError {
    fn from(value: PrecheckViolation) -> Self {
        match value {
            PrecheckViolation::SenderIsNotContractAndNoInitCode(addr) => {
                ProtoPrecheckViolationError {
                    violation: Some(
                        precheck_violation_error::Violation::SenderIsNotContractAndNoInitCode(
                            SenderIsNotContractAndNoInitCode {
                                sender_address: addr.to_proto_bytes(),
                            },
                        ),
                    ),
                }
            }
            PrecheckViolation::ExistingSenderWithInitCode(addr) => ProtoPrecheckViolationError {
                violation: Some(
                    precheck_violation_error::Violation::ExistingSenderWithInitCode(
                        ExistingSenderWithInitCode {
                            sender_address: addr.to_proto_bytes(),
                        },
                    ),
                ),
            },
            PrecheckViolation::FactoryIsNotContract(addr) => ProtoPrecheckViolationError {
                violation: Some(precheck_violation_error::Violation::FactoryIsNotContract(
                    FactoryIsNotContract {
                        factory_address: addr.to_proto_bytes(),
                    },
                )),
            },
            PrecheckViolation::TotalGasLimitTooHigh(actual, max) => ProtoPrecheckViolationError {
                violation: Some(precheck_violation_error::Violation::TotalGasLimitTooHigh(
                    TotalGasLimitTooHigh {
                        actual_gas: actual.to_proto_bytes(),
                        max_gas: max.to_proto_bytes(),
                    },
                )),
            },
            PrecheckViolation::VerificationGasLimitTooHigh(actual, max) => {
                ProtoPrecheckViolationError {
                    violation: Some(
                        precheck_violation_error::Violation::VerificationGasLimitTooHigh(
                            VerificationGasLimitTooHigh {
                                actual_gas: actual.to_proto_bytes(),
                                max_gas: max.to_proto_bytes(),
                            },
                        ),
                    ),
                }
            }
            PrecheckViolation::PreVerificationGasTooLow(actual, min) => {
                ProtoPrecheckViolationError {
                    violation: Some(
                        precheck_violation_error::Violation::PreVerificationGasTooLow(
                            PreVerificationGasTooLow {
                                actual_gas: actual.to_proto_bytes(),
                                min_gas: min.to_proto_bytes(),
                            },
                        ),
                    ),
                }
            }
            PrecheckViolation::PaymasterIsNotContract(addr) => ProtoPrecheckViolationError {
                violation: Some(precheck_violation_error::Violation::PaymasterIsNotContract(
                    PaymasterIsNotContract {
                        paymaster_address: addr.to_proto_bytes(),
                    },
                )),
            },
            PrecheckViolation::PaymasterDepositTooLow(actual, min) => ProtoPrecheckViolationError {
                violation: Some(precheck_violation_error::Violation::PaymasterDepositTooLow(
                    PaymasterDepositTooLow {
                        actual_deposit: actual.to_proto_bytes(),
                        min_deposit: min.to_proto_bytes(),
                    },
                )),
            },
            PrecheckViolation::SenderFundsTooLow(actual, min) => ProtoPrecheckViolationError {
                violation: Some(precheck_violation_error::Violation::SenderFundsTooLow(
                    SenderFundsTooLow {
                        actual_funds: actual.to_proto_bytes(),
                        min_funds: min.to_proto_bytes(),
                    },
                )),
            },
            PrecheckViolation::MaxFeePerGasTooLow(actual, min) => ProtoPrecheckViolationError {
                violation: Some(precheck_violation_error::Violation::MaxFeePerGasTooLow(
                    MaxFeePerGasTooLow {
                        actual_fee: actual.to_proto_bytes(),
                        min_fee: min.to_proto_bytes(),
                    },
                )),
            },
            PrecheckViolation::MaxPriorityFeePerGasTooLow(actual, min) => {
                ProtoPrecheckViolationError {
                    violation: Some(
                        precheck_violation_error::Violation::MaxPriorityFeePerGasTooLow(
                            MaxPriorityFeePerGasTooLow {
                                actual_fee: actual.to_proto_bytes(),
                                min_fee: min.to_proto_bytes(),
                            },
                        ),
                    ),
                }
            }
            PrecheckViolation::CallGasLimitTooLow(actual, min) => ProtoPrecheckViolationError {
                violation: Some(precheck_violation_error::Violation::CallGasLimitTooLow(
                    CallGasLimitTooLow {
                        actual_gas_limit: actual.to_proto_bytes(),
                        min_gas_limit: min.to_proto_bytes(),
                    },
                )),
            },
        }
    }
}

impl TryFrom<ProtoPrecheckViolationError> for PrecheckViolation {
    type Error = anyhow::Error;

    fn try_from(value: ProtoPrecheckViolationError) -> Result<Self, Self::Error> {
        Ok(match value.violation {
            Some(precheck_violation_error::Violation::SenderIsNotContractAndNoInitCode(e)) => {
                PrecheckViolation::SenderIsNotContractAndNoInitCode(from_bytes(&e.sender_address)?)
            }
            Some(precheck_violation_error::Violation::ExistingSenderWithInitCode(e)) => {
                PrecheckViolation::ExistingSenderWithInitCode(from_bytes(&e.sender_address)?)
            }
            Some(precheck_violation_error::Violation::FactoryIsNotContract(e)) => {
                PrecheckViolation::FactoryIsNotContract(from_bytes(&e.factory_address)?)
            }
            Some(precheck_violation_error::Violation::TotalGasLimitTooHigh(e)) => {
                PrecheckViolation::TotalGasLimitTooHigh(
                    from_bytes(&e.actual_gas)?,
                    from_bytes(&e.max_gas)?,
                )
            }
            Some(precheck_violation_error::Violation::VerificationGasLimitTooHigh(e)) => {
                PrecheckViolation::VerificationGasLimitTooHigh(
                    from_bytes(&e.actual_gas)?,
                    from_bytes(&e.max_gas)?,
                )
            }
            Some(precheck_violation_error::Violation::PreVerificationGasTooLow(e)) => {
                PrecheckViolation::PreVerificationGasTooLow(
                    from_bytes(&e.actual_gas)?,
                    from_bytes(&e.min_gas)?,
                )
            }
            Some(precheck_violation_error::Violation::PaymasterIsNotContract(e)) => {
                PrecheckViolation::PaymasterIsNotContract(from_bytes(&e.paymaster_address)?)
            }
            Some(precheck_violation_error::Violation::PaymasterDepositTooLow(e)) => {
                PrecheckViolation::PaymasterDepositTooLow(
                    from_bytes(&e.actual_deposit)?,
                    from_bytes(&e.min_deposit)?,
                )
            }
            Some(precheck_violation_error::Violation::SenderFundsTooLow(e)) => {
                PrecheckViolation::SenderFundsTooLow(
                    from_bytes(&e.actual_funds)?,
                    from_bytes(&e.min_funds)?,
                )
            }
            Some(precheck_violation_error::Violation::MaxFeePerGasTooLow(e)) => {
                PrecheckViolation::MaxFeePerGasTooLow(
                    from_bytes(&e.actual_fee)?,
                    from_bytes(&e.min_fee)?,
                )
            }
            Some(precheck_violation_error::Violation::MaxPriorityFeePerGasTooLow(e)) => {
                PrecheckViolation::MaxPriorityFeePerGasTooLow(
                    from_bytes(&e.actual_fee)?,
                    from_bytes(&e.min_fee)?,
                )
            }
            Some(precheck_violation_error::Violation::CallGasLimitTooLow(e)) => {
                PrecheckViolation::CallGasLimitTooLow(
                    from_bytes(&e.actual_gas_limit)?,
                    from_bytes(&e.min_gas_limit)?,
                )
            }
            None => {
                bail!("unknown proto mempool precheck violation")
            }
        })
    }
}

impl From<SimulationViolation> for ProtoSimulationViolationError {
    fn from(value: SimulationViolation) -> Self {
        match value {
            SimulationViolation::InvalidSignature => ProtoSimulationViolationError {
                violation: Some(simulation_violation_error::Violation::InvalidSignature(
                    InvalidSignature {},
                )),
            },
            SimulationViolation::InvalidAccountSignature => ProtoSimulationViolationError {
                violation: Some(
                    simulation_violation_error::Violation::InvalidAccountSignature(
                        InvalidAccountSignature {},
                    ),
                ),
            },
            SimulationViolation::InvalidPaymasterSignature => ProtoSimulationViolationError {
                violation: Some(
                    simulation_violation_error::Violation::InvalidPaymasterSignature(
                        InvalidPaymasterSignature {},
                    ),
                ),
            },
            SimulationViolation::UnstakedPaymasterContext => ProtoSimulationViolationError {
                violation: Some(
                    simulation_violation_error::Violation::UnstakedPaymasterContext(
                        UnstakedPaymasterContext {},
                    ),
                ),
            },
            SimulationViolation::UnintendedRevertWithMessage(et, reason, maybe_address) => {
                ProtoSimulationViolationError {
                    violation: Some(
                        simulation_violation_error::Violation::UnintendedRevertWithMessage(
                            UnintendedRevertWithMessage {
                                entity: Some(Entity {
                                    kind: EntityType::from(et) as i32,
                                    address: maybe_address
                                        .map_or(vec![], |addr| addr.to_proto_bytes()),
                                }),
                                reason,
                            },
                        ),
                    ),
                }
            }
            SimulationViolation::UsedForbiddenOpcode(entity, addr, opcode) => {
                ProtoSimulationViolationError {
                    violation: Some(simulation_violation_error::Violation::UsedForbiddenOpcode(
                        UsedForbiddenOpcode {
                            entity: Some((&entity).into()),
                            contract_address: addr.to_proto_bytes(),
                            opcode: opcode.0 as u32,
                        },
                    )),
                }
            }
            SimulationViolation::UsedForbiddenPrecompile(
                entity,
                contract_addr,
                precompile_addr,
            ) => ProtoSimulationViolationError {
                violation: Some(
                    simulation_violation_error::Violation::UsedForbiddenPrecompile(
                        UsedForbiddenPrecompile {
                            entity: Some((&entity).into()),
                            contract_address: contract_addr.to_proto_bytes(),
                            precompile_address: precompile_addr.to_proto_bytes(),
                        },
                    ),
                ),
            },
            SimulationViolation::FactoryCalledCreate2Twice(addr) => ProtoSimulationViolationError {
                violation: Some(
                    simulation_violation_error::Violation::FactoryCalledCreate2Twice(
                        FactoryCalledCreate2Twice {
                            factory_address: addr.to_proto_bytes(),
                        },
                    ),
                ),
            },
            SimulationViolation::AssociatedStorageDuringDeploy(entity, slot) => {
                ProtoSimulationViolationError {
                    violation: Some(
                        simulation_violation_error::Violation::AssociatedStorageDuringDeploy(
                            AssociatedStorageDuringDeploy {
                                entity: entity.as_ref().map(|e| e.into()),
                                contract_address: slot.address.to_proto_bytes(),
                                slot: slot.slot.to_proto_bytes(),
                            },
                        ),
                    ),
                }
            }
            SimulationViolation::InvalidStorageAccess(entity, slot) => {
                ProtoSimulationViolationError {
                    violation: Some(simulation_violation_error::Violation::InvalidStorageAccess(
                        InvalidStorageAccess {
                            entity: Some((&entity).into()),
                            contract_address: slot.address.to_proto_bytes(),
                            slot: slot.slot.to_proto_bytes(),
                        },
                    )),
                }
            }
            SimulationViolation::NotStaked(stake_data) => ProtoSimulationViolationError {
                violation: Some(simulation_violation_error::Violation::NotStaked(
                    NotStaked {
                        needs_stake: Some((&stake_data.needs_stake).into()),
                        accessing_entity: EntityType::from(stake_data.accessing_entity) as i32,
                        accessed_address: stake_data.accessed_address.to_proto_bytes(),
                        accessed_entity: EntityType::from(stake_data.accessed_entity) as i32,
                        slot: stake_data.slot.to_proto_bytes(),
                        min_stake: stake_data.min_stake.to_proto_bytes(),
                        min_unstake_delay: stake_data.min_unstake_delay.to_proto_bytes(),
                    },
                )),
            },
            SimulationViolation::UnintendedRevert(et, maybe_address) => {
                ProtoSimulationViolationError {
                    violation: Some(simulation_violation_error::Violation::UnintendedRevert(
                        UnintendedRevert {
                            entity: Some(Entity {
                                kind: EntityType::from(et) as i32,
                                address: maybe_address.map_or(vec![], |addr| addr.to_proto_bytes()),
                            }),
                        },
                    )),
                }
            }
            SimulationViolation::ValidationRevert(revert) => ProtoSimulationViolationError {
                violation: Some(simulation_violation_error::Violation::ValidationRevert(
                    revert.into(),
                )),
            },
            SimulationViolation::DidNotRevert => ProtoSimulationViolationError {
                violation: Some(simulation_violation_error::Violation::DidNotRevert(
                    DidNotRevert {},
                )),
            },
            SimulationViolation::UnstakedAggregator => ProtoSimulationViolationError {
                violation: Some(simulation_violation_error::Violation::UnstakedAggregator(
                    UnstakedAggregator {},
                )),
            },
            SimulationViolation::WrongNumberOfPhases(num_phases) => ProtoSimulationViolationError {
                violation: Some(simulation_violation_error::Violation::WrongNumberOfPhases(
                    WrongNumberOfPhases { num_phases },
                )),
            },
            SimulationViolation::CallHadValue(entity) => ProtoSimulationViolationError {
                violation: Some(simulation_violation_error::Violation::CallHadValue(
                    CallHadValue {
                        entity: Some((&entity).into()),
                    },
                )),
            },
            SimulationViolation::OutOfGas(entity) => ProtoSimulationViolationError {
                violation: Some(simulation_violation_error::Violation::OutOfGas(OutOfGas {
                    entity: Some((&entity).into()),
                })),
            },
            SimulationViolation::AccessedUndeployedContract(entity, contract_addr) => {
                ProtoSimulationViolationError {
                    violation: Some(
                        simulation_violation_error::Violation::AccessedUndeployedContract(
                            AccessedUndeployedContract {
                                entity: Some((&entity).into()),
                                contract_address: contract_addr.to_proto_bytes(),
                            },
                        ),
                    ),
                }
            }
            SimulationViolation::CalledBannedEntryPointMethod(entity) => {
                ProtoSimulationViolationError {
                    violation: Some(
                        simulation_violation_error::Violation::CalledBannedEntryPointMethod(
                            CalledBannedEntryPointMethod {
                                entity: Some((&entity).into()),
                            },
                        ),
                    ),
                }
            }
            SimulationViolation::CodeHashChanged => ProtoSimulationViolationError {
                violation: Some(simulation_violation_error::Violation::CodeHashChanged(
                    CodeHashChanged {},
                )),
            },
            SimulationViolation::InvalidTimeRange(valid_until, valid_after) => {
                ProtoSimulationViolationError {
                    violation: Some(simulation_violation_error::Violation::InvalidTimeRange(
                        InvalidTimeRange {
                            valid_until: valid_until.seconds_since_epoch(),
                            valud_after: valid_after.seconds_since_epoch(),
                        },
                    )),
                }
            }
            SimulationViolation::AggregatorValidationFailed => ProtoSimulationViolationError {
                violation: Some(
                    simulation_violation_error::Violation::AggregatorValidationFailed(
                        AggregatorValidationFailed {},
                    ),
                ),
            },
            SimulationViolation::VerificationGasLimitBufferTooLow(limit, needed) => {
                ProtoSimulationViolationError {
                    violation: Some(
                        simulation_violation_error::Violation::VerificationGasLimitBufferTooLow(
                            VerificationGasLimitBufferTooLow {
                                limit: limit.to_proto_bytes(),
                                needed: needed.to_proto_bytes(),
                            },
                        ),
                    ),
                }
            }
            SimulationViolation::AccessedUnsupportedContractType(contract_type, address) => {
                ProtoSimulationViolationError {
                    violation: Some(
                        simulation_violation_error::Violation::AccessedUnsupportedContractType(
                            AccessedUnsupportedContractType {
                                contract_type,
                                contract_address: address.to_proto_bytes(),
                            },
                        ),
                    ),
                }
            }
        }
    }
}

impl TryFrom<ProtoSimulationViolationError> for SimulationViolation {
    type Error = anyhow::Error;

    fn try_from(value: ProtoSimulationViolationError) -> Result<Self, Self::Error> {
        Ok(match value.violation {
            Some(simulation_violation_error::Violation::InvalidSignature(_)) => {
                SimulationViolation::InvalidSignature
            }
            Some(simulation_violation_error::Violation::InvalidTimeRange(e)) => {
                SimulationViolation::InvalidTimeRange(
                    Timestamp::new(e.valid_until),
                    Timestamp::new(e.valud_after),
                )
            }
            Some(simulation_violation_error::Violation::InvalidAccountSignature(_)) => {
                SimulationViolation::InvalidAccountSignature
            }
            Some(simulation_violation_error::Violation::InvalidPaymasterSignature(_)) => {
                SimulationViolation::InvalidPaymasterSignature
            }
            Some(simulation_violation_error::Violation::UnstakedPaymasterContext(_)) => {
                SimulationViolation::UnstakedPaymasterContext
            }
            Some(simulation_violation_error::Violation::UnintendedRevertWithMessage(e)) => {
                let entity = e.entity.context("should have entity in error")?;
                let addr = if entity.address.is_empty() {
                    None
                } else {
                    Some(from_bytes(&entity.address)?)
                };

                SimulationViolation::UnintendedRevertWithMessage(
                    rundler_types::EntityType::try_from(
                        EntityType::try_from(entity.kind).context("unknown entity type")?,
                    )?,
                    e.reason,
                    addr,
                )
            }
            Some(simulation_violation_error::Violation::UsedForbiddenOpcode(e)) => {
                SimulationViolation::UsedForbiddenOpcode(
                    (&e.entity.context("should have entity in error")?).try_into()?,
                    from_bytes(&e.contract_address)?,
                    ViolationOpCode(Opcode::try_from(e.opcode as u8)?),
                )
            }
            Some(simulation_violation_error::Violation::UsedForbiddenPrecompile(e)) => {
                SimulationViolation::UsedForbiddenPrecompile(
                    (&e.entity.context("should have entity in error")?).try_into()?,
                    from_bytes(&e.contract_address)?,
                    from_bytes(&e.precompile_address)?,
                )
            }
            Some(simulation_violation_error::Violation::FactoryCalledCreate2Twice(e)) => {
                SimulationViolation::FactoryCalledCreate2Twice(from_bytes(&e.factory_address)?)
            }
            Some(simulation_violation_error::Violation::AssociatedStorageDuringDeploy(e)) => {
                SimulationViolation::AssociatedStorageDuringDeploy(
                    e.entity.as_ref().map(|e| e.try_into()).transpose()?,
                    StorageSlot {
                        address: from_bytes(&e.contract_address)?,
                        slot: from_bytes(&e.slot)?,
                    },
                )
            }
            Some(simulation_violation_error::Violation::InvalidStorageAccess(e)) => {
                SimulationViolation::InvalidStorageAccess(
                    (&e.entity.context("should have entity in error")?).try_into()?,
                    StorageSlot {
                        address: from_bytes(&e.contract_address)?,
                        slot: from_bytes(&e.slot)?,
                    },
                )
            }
            Some(simulation_violation_error::Violation::NotStaked(e)) => {
                let accessing_entity = rundler_types::EntityType::try_from(
                    EntityType::try_from(e.accessing_entity).context("unknown entity type")?,
                )
                .context("invalid entity type")?;
                let accessed_entity = match rundler_types::EntityType::try_from(
                    EntityType::try_from(e.accessed_entity).context("unknown entity type")?,
                ) {
                    Ok(entity_type) => Some(entity_type),
                    Err(_) => None,
                };

                SimulationViolation::NotStaked(Box::new(NeedsStakeInformation {
                    needs_stake: (&e.needs_stake.context("should have entity in error")?)
                        .try_into()?,
                    accessing_entity,
                    accessed_address: from_bytes(&e.accessed_address)?,
                    accessed_entity,
                    slot: from_bytes(&e.slot)?,
                    min_stake: from_bytes(&e.min_stake)?,
                    min_unstake_delay: from_bytes(&e.min_unstake_delay)?,
                }))
            }
            Some(simulation_violation_error::Violation::UnintendedRevert(e)) => {
                let address = e.entity.clone().unwrap().address;
                SimulationViolation::UnintendedRevert(
                    rundler_types::EntityType::try_from(
                        EntityType::try_from(e.entity.unwrap().kind)
                            .context("unknown entity type")?,
                    )?,
                    if address.is_empty() {
                        None
                    } else {
                        Some(from_bytes(&address)?)
                    },
                )
            }
            Some(simulation_violation_error::Violation::ValidationRevert(e)) => {
                SimulationViolation::ValidationRevert(e.try_into()?)
            }
            Some(simulation_violation_error::Violation::DidNotRevert(_)) => {
                SimulationViolation::DidNotRevert
            }
            Some(simulation_violation_error::Violation::UnstakedAggregator(_)) => {
                SimulationViolation::UnstakedAggregator
            }
            Some(simulation_violation_error::Violation::WrongNumberOfPhases(e)) => {
                SimulationViolation::WrongNumberOfPhases(e.num_phases)
            }
            Some(simulation_violation_error::Violation::CallHadValue(e)) => {
                SimulationViolation::CallHadValue(
                    (&e.entity.context("should have entity in error")?).try_into()?,
                )
            }
            Some(simulation_violation_error::Violation::OutOfGas(e)) => {
                SimulationViolation::OutOfGas(
                    (&e.entity.context("should have entity in error")?).try_into()?,
                )
            }
            Some(simulation_violation_error::Violation::AccessedUndeployedContract(e)) => {
                SimulationViolation::AccessedUndeployedContract(
                    (&e.entity.context("should have entity in error")?).try_into()?,
                    from_bytes(&e.contract_address)?,
                )
            }
            Some(simulation_violation_error::Violation::CalledBannedEntryPointMethod(e)) => {
                SimulationViolation::CalledBannedEntryPointMethod(
                    (&e.entity.context("should have entity in error")?).try_into()?,
                )
            }
            Some(simulation_violation_error::Violation::CodeHashChanged(_)) => {
                SimulationViolation::CodeHashChanged
            }
            Some(simulation_violation_error::Violation::AggregatorValidationFailed(_)) => {
                SimulationViolation::AggregatorValidationFailed
            }
            Some(simulation_violation_error::Violation::VerificationGasLimitBufferTooLow(e)) => {
                SimulationViolation::VerificationGasLimitBufferTooLow(
                    from_bytes(&e.limit)?,
                    from_bytes(&e.needed)?,
                )
            }
            Some(simulation_violation_error::Violation::AccessedUnsupportedContractType(e)) => {
                SimulationViolation::AccessedUnsupportedContractType(
                    e.contract_type,
                    from_bytes(&e.contract_address)?,
                )
            }
            None => {
                bail!("unknown proto mempool simulation violation")
            }
        })
    }
}

impl From<ValidationRevert> for ProtoValidationRevert {
    fn from(revert: ValidationRevert) -> Self {
        let inner = match revert {
            ValidationRevert::EntryPoint(reason) => {
                validation_revert::Revert::EntryPoint(EntryPointRevert { reason })
            }
            ValidationRevert::Operation {
                entry_point_reason,
                inner_revert_data,
                inner_revert_reason,
            } => validation_revert::Revert::Operation(OperationRevert {
                entry_point_reason,
                inner_revert_data: inner_revert_data.to_vec(),
                inner_revert_reason: inner_revert_reason.unwrap_or_default(),
            }),
            ValidationRevert::Unknown(revert_bytes) => {
                validation_revert::Revert::Unknown(UnknownRevert {
                    revert_bytes: revert_bytes.to_vec(),
                })
            }
        };
        ProtoValidationRevert {
            revert: Some(inner),
        }
    }
}

impl TryFrom<ProtoValidationRevert> for ValidationRevert {
    type Error = anyhow::Error;

    fn try_from(value: ProtoValidationRevert) -> Result<Self, Self::Error> {
        Ok(match value.revert {
            Some(validation_revert::Revert::EntryPoint(e)) => {
                ValidationRevert::EntryPoint(e.reason)
            }
            Some(validation_revert::Revert::Operation(e)) => ValidationRevert::Operation {
                entry_point_reason: e.entry_point_reason,
                inner_revert_data: e.inner_revert_data.into(),
                inner_revert_reason: Some(e.inner_revert_reason).filter(|s| !s.is_empty()),
            },
            Some(validation_revert::Revert::Unknown(e)) => {
                ValidationRevert::Unknown(e.revert_bytes.into())
            }
            None => {
                bail!("unknown proto validation revert")
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_other_error() {
        let error = MempoolError::Other(anyhow::anyhow!("test error"));
        let proto_error: ProtoMempoolError = error.into();
        let error2 = proto_error.try_into().unwrap();
        match error2 {
            MempoolError::Other(e) => assert_eq!(e.to_string(), "test error"),
            _ => panic!("wrong error type"),
        }
    }

    #[test]
    fn test_precheck_error() {
        let error = MempoolError::PrecheckViolation(PrecheckViolation::SenderFundsTooLow(
            0.into(),
            0.into(),
        ));
        let proto_error: ProtoMempoolError = error.into();
        let error2 = proto_error.try_into().unwrap();
        match error2 {
            MempoolError::PrecheckViolation(PrecheckViolation::SenderFundsTooLow(x, y)) => {
                assert_eq!(x, 0.into());
                assert_eq!(y, 0.into());
            }
            _ => panic!("wrong error type"),
        }
    }

    #[test]
    fn test_simulation_error() {
        let error = MempoolError::SimulationViolation(SimulationViolation::UnintendedRevert(
            rundler_types::EntityType::Aggregator,
            None,
        ));
        let proto_error: ProtoMempoolError = error.into();
        let error2 = proto_error.try_into().unwrap();
        match error2 {
            MempoolError::SimulationViolation(SimulationViolation::UnintendedRevert(
                rundler_types::EntityType::Aggregator,
                None,
            )) => {}
            _ => panic!("wrong error type"),
        }
    }

    #[test]
    fn test_invalid_convert() {
        let error = ProtoMempoolError { error: None };
        let error2 = std::convert::TryInto::<MempoolError>::try_into(error);
        assert!(error2.is_err());
    }
}
