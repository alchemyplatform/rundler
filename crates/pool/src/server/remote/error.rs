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
use ethers::types::Opcode;
use rundler_sim::{PrecheckViolation, SimulationViolation, ViolationOpCode};
use rundler_task::grpc::protos::{from_bytes, to_le_bytes, ConversionError};
use rundler_types::StorageSlot;

use super::protos::{
    mempool_error, precheck_violation_error, simulation_violation_error,
    AccessedUndeployedContract, AggregatorValidationFailed, CallGasLimitTooLow, CallHadValue,
    CalledBannedEntryPointMethod, CodeHashChanged, DidNotRevert, DiscardedOnInsertError, Entity,
    EntityThrottledError, EntityType, ExistingSenderWithInitCode, FactoryCalledCreate2Twice,
    FactoryIsNotContract, InitCodeTooShort, InvalidSignature, InvalidStorageAccess,
    MaxFeePerGasTooLow, MaxOperationsReachedError, MaxPriorityFeePerGasTooLow,
    MempoolError as ProtoMempoolError, NotStaked, OperationAlreadyKnownError, OutOfGas,
    PaymasterDepositTooLow, PaymasterIsNotContract, PaymasterTooShort, PreVerificationGasTooLow,
    PrecheckViolationError as ProtoPrecheckViolationError, ReplacementUnderpricedError,
    SenderFundsTooLow, SenderIsNotContractAndNoInitCode,
    SimulationViolationError as ProtoSimulationViolationError, TotalGasLimitTooHigh,
    UnintendedRevert, UnintendedRevertWithMessage, UnknownEntryPointError,
    UnsupportedAggregatorError, UsedForbiddenOpcode, UsedForbiddenPrecompile,
    VerificationGasLimitTooHigh, WrongNumberOfPhases,
};
use crate::{mempool::MempoolError, server::error::PoolServerError};

impl From<tonic::Status> for PoolServerError {
    fn from(value: tonic::Status) -> Self {
        PoolServerError::Other(anyhow::anyhow!(value.to_string()))
    }
}

impl From<ConversionError> for PoolServerError {
    fn from(value: ConversionError) -> Self {
        PoolServerError::Other(anyhow::anyhow!(value.to_string()))
    }
}

impl TryFrom<ProtoMempoolError> for PoolServerError {
    type Error = anyhow::Error;

    fn try_from(value: ProtoMempoolError) -> Result<Self, Self::Error> {
        Ok(PoolServerError::MempoolError(value.try_into()?))
    }
}

impl From<PoolServerError> for ProtoMempoolError {
    fn from(value: PoolServerError) -> Self {
        match value {
            PoolServerError::MempoolError(e) => e.into(),
            PoolServerError::UnexpectedResponse => ProtoMempoolError {
                error: Some(mempool_error::Error::Internal(
                    "unexpected response from pool server".to_string(),
                )),
            },
            PoolServerError::Other(e) => ProtoMempoolError {
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
                    from_bytes(&e.sender_address)?,
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
            _ => bail!("unknown proto mempool error"),
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
            MempoolError::ReplacementUnderpriced(fee, priority_fee) => ProtoMempoolError {
                error: Some(mempool_error::Error::ReplacementUnderpriced(
                    ReplacementUnderpricedError {
                        current_fee: to_le_bytes(fee),
                        current_priority_fee: to_le_bytes(priority_fee),
                    },
                )),
            },
            MempoolError::MaxOperationsReached(ops, addr) => ProtoMempoolError {
                error: Some(mempool_error::Error::MaxOperationsReached(
                    MaxOperationsReachedError {
                        num_ops: ops as u64,
                        sender_address: addr.as_bytes().to_vec(),
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
            MempoolError::PrecheckViolation(violation) => ProtoMempoolError {
                error: Some(mempool_error::Error::PrecheckViolation(violation.into())),
            },
            MempoolError::SimulationViolation(violation) => ProtoMempoolError {
                error: Some(mempool_error::Error::SimulationViolation(violation.into())),
            },
            MempoolError::UnsupportedAggregator(agg) => ProtoMempoolError {
                error: Some(mempool_error::Error::UnsupportedAggregator(
                    UnsupportedAggregatorError {
                        aggregator_address: agg.as_bytes().to_vec(),
                    },
                )),
            },
            MempoolError::UnknownEntryPoint(entry_point) => ProtoMempoolError {
                error: Some(mempool_error::Error::UnknownEntryPoint(
                    UnknownEntryPointError {
                        entry_point: entry_point.as_bytes().to_vec(),
                    },
                )),
            },
        }
    }
}

impl From<PrecheckViolation> for ProtoPrecheckViolationError {
    fn from(value: PrecheckViolation) -> Self {
        match value {
            PrecheckViolation::InitCodeTooShort(length) => ProtoPrecheckViolationError {
                violation: Some(precheck_violation_error::Violation::InitCodeTooShort(
                    InitCodeTooShort {
                        length: length as u64,
                    },
                )),
            },
            PrecheckViolation::SenderIsNotContractAndNoInitCode(addr) => {
                ProtoPrecheckViolationError {
                    violation: Some(
                        precheck_violation_error::Violation::SenderIsNotContractAndNoInitCode(
                            SenderIsNotContractAndNoInitCode {
                                sender_address: addr.as_bytes().to_vec(),
                            },
                        ),
                    ),
                }
            }
            PrecheckViolation::ExistingSenderWithInitCode(addr) => ProtoPrecheckViolationError {
                violation: Some(
                    precheck_violation_error::Violation::ExistingSenderWithInitCode(
                        ExistingSenderWithInitCode {
                            sender_address: addr.as_bytes().to_vec(),
                        },
                    ),
                ),
            },
            PrecheckViolation::FactoryIsNotContract(addr) => ProtoPrecheckViolationError {
                violation: Some(precheck_violation_error::Violation::FactoryIsNotContract(
                    FactoryIsNotContract {
                        factory_address: addr.as_bytes().to_vec(),
                    },
                )),
            },
            PrecheckViolation::TotalGasLimitTooHigh(actual, max) => ProtoPrecheckViolationError {
                violation: Some(precheck_violation_error::Violation::TotalGasLimitTooHigh(
                    TotalGasLimitTooHigh {
                        actual_gas: to_le_bytes(actual),
                        max_gas: to_le_bytes(max),
                    },
                )),
            },
            PrecheckViolation::VerificationGasLimitTooHigh(actual, max) => {
                ProtoPrecheckViolationError {
                    violation: Some(
                        precheck_violation_error::Violation::VerificationGasLimitTooHigh(
                            VerificationGasLimitTooHigh {
                                actual_gas: to_le_bytes(actual),
                                max_gas: to_le_bytes(max),
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
                                actual_gas: to_le_bytes(actual),
                                min_gas: to_le_bytes(min),
                            },
                        ),
                    ),
                }
            }
            PrecheckViolation::PaymasterTooShort(length) => ProtoPrecheckViolationError {
                violation: Some(precheck_violation_error::Violation::PaymasterTooShort(
                    PaymasterTooShort {
                        length: length as u64,
                    },
                )),
            },
            PrecheckViolation::PaymasterIsNotContract(addr) => ProtoPrecheckViolationError {
                violation: Some(precheck_violation_error::Violation::PaymasterIsNotContract(
                    PaymasterIsNotContract {
                        paymaster_address: addr.as_bytes().to_vec(),
                    },
                )),
            },
            PrecheckViolation::PaymasterDepositTooLow(actual, min) => ProtoPrecheckViolationError {
                violation: Some(precheck_violation_error::Violation::PaymasterDepositTooLow(
                    PaymasterDepositTooLow {
                        actual_deposit: to_le_bytes(actual),
                        min_deposit: to_le_bytes(min),
                    },
                )),
            },
            PrecheckViolation::SenderFundsTooLow(actual, min) => ProtoPrecheckViolationError {
                violation: Some(precheck_violation_error::Violation::SenderFundsTooLow(
                    SenderFundsTooLow {
                        actual_funds: to_le_bytes(actual),
                        min_funds: to_le_bytes(min),
                    },
                )),
            },
            PrecheckViolation::MaxFeePerGasTooLow(actual, min) => ProtoPrecheckViolationError {
                violation: Some(precheck_violation_error::Violation::MaxFeePerGasTooLow(
                    MaxFeePerGasTooLow {
                        actual_fee: to_le_bytes(actual),
                        min_fee: to_le_bytes(min),
                    },
                )),
            },
            PrecheckViolation::MaxPriorityFeePerGasTooLow(actual, min) => {
                ProtoPrecheckViolationError {
                    violation: Some(
                        precheck_violation_error::Violation::MaxPriorityFeePerGasTooLow(
                            MaxPriorityFeePerGasTooLow {
                                actual_fee: to_le_bytes(actual),
                                min_fee: to_le_bytes(min),
                            },
                        ),
                    ),
                }
            }
            PrecheckViolation::CallGasLimitTooLow(actual, min) => ProtoPrecheckViolationError {
                violation: Some(precheck_violation_error::Violation::CallGasLimitTooLow(
                    CallGasLimitTooLow {
                        actual_gas_limit: to_le_bytes(actual),
                        min_gas_limit: to_le_bytes(min),
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
            Some(precheck_violation_error::Violation::InitCodeTooShort(e)) => {
                PrecheckViolation::InitCodeTooShort(e.length as usize)
            }
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
            Some(precheck_violation_error::Violation::PaymasterTooShort(e)) => {
                PrecheckViolation::PaymasterTooShort(e.length as usize)
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
            SimulationViolation::UnintendedRevertWithMessage(et, reason, maybe_address) => {
                ProtoSimulationViolationError {
                    violation: Some(
                        simulation_violation_error::Violation::UnintendedRevertWithMessage(
                            UnintendedRevertWithMessage {
                                entity: Some(Entity {
                                    kind: EntityType::from(et) as i32,
                                    address: maybe_address
                                        .map_or(vec![], |addr| addr.as_bytes().to_vec()),
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
                            contract_address: addr.as_bytes().to_vec(),
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
                            contract_address: contract_addr.as_bytes().to_vec(),
                            precompile_address: precompile_addr.as_bytes().to_vec(),
                        },
                    ),
                ),
            },
            SimulationViolation::FactoryCalledCreate2Twice(addr) => ProtoSimulationViolationError {
                violation: Some(
                    simulation_violation_error::Violation::FactoryCalledCreate2Twice(
                        FactoryCalledCreate2Twice {
                            factory_address: addr.as_bytes().to_vec(),
                        },
                    ),
                ),
            },
            SimulationViolation::InvalidStorageAccess(entity, slot) => {
                ProtoSimulationViolationError {
                    violation: Some(simulation_violation_error::Violation::InvalidStorageAccess(
                        InvalidStorageAccess {
                            entity: Some((&entity).into()),
                            contract_address: slot.address.as_bytes().to_vec(),
                            slot: to_le_bytes(slot.slot),
                        },
                    )),
                }
            }
            SimulationViolation::NotStaked(entity, min_stake, min_unstake_delay) => {
                ProtoSimulationViolationError {
                    violation: Some(simulation_violation_error::Violation::NotStaked(
                        NotStaked {
                            entity: Some((&entity).into()),
                            min_stake: to_le_bytes(min_stake),
                            min_unstake_delay: to_le_bytes(min_unstake_delay),
                        },
                    )),
                }
            }
            SimulationViolation::UnintendedRevert(et, maybe_address) => ProtoSimulationViolationError {
                violation: Some(simulation_violation_error::Violation::UnintendedRevert(
                    UnintendedRevert {
                        entity: Some(Entity {
                            kind: EntityType::from(et) as i32,
                            address: maybe_address
                                .map_or(vec![], |addr| addr.as_bytes().to_vec()),
                        }),
                    },
                )),
            },
            SimulationViolation::DidNotRevert => ProtoSimulationViolationError {
                violation: Some(simulation_violation_error::Violation::DidNotRevert(
                    DidNotRevert {},
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
                                contract_address: contract_addr.as_bytes().to_vec(),
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
            SimulationViolation::AggregatorValidationFailed => ProtoSimulationViolationError {
                violation: Some(
                    simulation_violation_error::Violation::AggregatorValidationFailed(
                        AggregatorValidationFailed {},
                    ),
                ),
            },
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
                SimulationViolation::NotStaked(
                    (&e.entity.context("should have entity in error")?).try_into()?,
                    from_bytes(&e.min_stake)?,
                    from_bytes(&e.min_unstake_delay)?,
                )
            }
            Some(simulation_violation_error::Violation::UnintendedRevert(e)) => {
                SimulationViolation::UnintendedRevert(
                    rundler_types::EntityType::try_from(
                        EntityType::try_from(e.entity.clone().unwrap().kind).context("unknown entity type")?,
                    )?, 
                    Some(from_bytes(&e.entity.unwrap().address)?)
                )
            }
            Some(simulation_violation_error::Violation::DidNotRevert(_)) => {
                SimulationViolation::DidNotRevert
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
            None => {
                bail!("unknown proto mempool simulation violation")
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
        let error = MempoolError::PrecheckViolation(PrecheckViolation::InitCodeTooShort(0));
        let proto_error: ProtoMempoolError = error.into();
        let error2 = proto_error.try_into().unwrap();
        match error2 {
            MempoolError::PrecheckViolation(PrecheckViolation::InitCodeTooShort(v)) => {
                assert_eq!(v, 0)
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
