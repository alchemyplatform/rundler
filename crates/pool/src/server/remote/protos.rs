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

use anyhow::Context;
use ethers::types::{Address, H256};
use rundler_task::grpc::protos::{from_bytes, to_le_bytes, ConversionError};
use rundler_types::{
    Entity as RundlerEntity, EntityType as RundlerEntityType,
    UserOperation as RundlerUserOperation, ValidTimeRange,
};

use crate::{
    mempool::{
        PoolOperation, Reputation as PoolReputation, ReputationStatus as PoolReputationStatus,
    },
    server::NewHead as PoolNewHead,
};

tonic::include_proto!("op_pool");

pub const OP_POOL_FILE_DESCRIPTOR_SET: &[u8] =
    tonic::include_file_descriptor_set!("op_pool_descriptor");

impl From<&RundlerUserOperation> for UserOperation {
    fn from(op: &RundlerUserOperation) -> Self {
        UserOperation {
            sender: op.sender.0.to_vec(),
            nonce: to_le_bytes(op.nonce),
            init_code: op.init_code.to_vec(),
            call_data: op.call_data.to_vec(),
            call_gas_limit: to_le_bytes(op.call_gas_limit),
            verification_gas_limit: to_le_bytes(op.verification_gas_limit),
            pre_verification_gas: to_le_bytes(op.pre_verification_gas),
            max_fee_per_gas: to_le_bytes(op.max_fee_per_gas),
            max_priority_fee_per_gas: to_le_bytes(op.max_priority_fee_per_gas),
            paymaster_and_data: op.paymaster_and_data.to_vec(),
            signature: op.signature.to_vec(),
        }
    }
}

impl TryFrom<UserOperation> for RundlerUserOperation {
    type Error = ConversionError;

    fn try_from(op: UserOperation) -> Result<Self, Self::Error> {
        Ok(RundlerUserOperation {
            sender: from_bytes(&op.sender)?,
            nonce: from_bytes(&op.nonce)?,
            init_code: op.init_code.into(),
            call_data: op.call_data.into(),
            call_gas_limit: from_bytes(&op.call_gas_limit)?,
            verification_gas_limit: from_bytes(&op.verification_gas_limit)?,
            pre_verification_gas: from_bytes(&op.pre_verification_gas)?,
            max_fee_per_gas: from_bytes(&op.max_fee_per_gas)?,
            max_priority_fee_per_gas: from_bytes(&op.max_priority_fee_per_gas)?,
            paymaster_and_data: op.paymaster_and_data.into(),
            signature: op.signature.into(),
        })
    }
}

impl TryFrom<EntityType> for RundlerEntityType {
    type Error = ConversionError;

    fn try_from(entity: EntityType) -> Result<Self, Self::Error> {
        match entity {
            EntityType::Unspecified => Err(ConversionError::InvalidEnumValue(entity as i32)),
            EntityType::Account => Ok(RundlerEntityType::Account),
            EntityType::Paymaster => Ok(RundlerEntityType::Paymaster),
            EntityType::Aggregator => Ok(RundlerEntityType::Aggregator),
            EntityType::Factory => Ok(RundlerEntityType::Factory),
        }
    }
}

impl From<RundlerEntityType> for EntityType {
    fn from(entity: RundlerEntityType) -> Self {
        match entity {
            RundlerEntityType::Account => EntityType::Account,
            RundlerEntityType::Paymaster => EntityType::Paymaster,
            RundlerEntityType::Aggregator => EntityType::Aggregator,
            RundlerEntityType::Factory => EntityType::Factory,
        }
    }
}

impl TryFrom<&Entity> for RundlerEntity {
    type Error = ConversionError;

    fn try_from(entity: &Entity) -> Result<Self, ConversionError> {
        Ok(RundlerEntity {
            kind: EntityType::try_from(entity.kind)
                .map_err(|_| ConversionError::InvalidEnumValue(entity.kind))?
                .try_into()?,
            address: from_bytes(&entity.address)?,
        })
    }
}

impl From<&RundlerEntity> for Entity {
    fn from(entity: &RundlerEntity) -> Self {
        Entity {
            kind: EntityType::from(entity.kind).into(),
            address: entity.address.as_bytes().to_vec(),
        }
    }
}

impl From<PoolReputationStatus> for ReputationStatus {
    fn from(status: PoolReputationStatus) -> Self {
        match status {
            PoolReputationStatus::Ok => ReputationStatus::Ok,
            PoolReputationStatus::Throttled => ReputationStatus::Throttled,
            PoolReputationStatus::Banned => ReputationStatus::Banned,
        }
    }
}

impl From<PoolReputation> for Reputation {
    fn from(rep: PoolReputation) -> Self {
        Reputation {
            address: rep.address.as_bytes().to_vec(),
            status: ReputationStatus::from(rep.status).into(),
            ops_seen: rep.ops_seen,
            ops_included: rep.ops_included,
        }
    }
}

impl TryFrom<i32> for PoolReputationStatus {
    type Error = ConversionError;

    fn try_from(status: i32) -> Result<Self, Self::Error> {
        match status {
            x if x == ReputationStatus::Ok as i32 => Ok(Self::Ok),
            x if x == ReputationStatus::Throttled as i32 => Ok(Self::Throttled),
            x if x == ReputationStatus::Banned as i32 => Ok(Self::Banned),
            _ => Err(ConversionError::InvalidEnumValue(status)),
        }
    }
}

impl TryFrom<Reputation> for PoolReputation {
    type Error = ConversionError;

    fn try_from(op: Reputation) -> Result<Self, Self::Error> {
        Ok(Self {
            address: from_bytes(&op.address)?,
            status: PoolReputationStatus::try_from(op.status)?,
            ops_seen: op.ops_seen,
            ops_included: op.ops_included,
        })
    }
}

impl From<&PoolOperation> for MempoolOp {
    fn from(op: &PoolOperation) -> Self {
        MempoolOp {
            uo: Some(UserOperation::from(&op.uo)),
            aggregator: op.aggregator.map_or(vec![], |a| a.as_bytes().to_vec()),
            valid_after: op.valid_time_range.valid_after.seconds_since_epoch(),
            valid_until: op.valid_time_range.valid_until.seconds_since_epoch(),
            expected_code_hash: op.expected_code_hash.as_bytes().to_vec(),
            sim_block_hash: op.sim_block_hash.as_bytes().to_vec(),
            entities_needing_stake: op
                .entities_needing_stake
                .iter()
                .map(|e| EntityType::from(*e).into())
                .collect(),
            account_is_staked: op.account_is_staked,
        }
    }
}

pub const MISSING_USER_OP_ERR_STR: &str = "Mempool op should contain user operation";
impl TryFrom<MempoolOp> for PoolOperation {
    type Error = anyhow::Error;

    fn try_from(op: MempoolOp) -> Result<Self, Self::Error> {
        let uo = op.uo.context(MISSING_USER_OP_ERR_STR)?.try_into()?;

        let aggregator: Option<Address> = if op.aggregator.is_empty() {
            None
        } else {
            Some(from_bytes(&op.aggregator)?)
        };

        let valid_time_range = ValidTimeRange::new(op.valid_after.into(), op.valid_until.into());

        let expected_code_hash = H256::from_slice(&op.expected_code_hash);
        let sim_block_hash = H256::from_slice(&op.sim_block_hash);
        let entities_needing_stake = op
            .entities_needing_stake
            .into_iter()
            .map(|e| {
                let pe =
                    EntityType::try_from(e).map_err(|_| ConversionError::InvalidEnumValue(e))?;
                pe.try_into()
            })
            .collect::<Result<Vec<_>, ConversionError>>()?;

        Ok(PoolOperation {
            uo,
            aggregator,
            valid_time_range,
            expected_code_hash,
            entities_needing_stake,
            sim_block_hash,
            account_is_staked: op.account_is_staked,
        })
    }
}

impl TryFrom<NewHead> for PoolNewHead {
    type Error = ConversionError;

    fn try_from(new_head: NewHead) -> Result<Self, Self::Error> {
        Ok(Self {
            block_hash: from_bytes(&new_head.block_hash)?,
            block_number: new_head.block_number,
        })
    }
}

impl From<PoolNewHead> for NewHead {
    fn from(head: PoolNewHead) -> Self {
        Self {
            block_hash: head.block_hash.as_bytes().to_vec(),
            block_number: head.block_number,
        }
    }
}
