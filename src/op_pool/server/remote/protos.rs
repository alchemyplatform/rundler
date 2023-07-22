use anyhow::Context;
use ethers::types::{Address, H256};

use crate::{
    common::{
        protos::{from_bytes, to_le_bytes, ConversionError},
        types::{
            Entity as CommonEntity, EntityType as CommonEntityType,
            UserOperation as PoolUserOperation, ValidTimeRange,
        },
    },
    op_pool::{
        mempool::{Reputation as PoolReputation, ReputationStatus as PoolReputationStatus},
        NewHead as PoolNewHead, PoolOperation,
    },
};

tonic::include_proto!("op_pool");

pub const OP_POOL_FILE_DESCRIPTOR_SET: &[u8] =
    tonic::include_file_descriptor_set!("op_pool_descriptor");

impl From<&PoolUserOperation> for UserOperation {
    fn from(op: &PoolUserOperation) -> Self {
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

impl TryFrom<UserOperation> for PoolUserOperation {
    type Error = ConversionError;

    fn try_from(op: UserOperation) -> Result<Self, Self::Error> {
        Ok(PoolUserOperation {
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

impl TryFrom<EntityType> for CommonEntityType {
    type Error = ConversionError;

    fn try_from(entity: EntityType) -> Result<Self, Self::Error> {
        match entity {
            EntityType::Unspecified => Err(ConversionError::InvalidEnumValue(entity as i32)),
            EntityType::Account => Ok(CommonEntityType::Account),
            EntityType::Paymaster => Ok(CommonEntityType::Paymaster),
            EntityType::Aggregator => Ok(CommonEntityType::Aggregator),
            EntityType::Factory => Ok(CommonEntityType::Factory),
        }
    }
}

impl From<CommonEntityType> for EntityType {
    fn from(entity: CommonEntityType) -> Self {
        match entity {
            CommonEntityType::Account => EntityType::Account,
            CommonEntityType::Paymaster => EntityType::Paymaster,
            CommonEntityType::Aggregator => EntityType::Aggregator,
            CommonEntityType::Factory => EntityType::Factory,
        }
    }
}

impl TryFrom<&Entity> for CommonEntity {
    type Error = ConversionError;

    fn try_from(entity: &Entity) -> Result<Self, ConversionError> {
        Ok(CommonEntity {
            kind: EntityType::from_i32(entity.kind)
                .ok_or(ConversionError::InvalidEnumValue(entity.kind))?
                .try_into()?,
            address: from_bytes(&entity.address)?,
        })
    }
}

impl From<&CommonEntity> for Entity {
    fn from(entity: &CommonEntity) -> Self {
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
                let pe = EntityType::from_i32(e).ok_or(ConversionError::InvalidEnumValue(e))?;
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
