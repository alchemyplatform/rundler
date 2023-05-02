use ethers::types::{Address, H256, U256};

use crate::common::types::{
    BundlingMode as RpcBundlingMode, Entity as CommonEntity, EntityType as CommonEntityType,
    UserOperation as RpcUserOperation,
};

pub mod op_pool {
    use super::*;

    tonic::include_proto!("op_pool");

    pub const OP_POOL_FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("op_pool_descriptor");

    impl From<&RpcUserOperation> for UserOperation {
        fn from(op: &RpcUserOperation) -> Self {
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

    impl TryFrom<UserOperation> for RpcUserOperation {
        type Error = ConversionError;

        fn try_from(op: UserOperation) -> Result<Self, Self::Error> {
            Ok(RpcUserOperation {
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
                EntityType::Unspecified => Err(ConversionError::InvalidEntity(entity as i32)),
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
                    .ok_or(ConversionError::InvalidEntity(entity.kind))?
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
}

pub mod builder {
    use super::*;

    tonic::include_proto!("builder");

    pub const BUILDER_FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("builder_descriptor");

    impl From<RpcBundlingMode> for BundlingMode {
        fn from(mode: RpcBundlingMode) -> Self {
            match mode {
                RpcBundlingMode::Auto => BundlingMode::Auto,
                RpcBundlingMode::Manual => BundlingMode::Manual,
            }
        }
    }

    impl TryFrom<BundlingMode> for RpcBundlingMode {
        type Error = ConversionError;

        fn try_from(value: BundlingMode) -> Result<Self, Self::Error> {
            match value {
                BundlingMode::Auto => Ok(RpcBundlingMode::Auto),
                BundlingMode::Manual => Ok(RpcBundlingMode::Manual),
                _ => Err(ConversionError::InvalidBundlingMode(value as i32)),
            }
        }
    }
}

pub fn to_le_bytes(n: U256) -> Vec<u8> {
    let mut vec = vec![0_u8; 32];
    n.to_little_endian(&mut vec);
    vec
}

/// Error type for conversions from protobuf types to Ethers/local types.
#[derive(Debug, thiserror::Error)]
pub enum ConversionError {
    #[error("Invalid length: {0}, expected: {1}")]
    InvalidLength(usize, usize),
    #[error("Invalid timestamp: {0}")]
    InvalidTimestamp(u64),
    #[error("Entity was invalid or unspecified: {0}")]
    InvalidEntity(i32),
    #[error("Bundling Mode was invalid or unspecified: {0}")]
    InvalidBundlingMode(i32),
}

pub fn from_bytes<T: FromProtoBytes>(bytes: &[u8]) -> Result<T, ConversionError> {
    T::from_proto_bytes(bytes)
}

pub trait FromProtoBytes: Sized {
    fn from_proto_bytes(bytes: &[u8]) -> Result<Self, ConversionError>;
}

pub trait FromFixedLengthProtoBytes: Sized {
    const LEN: usize;

    fn from_fixed_length_bytes(bytes: &[u8]) -> Self;
}

impl<T: FromFixedLengthProtoBytes> FromProtoBytes for T {
    fn from_proto_bytes(bytes: &[u8]) -> Result<Self, ConversionError> {
        let len = bytes.len();
        if len != Self::LEN {
            Err(ConversionError::InvalidLength(len, Self::LEN))
        } else {
            Ok(Self::from_fixed_length_bytes(bytes))
        }
    }
}

impl FromFixedLengthProtoBytes for Address {
    const LEN: usize = 20;

    fn from_fixed_length_bytes(bytes: &[u8]) -> Self {
        Self::from_slice(bytes)
    }
}

impl FromFixedLengthProtoBytes for U256 {
    const LEN: usize = 32;

    fn from_fixed_length_bytes(bytes: &[u8]) -> Self {
        Self::from_little_endian(bytes)
    }
}

impl FromFixedLengthProtoBytes for H256 {
    const LEN: usize = 32;

    fn from_fixed_length_bytes(bytes: &[u8]) -> Self {
        Self::from_slice(bytes)
    }
}
