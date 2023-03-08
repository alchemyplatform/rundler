use crate::common::types::UserOperation as RpcUserOperation;
use chrono::{DateTime, LocalResult, TimeZone, Utc};
use ethers::types::{Address, Bytes, H256, U256};
use std::mem;

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

        fn try_from(mut op: UserOperation) -> Result<Self, Self::Error> {
            Ok(RpcUserOperation {
                sender: ProtoBytes(&op.sender).try_into()?,
                nonce: ProtoBytes(&op.nonce).try_into()?,
                init_code: Bytes::from(mem::take(&mut op.init_code)),
                call_data: Bytes::from(mem::take(&mut op.call_data)),
                call_gas_limit: ProtoBytes(&op.call_gas_limit).try_into()?,
                verification_gas_limit: ProtoBytes(&op.verification_gas_limit).try_into()?,
                pre_verification_gas: ProtoBytes(&op.pre_verification_gas).try_into()?,
                max_fee_per_gas: ProtoBytes(&op.max_fee_per_gas).try_into()?,
                max_priority_fee_per_gas: ProtoBytes(&op.max_priority_fee_per_gas).try_into()?,
                paymaster_and_data: Bytes::from(mem::take(&mut op.paymaster_and_data)),
                signature: Bytes::from(mem::take(&mut op.signature)),
            })
        }
    }
}

pub fn to_le_bytes(n: U256) -> Vec<u8> {
    let mut vec = vec![0_u8; 32];
    n.to_little_endian(&mut vec);
    vec
}

/// Error type for conversions from protobuf types to Ethers types.
#[derive(Debug, thiserror::Error)]
pub enum ConversionError {
    #[error("Invalid length: {0}, expected: {1}")]
    InvalidLength(usize, usize),
    #[error("Invalid timestamp: {0}")]
    InvalidTimestamp(u64),
}

/// Wrapper around protobyf bytes for converting to Ethers types.
#[derive(Debug, Copy, Clone)]
pub struct ProtoBytes<'a>(pub &'a [u8]);

impl TryInto<Address> for ProtoBytes<'_> {
    type Error = ConversionError;

    fn try_into(self) -> Result<Address, Self::Error> {
        let len = self.0.len();
        if len != 20 {
            Err(ConversionError::InvalidLength(len, 20))
        } else {
            Ok(Address::from_slice(self.0))
        }
    }
}

impl TryInto<U256> for ProtoBytes<'_> {
    type Error = ConversionError;

    fn try_into(self) -> Result<U256, Self::Error> {
        let len = self.0.len();
        if len != 32 {
            Err(ConversionError::InvalidLength(len, 32))
        } else {
            Ok(U256::from_little_endian(self.0))
        }
    }
}

impl TryInto<H256> for ProtoBytes<'_> {
    type Error = ConversionError;

    fn try_into(self) -> Result<H256, Self::Error> {
        let len = self.0.len();
        if len != 32 {
            Err(ConversionError::InvalidLength(len, 32))
        } else {
            Ok(H256::from_slice(self.0))
        }
    }
}

/// Wrapper around protobyf u64 timestamps for converting to chrono types.
#[derive(Debug, Copy, Clone)]
pub struct ProtoTimestampMillis(pub u64);

impl TryInto<DateTime<Utc>> for ProtoTimestampMillis {
    type Error = ConversionError;

    fn try_into(self) -> Result<DateTime<Utc>, Self::Error> {
        match Utc.timestamp_millis_opt(
            self.0
                .try_into()
                .map_err(|_| ConversionError::InvalidTimestamp(self.0))?,
        ) {
            LocalResult::Single(t) => Ok(t),
            _ => Err(ConversionError::InvalidTimestamp(self.0)),
        }
    }
}
