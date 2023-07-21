use ethers::types::{Address, H256, U256};

use crate::common::types::BundlingMode as RpcBundlingMode;

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
                _ => Err(ConversionError::InvalidEnumValue(value as i32)),
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
    #[error("Invalid enum value {0}")]
    InvalidEnumValue(i32),
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
