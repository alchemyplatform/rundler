//! Protobuf utilities

use ethers::types::{Address, H256, U256};

/// Error type for conversions from protobuf types to Ethers/local types.
#[derive(Debug, thiserror::Error)]
pub enum ConversionError {
    /// Invalid length of a variable length proto field
    #[error("Invalid length: {0}, expected: {1}")]
    InvalidLength(usize, usize),
    /// Invalid timestamp value, does not represent a valid time
    #[error("Invalid timestamp: {0}")]
    InvalidTimestamp(u64),
    /// Invalid enum value, does not map to a valid enum variant
    #[error("Invalid enum value {0}")]
    InvalidEnumValue(i32),
}

/// Convert an Ethers U256 to little endian bytes for packing into a proto struct.
pub fn to_le_bytes(n: U256) -> Vec<u8> {
    let mut vec = vec![0_u8; 32];
    n.to_little_endian(&mut vec);
    vec
}

/// Convert proto bytes into a type that implements `FromProtoBytes`.
///
/// Returns a `ConversionError` if the bytes could not be converted.
pub fn from_bytes<T: FromProtoBytes>(bytes: &[u8]) -> Result<T, ConversionError> {
    T::from_proto_bytes(bytes)
}

/// Trait for a type that can be converted from protobuf bytes.
pub trait FromProtoBytes: Sized {
    /// Convert from protobuf bytes.
    ///
    /// Returns a `ConversionError` if the bytes could not be converted.
    fn from_proto_bytes(bytes: &[u8]) -> Result<Self, ConversionError>;
}

/// Trait for a type that can be converted from fixed length protobuf bytes.
pub trait FromFixedLengthProtoBytes: Sized {
    /// Length of the fixed length bytes. If the bytes are this length they can be converted.
    const LEN: usize;

    /// Convert from fixed length protobuf bytes.
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
