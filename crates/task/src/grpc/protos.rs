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

//! Protobuf utilities

use ethers::types::{Address, Bytes, H256, U128, U256};

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
    /// Other error
    #[error(transparent)]
    Other(#[from] anyhow::Error),
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

impl FromFixedLengthProtoBytes for U128 {
    const LEN: usize = 16;

    fn from_fixed_length_bytes(bytes: &[u8]) -> Self {
        Self::from_little_endian(bytes)
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

/// Trait for a type that can be converted to protobuf bytes.
pub trait ToProtoBytes {
    /// Convert to protobuf bytes.
    fn to_proto_bytes(&self) -> Vec<u8>;
}

impl ToProtoBytes for Address {
    fn to_proto_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl ToProtoBytes for U128 {
    fn to_proto_bytes(&self) -> Vec<u8> {
        let mut vec = vec![0_u8; 16];
        self.to_little_endian(&mut vec);
        vec
    }
}

impl ToProtoBytes for U256 {
    fn to_proto_bytes(&self) -> Vec<u8> {
        let mut vec = vec![0_u8; 32];
        self.to_little_endian(&mut vec);
        vec
    }
}

impl ToProtoBytes for H256 {
    fn to_proto_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl ToProtoBytes for Bytes {
    fn to_proto_bytes(&self) -> Vec<u8> {
        self.to_vec()
    }
}
