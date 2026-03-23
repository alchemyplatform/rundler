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

use alloy_eips::eip7702::{Authorization, SignedAuthorization};
use alloy_primitives::U256;
use rundler_task::grpc::protos::{ConversionError, ToProtoBytes, from_bytes};
use rundler_types::{authorization::Eip7702Auth, builder::BundlingMode as RpcBundlingMode};

tonic::include_proto!("builder");

pub const BUILDER_FILE_DESCRIPTOR_SET: &[u8] =
    tonic::include_file_descriptor_set!("builder_descriptor");

impl From<RpcBundlingMode> for BundlingMode {
    fn from(mode: RpcBundlingMode) -> Self {
        match mode {
            RpcBundlingMode::Auto => Self::Auto,
            RpcBundlingMode::Manual => Self::Manual,
        }
    }
}

impl From<AuthorizationTuple> for Eip7702Auth {
    fn from(value: AuthorizationTuple) -> Self {
        SignedAuthorization::new_unchecked(
            Authorization {
                chain_id: U256::from(value.chain_id),
                address: from_bytes(&value.address).unwrap_or_default(),
                nonce: value.nonce,
            },
            value.y_parity as u8,
            from_bytes(&value.r).unwrap_or_default(),
            from_bytes(&value.s).unwrap_or_default(),
        )
        .into()
    }
}

impl From<Eip7702Auth> for AuthorizationTuple {
    fn from(value: Eip7702Auth) -> Self {
        AuthorizationTuple {
            chain_id: value.chain_id.try_into().unwrap_or(u64::MAX),
            address: value.address.to_proto_bytes(),
            nonce: value.nonce,
            y_parity: value.y_parity().into(),
            r: value.r().to_proto_bytes(),
            s: value.s().to_proto_bytes(),
        }
    }
}

impl TryFrom<BundlingMode> for RpcBundlingMode {
    type Error = ConversionError;

    fn try_from(value: BundlingMode) -> Result<Self, Self::Error> {
        match value {
            BundlingMode::Auto => Ok(Self::Auto),
            BundlingMode::Manual => Ok(Self::Manual),
            _ => Err(ConversionError::InvalidEnumValue(value as i32)),
        }
    }
}
