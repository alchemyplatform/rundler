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

use rundler_task::grpc::protos::ConversionError;
use rundler_types::builder::BundlingMode as RpcBundlingMode;

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
