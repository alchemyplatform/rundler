use rundler_task::grpc::protos::ConversionError;

use crate::server::BundlingMode as RpcBundlingMode;

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

impl TryFrom<i32> for RpcBundlingMode {
    type Error = ConversionError;

    fn try_from(status: i32) -> Result<Self, Self::Error> {
        match status {
            x if x == BundlingMode::Auto as i32 => Ok(Self::Auto),
            x if x == BundlingMode::Manual as i32 => Ok(Self::Manual),
            _ => Err(ConversionError::InvalidEnumValue(status)),
        }
    }
}
