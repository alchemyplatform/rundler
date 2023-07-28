use crate::{builder::BundlingMode as RpcBundlingMode, common::protos::ConversionError};

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
