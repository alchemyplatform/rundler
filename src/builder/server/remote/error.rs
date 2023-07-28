use super::protos::BuilderError as ProtoBuilderError;
use crate::{builder::server::BuilderServerError, common::protos::ConversionError};

impl From<tonic::Status> for BuilderServerError {
    fn from(value: tonic::Status) -> Self {
        BuilderServerError::Other(anyhow::anyhow!(value.to_string()))
    }
}

impl From<ConversionError> for BuilderServerError {
    fn from(value: ConversionError) -> Self {
        BuilderServerError::Other(anyhow::anyhow!(value.to_string()))
    }
}

impl TryFrom<ProtoBuilderError> for BuilderServerError {
    type Error = anyhow::Error;

    fn try_from(value: ProtoBuilderError) -> Result<Self, Self::Error> {
        todo!()
    }
}

impl From<BuilderServerError> for ProtoBuilderError {
    fn from(value: BuilderServerError) -> Self {
        todo!()
    }
}
