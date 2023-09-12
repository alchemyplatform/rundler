use rundler_task::grpc::protos::ConversionError;

use super::protos::{builder_error, BuilderError as ProtoBuilderError};
use crate::server::BuilderServerError;

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
        match value.error {
            Some(builder_error::Error::Internal(e)) => {
                Ok(BuilderServerError::Other(anyhow::anyhow!(e)))
            }
            None => Ok(BuilderServerError::Other(anyhow::anyhow!("Unknown error"))),
        }
    }
}

impl From<BuilderServerError> for ProtoBuilderError {
    fn from(value: BuilderServerError) -> Self {
        match value {
            BuilderServerError::UnexpectedResponse => ProtoBuilderError {
                error: Some(builder_error::Error::Internal(
                    "Unexpected response".to_string(),
                )),
            },
            BuilderServerError::Other(e) => ProtoBuilderError {
                error: Some(builder_error::Error::Internal(e.to_string())),
            },
        }
    }
}
