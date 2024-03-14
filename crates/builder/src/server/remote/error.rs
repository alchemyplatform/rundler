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

use rundler_types::builder::BuilderError;

use super::protos::{builder_error, BuilderError as ProtoBuilderError};

impl TryFrom<ProtoBuilderError> for BuilderError {
    type Error = anyhow::Error;

    fn try_from(value: ProtoBuilderError) -> Result<Self, Self::Error> {
        match value.error {
            Some(builder_error::Error::Internal(e)) => Ok(BuilderError::Other(anyhow::anyhow!(e))),
            None => Ok(BuilderError::Other(anyhow::anyhow!("Unknown error"))),
        }
    }
}

impl From<BuilderError> for ProtoBuilderError {
    fn from(value: BuilderError) -> Self {
        match value {
            BuilderError::UnexpectedResponse => ProtoBuilderError {
                error: Some(builder_error::Error::Internal(
                    "Unexpected response".to_string(),
                )),
            },
            BuilderError::Other(e) => ProtoBuilderError {
                error: Some(builder_error::Error::Internal(e.to_string())),
            },
        }
    }
}
