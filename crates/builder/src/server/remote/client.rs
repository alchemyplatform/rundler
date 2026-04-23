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

use std::str::FromStr;

use alloy_primitives::{Address, B256};
use async_trait::async_trait;
use rundler_task::{
    grpc::protos::{ConversionError, from_bytes},
    server::{HealthCheck, ServerStatus},
};
use rundler_types::{
    authorization::Eip7702Auth,
    builder::{Builder, BuilderError, BuilderResult, BundlingMode, DelegationId, DelegationStatus},
};
use tonic::transport::{Channel, Uri};
use tonic_health::{
    ServingStatus,
    pb::{HealthCheckRequest, health_client::HealthClient},
};

use super::protos::{
    AuthorizationTuple, BundlingMode as ProtoBundlingMode, DebugSendBundleNowRequest,
    DebugSetBundlingModeRequest, DelegationStatusKind, GetDelegationStatusRequest,
    GetSupportedEntryPointsRequest, SendSponsoredDelegationRequest, builder_client::BuilderClient,
    debug_send_bundle_now_response, debug_set_bundling_mode_response,
    get_delegation_status_response, send_sponsored_delegation_response,
};

/// Remote builder client, used for communicating with a remote builder server
#[derive(Debug, Clone)]
pub struct RemoteBuilderClient {
    grpc_client: BuilderClient<Channel>,
    health_client: HealthClient<Channel>,
}

impl RemoteBuilderClient {
    /// Connect to a remote builder server
    pub async fn connect(url: String) -> anyhow::Result<Self> {
        let grpc_client = BuilderClient::connect(url.clone()).await?;
        let health_client =
            HealthClient::new(Channel::builder(Uri::from_str(&url)?).connect().await?);
        Ok(Self {
            grpc_client,
            health_client,
        })
    }
}

#[async_trait]
impl Builder for RemoteBuilderClient {
    async fn get_supported_entry_points(&self) -> BuilderResult<Vec<Address>> {
        Ok(self
            .grpc_client
            .clone()
            .get_supported_entry_points(GetSupportedEntryPointsRequest {})
            .await
            .map_err(anyhow::Error::from)?
            .into_inner()
            .entry_points
            .into_iter()
            .map(|ep| from_bytes(ep.as_slice()))
            .collect::<Result<_, ConversionError>>()
            .map_err(anyhow::Error::from)?)
    }

    async fn debug_send_bundle_now(&self) -> BuilderResult<(B256, u64)> {
        let res = self
            .grpc_client
            .clone()
            .debug_send_bundle_now(DebugSendBundleNowRequest {})
            .await
            .map_err(anyhow::Error::from)?
            .into_inner()
            .result;

        match res {
            Some(debug_send_bundle_now_response::Result::Success(s)) => {
                Ok((B256::from_slice(&s.transaction_hash), s.block_number))
            }
            Some(debug_send_bundle_now_response::Result::Failure(f)) => Err(f.try_into()?),
            None => Err(BuilderError::Other(anyhow::anyhow!(
                "should have received result from builder"
            )))?,
        }
    }

    async fn send_sponsored_delegation(
        &self,
        auth: Eip7702Auth,
        valid_until: Option<u64>,
    ) -> BuilderResult<DelegationId> {
        let res = self
            .grpc_client
            .clone()
            .send_sponsored_delegation(SendSponsoredDelegationRequest {
                auth: Some(AuthorizationTuple::from(auth)),
                valid_until,
            })
            .await
            .map_err(anyhow::Error::from)?
            .into_inner()
            .result;

        match res {
            Some(send_sponsored_delegation_response::Result::Success(s)) => s
                .delegation_id
                .parse::<DelegationId>()
                .map_err(BuilderError::from),
            Some(send_sponsored_delegation_response::Result::Failure(f)) => Err(f.try_into()?),
            None => Err(BuilderError::Other(anyhow::anyhow!(
                "should have received result from builder"
            )))?,
        }
    }

    async fn get_delegation_status(&self, id: DelegationId) -> BuilderResult<DelegationStatus> {
        let res = self
            .grpc_client
            .clone()
            .get_delegation_status(GetDelegationStatusRequest {
                delegation_id: id.to_string(),
            })
            .await
            .map_err(anyhow::Error::from)?
            .into_inner()
            .result;

        match res {
            Some(get_delegation_status_response::Result::Success(s)) => {
                let kind = DelegationStatusKind::try_from(s.status)
                    .map_err(|e| anyhow::anyhow!("invalid delegation status: {e}"))?;
                let status = match kind {
                    DelegationStatusKind::Pending => DelegationStatus::Pending,
                    DelegationStatusKind::Mined => {
                        let tx_hash = s
                            .tx_hash
                            .ok_or_else(|| anyhow::anyhow!("mined delegation missing tx_hash"))?;
                        DelegationStatus::Mined {
                            tx_hash: B256::from_slice(&tx_hash),
                        }
                    }
                    DelegationStatusKind::Unspecified | DelegationStatusKind::Unknown => {
                        DelegationStatus::Unknown
                    }
                };
                Ok(status)
            }
            Some(get_delegation_status_response::Result::Failure(f)) => Err(f.try_into()?),
            None => Err(BuilderError::Other(anyhow::anyhow!(
                "should have received result from builder"
            )))?,
        }
    }

    async fn debug_set_bundling_mode(&self, mode: BundlingMode) -> BuilderResult<()> {
        let res = self
            .grpc_client
            .clone()
            .debug_set_bundling_mode(DebugSetBundlingModeRequest {
                mode: ProtoBundlingMode::from(mode) as i32,
            })
            .await
            .map_err(anyhow::Error::from)?
            .into_inner()
            .result;

        match res {
            Some(debug_set_bundling_mode_response::Result::Success(_)) => Ok(()),
            Some(debug_set_bundling_mode_response::Result::Failure(f)) => Err(f.try_into()?),
            None => Err(BuilderError::Other(anyhow::anyhow!(
                "should have received result from builder"
            )))?,
        }
    }
}

#[async_trait]
impl HealthCheck for RemoteBuilderClient {
    fn name(&self) -> &'static str {
        "RemoteBuilderServer"
    }

    async fn status(&self) -> ServerStatus {
        self.health_client
            .clone()
            .check(HealthCheckRequest::default())
            .await
            .ok()
            .filter(|status| status.get_ref().status == ServingStatus::Serving as i32)
            .map(|_| ServerStatus::Serving)
            .unwrap_or(ServerStatus::NotServing)
    }
}
