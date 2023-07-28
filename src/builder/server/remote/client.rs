use std::sync::Arc;

use anyhow::bail;
use ethers::types::{Address, H256};
use tokio_util::sync::CancellationToken;
use tonic::{async_trait, transport::Channel};

use super::protos::{
    builder_client::BuilderClient as GrpcBuilderClient, debug_send_bundle_now_response,
    debug_set_bundling_mode_response, get_supported_entry_points_response,
    BundlingMode as ProtoBundlingMode, DebugSendBundleNowRequest, DebugSetBundlingModeRequest,
    GetSupportedEntryPointsRequest,
};
use crate::{
    builder::{
        server::{BuilderClient, BuilderResult, BuilderServerError},
        BundlingMode,
    },
    common::{
        protos::{from_bytes, ConversionError},
        server::connect_with_retries,
    },
};

pub struct RemoteBuilderClient {
    grpc_client: GrpcBuilderClient<Channel>,
}

impl RemoteBuilderClient {
    pub fn new(grpc_client: GrpcBuilderClient<Channel>) -> Self {
        Self { grpc_client }
    }
}

#[async_trait]
impl BuilderClient for Arc<RemoteBuilderClient> {
    async fn get_supported_entry_points(&self) -> BuilderResult<Vec<Address>> {
        let res = self
            .grpc_client
            .clone()
            .get_supported_entry_points(GetSupportedEntryPointsRequest {})
            .await?
            .into_inner()
            .result;

        match res {
            Some(get_supported_entry_points_response::Result::Success(s)) => Ok(s
                .entry_points
                .into_iter()
                .map(|ep| from_bytes(ep.as_slice()))
                .collect::<Result<_, ConversionError>>()?),
            Some(get_supported_entry_points_response::Result::Failure(f)) => Err(f.try_into()?),
            None => Err(BuilderServerError::Other(anyhow::anyhow!(
                "should have received result from builder"
            )))?,
        }
    }

    async fn debug_send_bundle_now(&self) -> BuilderResult<H256> {
        let res = self
            .grpc_client
            .clone()
            .debug_send_bundle_now(DebugSendBundleNowRequest {})
            .await?
            .into_inner()
            .result;

        match res {
            Some(debug_send_bundle_now_response::Result::Success(s)) => {
                Ok(H256::from_slice(&s.transaction_hash))
            }
            Some(debug_send_bundle_now_response::Result::Failure(f)) => Err(f.try_into()?),
            None => Err(BuilderServerError::Other(anyhow::anyhow!(
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
            .await?
            .into_inner()
            .result;

        match res {
            Some(debug_set_bundling_mode_response::Result::Success(_)) => Ok(()),
            Some(debug_set_bundling_mode_response::Result::Failure(f)) => Err(f.try_into()?),
            None => Err(BuilderServerError::Other(anyhow::anyhow!(
                "should have received result from builder"
            )))?,
        }
    }
}

pub async fn connect_remote_builder_client(
    builder_url: &str,
    shutdown_token: CancellationToken,
) -> anyhow::Result<Arc<RemoteBuilderClient>> {
    tokio::select! {
        _ = shutdown_token.cancelled() => {
            tracing::error!("bailing from connecting client, server shutting down");
            bail!("Server shutting down")
        }
        res = connect_with_retries("builder", builder_url, GrpcBuilderClient::connect) => {
            Ok(Arc::new(RemoteBuilderClient::new(res?)))
        }
    }
}
