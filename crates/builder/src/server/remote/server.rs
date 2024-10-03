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

use std::net::SocketAddr;

use rundler_task::GracefulShutdown;
use rundler_types::builder::Builder;
use tonic::{async_trait, transport::Server, Request, Response, Status};

use super::protos::{
    builder_server::{Builder as GrpcBuilder, BuilderServer as GrpcBuilderServer},
    debug_send_bundle_now_response, debug_set_bundling_mode_response, BundlingMode,
    DebugSendBundleNowRequest, DebugSendBundleNowResponse, DebugSetBundlingModeRequest,
    DebugSetBundlingModeResponse, DebugSetBundlingModeSuccess, GetSupportedEntryPointsRequest,
    GetSupportedEntryPointsResponse, BUILDER_FILE_DESCRIPTOR_SET,
};
use crate::server::{local::LocalBuilderHandle, remote::protos::DebugSendBundleNowSuccess};

/// Spawn a remote builder server
pub(crate) async fn remote_builder_server_task(
    addr: SocketAddr,
    chain_id: u64,
    local_builder: LocalBuilderHandle,
    shutdown: GracefulShutdown,
) {
    // gRPC server
    let builder_server = GrpcBuilderServerImpl::new(chain_id, local_builder);
    let builder_server = GrpcBuilderServer::new(builder_server);

    let reflection_service = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(BUILDER_FILE_DESCRIPTOR_SET)
        .build_v1()
        .expect("should build builder reflection service");

    // health service
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<GrpcBuilderServer<GrpcBuilderServerImpl>>()
        .await;

    if let Err(e) = Server::builder()
        .add_service(builder_server)
        .add_service(reflection_service)
        .add_service(health_service)
        .serve_with_shutdown(addr, async move {
            let _ = shutdown.await;
        })
        .await
    {
        tracing::error!("builder server failed: {e:?}");
    }
}

#[derive(Debug)]
struct GrpcBuilderServerImpl {
    chain_id: u64,
    local_builder: LocalBuilderHandle,
}

impl GrpcBuilderServerImpl {
    fn new(chain_id: u64, local_builder: LocalBuilderHandle) -> Self {
        Self {
            chain_id,
            local_builder,
        }
    }
}

#[async_trait]
impl GrpcBuilder for GrpcBuilderServerImpl {
    async fn get_supported_entry_points(
        &self,
        _request: Request<GetSupportedEntryPointsRequest>,
    ) -> tonic::Result<Response<GetSupportedEntryPointsResponse>> {
        let resp = match self.local_builder.get_supported_entry_points().await {
            Ok(entry_points) => GetSupportedEntryPointsResponse {
                chain_id: self.chain_id,
                entry_points: entry_points.into_iter().map(|ep| ep.to_vec()).collect(),
            },
            Err(e) => {
                return Err(Status::internal(format!("Failed to get entry points: {e}")));
            }
        };

        Ok(Response::new(resp))
    }

    async fn debug_send_bundle_now(
        &self,
        _request: Request<DebugSendBundleNowRequest>,
    ) -> tonic::Result<Response<DebugSendBundleNowResponse>> {
        let resp = match self.local_builder.debug_send_bundle_now().await {
            Ok((hash, block_number)) => DebugSendBundleNowResponse {
                result: Some(debug_send_bundle_now_response::Result::Success(
                    DebugSendBundleNowSuccess {
                        transaction_hash: hash.to_vec(),
                        block_number,
                    },
                )),
            },
            Err(e) => {
                return Err(Status::internal(format!("Failed to send bundle: {e}")));
            }
        };

        Ok(Response::new(resp))
    }

    async fn debug_set_bundling_mode(
        &self,
        request: Request<DebugSetBundlingModeRequest>,
    ) -> tonic::Result<Response<DebugSetBundlingModeResponse>> {
        let mode = BundlingMode::try_from(request.into_inner().mode).map_err(|e| {
            Status::internal(format!("Failed to convert from proto reputation {e}"))
        })?;
        let mode = mode.try_into().map_err(|e| {
            Status::internal(format!("Failed to convert from proto reputation {e}"))
        })?;

        let resp = match self.local_builder.debug_set_bundling_mode(mode).await {
            Ok(()) => DebugSetBundlingModeResponse {
                result: Some(debug_set_bundling_mode_response::Result::Success(
                    DebugSetBundlingModeSuccess {},
                )),
            },
            Err(e) => {
                return Err(Status::internal(format!(
                    "Failed to set bundling mode: {e}"
                )));
            }
        };

        Ok(Response::new(resp))
    }
}
