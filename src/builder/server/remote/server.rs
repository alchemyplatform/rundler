use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use ethers::types::Address;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
use tonic::{async_trait, transport::Server, Request, Response, Status};
use tracing::debug;

use super::protos::{
    builder_server::{Builder, BuilderServer},
    debug_set_bundling_mode_response, get_supported_entry_points_response, BundlingMode,
    DebugSendBundleNowRequest, DebugSendBundleNowResponse, DebugSetBundlingModeRequest,
    DebugSetBundlingModeResponse, DebugSetBundlingModeSuccess, GetSupportedEntryPointsRequest,
    GetSupportedEntryPointsResponse, GetSupportedEntryPointsSuccess, BUILDER_FILE_DESCRIPTOR_SET,
};
use crate::builder::{
    bundle_sender::{SendBundleRequest, SendBundleResult},
    server::remote::protos::{debug_send_bundle_now_response, DebugSendBundleNowSuccess},
};

pub async fn spawn_remote_builder_server(
    addr: SocketAddr,
    manual_bundling_mode: Arc<AtomicBool>,
    send_bundle_requester: mpsc::Sender<SendBundleRequest>,
    entry_points: Vec<Address>,
    chain_id: u64,
    shutdown_token: CancellationToken,
) -> anyhow::Result<JoinHandle<anyhow::Result<()>>> {
    // gRPC server
    let builder_server = BuilderImpl::new(
        manual_bundling_mode,
        send_bundle_requester,
        entry_points,
        chain_id,
    );
    let builder_server = BuilderServer::new(builder_server);

    let reflection_service = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(BUILDER_FILE_DESCRIPTOR_SET)
        .build()?;

    // health service
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<BuilderServer<BuilderImpl>>()
        .await;

    Ok(tokio::spawn(async move {
        Server::builder()
            .add_service(builder_server)
            .add_service(reflection_service)
            .add_service(health_service)
            .serve_with_shutdown(addr, async move { shutdown_token.cancelled().await })
            .await
            .map_err(|e| anyhow::anyhow!(format!("builder server failed: {e:?}")))
    }))
}

#[derive(Debug)]
pub struct BuilderImpl {
    send_bundle_requester: mpsc::Sender<SendBundleRequest>,
    manual_bundling_mode: Arc<AtomicBool>,
    entry_points: Vec<Address>,
    chain_id: u64,
}

impl BuilderImpl {
    pub fn new(
        manual_bundling_mode: Arc<AtomicBool>,
        send_bundle_requester: mpsc::Sender<SendBundleRequest>,
        entry_points: Vec<Address>,
        chain_id: u64,
    ) -> Self {
        Self {
            manual_bundling_mode,
            send_bundle_requester,
            entry_points,
            chain_id,
        }
    }
}

#[async_trait]
impl Builder for BuilderImpl {
    async fn get_supported_entry_points(
        &self,
        _request: Request<GetSupportedEntryPointsRequest>,
    ) -> tonic::Result<Response<GetSupportedEntryPointsResponse>> {
        Ok(Response::new(GetSupportedEntryPointsResponse {
            result: Some(get_supported_entry_points_response::Result::Success(
                GetSupportedEntryPointsSuccess {
                    entry_points: self
                        .entry_points
                        .clone()
                        .into_iter()
                        .map(|a| a.as_bytes().to_vec())
                        .collect(),
                    chain_id: self.chain_id,
                },
            )),
        }))
    }

    async fn debug_send_bundle_now(
        &self,
        _request: Request<DebugSendBundleNowRequest>,
    ) -> tonic::Result<Response<DebugSendBundleNowResponse>> {
        // TODO(danc): Errors

        debug!("Send bundle now called");
        if !self.manual_bundling_mode.load(Ordering::Relaxed) {
            return Err(Status::failed_precondition(
                "manual bundling mode must be enabled",
            ));
        }

        let (tx, rx) = oneshot::channel();

        self.send_bundle_requester
            .send(SendBundleRequest { responder: tx })
            .await
            .map_err(|e| Status::internal(format!("failed to send bundle request {e}")))?;

        let result = rx
            .await
            .map_err(|e| Status::internal(format!("failed to receive bundle result {e}")))?;

        let tx_hash = match result {
            SendBundleResult::Success { tx_hash, .. } => tx_hash,
            SendBundleResult::NoOperationsInitially => {
                return Err(Status::internal("no ops to send"))
            }
            SendBundleResult::NoOperationsAfterFeeIncreases { .. } => {
                return Err(Status::internal(
                    "bundle initially had operations, but after increasing gas fees it was empty",
                ))
            }
            SendBundleResult::StalledAtMaxFeeIncreases => {
                return Err(Status::internal("stalled at max fee increases"))
            }
            SendBundleResult::Error(error) => return Err(Status::internal(error.to_string())),
        };
        Ok(Response::new(DebugSendBundleNowResponse {
            result: Some(debug_send_bundle_now_response::Result::Success(
                DebugSendBundleNowSuccess {
                    transaction_hash: tx_hash.as_bytes().to_vec(),
                },
            )),
        }))
    }

    async fn debug_set_bundling_mode(
        &self,
        request: Request<DebugSetBundlingModeRequest>,
    ) -> tonic::Result<Response<DebugSetBundlingModeResponse>> {
        let mode = BundlingMode::from_i32(request.into_inner().mode).unwrap_or_default();
        let is_manual_bundling = match mode {
            BundlingMode::Unspecified => {
                return Err(Status::invalid_argument("invalid bundling mode"))
            }
            BundlingMode::Manual => true,
            BundlingMode::Auto => false,
        };
        self.manual_bundling_mode
            .store(is_manual_bundling, Ordering::Relaxed);
        Ok(Response::new(DebugSetBundlingModeResponse {
            result: Some(debug_set_bundling_mode_response::Result::Success(
                DebugSetBundlingModeSuccess {},
            )),
        }))
    }
}
