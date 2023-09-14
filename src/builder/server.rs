use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use tokio::sync::{mpsc, oneshot};
use tonic::{async_trait, Request, Response, Status};
use tracing::debug;

use super::bundle_sender::SendBundleRequest;
use crate::{
    builder::bundle_sender::SendBundleResult,
    common::protos::builder::{
        builder_server::Builder, BundlingMode, DebugSendBundleNowRequest,
        DebugSendBundleNowResponse, DebugSetBundlingModeRequest, DebugSetBundlingModeResponse,
    },
};

pub struct BuilderImpl {
    manual_bundling_mode: Arc<AtomicBool>,
    send_bundle_requester: mpsc::Sender<SendBundleRequest>,
}

impl BuilderImpl {
    pub fn new(
        manual_bundling_mode: Arc<AtomicBool>,
        send_bundle_requester: mpsc::Sender<SendBundleRequest>,
    ) -> Self {
        Self {
            manual_bundling_mode,
            send_bundle_requester,
        }
    }
}

#[async_trait]
impl Builder for BuilderImpl {
    async fn debug_send_bundle_now(
        &self,
        _request: Request<DebugSendBundleNowRequest>,
    ) -> tonic::Result<Response<DebugSendBundleNowResponse>> {
        debug!("Send bundle now called");
        if !self.manual_bundling_mode.load(Ordering::Relaxed) {
            return Err(Status::invalid_argument("bundling mode is not manual"));
        }

        let (tx, rx) = oneshot::channel();

        if self
            .send_bundle_requester
            .send(SendBundleRequest { responder: tx })
            .await
            .is_err()
        {
            return Err(Status::internal("failed to send bundle request"));
        }

        let result = rx.await.map_err(|e| Status::internal(e.to_string()))?;

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
            transaction_hash: tx_hash.as_bytes().to_vec(),
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
        Ok(Response::new(DebugSetBundlingModeResponse {}))
    }
}

/// This stupid type exists because we need to write out some type that
/// implements `Builder` to set up the health reporter, i.e.
///
/// `health_reporter.set_serving::<BuilderService<ANY_BUILDER_HERE>>().await;`
///
/// It doesn't matter what the type is: the type parameter there is only used to
/// read the service name out of `BuilderService` which doesn't depend on the
/// `Builder` impl. But the only other `Builder` impl we have is `BuilderImpl`,
/// which has multiple type parameters whose concrete types themselves need type
/// parameters and is overall extremely nasty to write out. So we make ourselves
/// a non-instantiatable type that implements `Builder` that we can use instead.
pub enum DummyBuilder {}

#[async_trait]
impl Builder for DummyBuilder {
    async fn debug_send_bundle_now(
        &self,
        _request: Request<DebugSendBundleNowRequest>,
    ) -> tonic::Result<Response<DebugSendBundleNowResponse>> {
        panic!()
    }

    async fn debug_set_bundling_mode(
        &self,
        _request: Request<DebugSetBundlingModeRequest>,
    ) -> tonic::Result<Response<DebugSetBundlingModeResponse>> {
        panic!()
    }
}
