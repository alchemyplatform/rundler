use tonic::{async_trait, Request, Response, Result};

use crate::common::protos::builder::{
    builder_server::Builder, DebugSendBundleNowRequest, DebugSendBundleNowResponse,
    DebugSetBundlingModeRequest, DebugSetBundlingModeResponse,
};

pub struct BuilderImpl {}

impl BuilderImpl {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl Builder for BuilderImpl {
    async fn debug_send_bundle_now(
        &self,
        _request: Request<DebugSendBundleNowRequest>,
    ) -> Result<Response<DebugSendBundleNowResponse>> {
        Err(tonic::Status::unimplemented("not implemented"))
    }

    async fn debug_set_bundling_mode(
        &self,
        _request: Request<DebugSetBundlingModeRequest>,
    ) -> Result<Response<DebugSetBundlingModeResponse>> {
        Err(tonic::Status::unimplemented("not implemented"))
    }
}
