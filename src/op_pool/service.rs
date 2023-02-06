use crate::common::protos::op_pool::op_pool_server::OpPool;
use crate::common::protos::op_pool::{
    AddOpRequest, AddOpResponse, DebugClearStateRequest, DebugClearStateResponse,
    DebugDumpMempoolRequest, DebugDumpMempoolResponse, DebugDumpReputationRequest,
    DebugDumpReputationResponse, DebugSetReputationRequest, DebugSetReputationResponse,
    GetOpsRequest, GetOpsResponse, GetReputationRequest, GetReputationResponse,
    GetSupportedEntrypointsRequest, GetSupportedEntrypointsResponse,
};
use tonic::{async_trait, Request, Response};

pub struct OpPoolImpl;

#[async_trait]
impl OpPool for OpPoolImpl {
    async fn get_supported_entrypoints(
        &self,
        _request: Request<GetSupportedEntrypointsRequest>,
    ) -> tonic::Result<Response<GetSupportedEntrypointsResponse>> {
        unimplemented!("get_supported_entrypoints not implemented");
    }

    async fn add_op(
        &self,
        _request: Request<AddOpRequest>,
    ) -> tonic::Result<Response<AddOpResponse>> {
        unimplemented!("add_op not implemented");
    }

    async fn get_ops(
        &self,
        _request: Request<GetOpsRequest>,
    ) -> tonic::Result<Response<GetOpsResponse>> {
        unimplemented!("get_ops not implemented");
    }

    async fn get_reputation(
        &self,
        _request: Request<GetReputationRequest>,
    ) -> tonic::Result<Response<GetReputationResponse>> {
        unimplemented!("get_reputation not implemented");
    }

    async fn debug_clear_state(
        &self,
        _request: Request<DebugClearStateRequest>,
    ) -> tonic::Result<Response<DebugClearStateResponse>> {
        unimplemented!("debug_clear_state not implemented");
    }

    async fn debug_dump_mempool(
        &self,
        _request: Request<DebugDumpMempoolRequest>,
    ) -> tonic::Result<Response<DebugDumpMempoolResponse>> {
        unimplemented!("debug_dump_mempool not implemented");
    }

    async fn debug_set_reputation(
        &self,
        _request: Request<DebugSetReputationRequest>,
    ) -> tonic::Result<Response<DebugSetReputationResponse>> {
        unimplemented!("debug_set_reputation not implemented");
    }

    async fn debug_dump_reputation(
        &self,
        _request: Request<DebugDumpReputationRequest>,
    ) -> tonic::Result<Response<DebugDumpReputationResponse>> {
        unimplemented!("debug_dump_reputation not implemented");
    }
}
