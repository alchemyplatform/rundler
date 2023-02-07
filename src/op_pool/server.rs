use super::metrics::OpPoolMetrics;
use crate::common::protos::op_pool::op_pool_server::OpPool;
use crate::common::protos::op_pool::{
    AddOpRequest, AddOpResponse, DebugClearStateRequest, DebugClearStateResponse,
    DebugDumpMempoolRequest, DebugDumpMempoolResponse, DebugDumpReputationRequest,
    DebugDumpReputationResponse, DebugSetReputationRequest, DebugSetReputationResponse,
    GetOpsRequest, GetOpsResponse, GetReputationRequest, GetReputationResponse,
    GetSupportedEntryPointsRequest, GetSupportedEntryPointsResponse,
};
use tonic::{async_trait, Request, Response};

#[derive(Default)]
pub struct OpPoolImpl {
    metrics: OpPoolMetrics,
}

#[async_trait]
impl OpPool for OpPoolImpl {
    async fn get_supported_entry_points(
        &self,
        _request: Request<GetSupportedEntryPointsRequest>,
    ) -> tonic::Result<Response<GetSupportedEntryPointsResponse>> {
        self.metrics.request_counter.increment(1);
        unimplemented!("get_supported_entry_points not implemented");
    }

    async fn add_op(
        &self,
        _request: Request<AddOpRequest>,
    ) -> tonic::Result<Response<AddOpResponse>> {
        self.metrics.request_counter.increment(1);
        unimplemented!("add_op not implemented");
    }

    async fn get_ops(
        &self,
        _request: Request<GetOpsRequest>,
    ) -> tonic::Result<Response<GetOpsResponse>> {
        self.metrics.request_counter.increment(1);
        unimplemented!("get_ops not implemented");
    }

    async fn get_reputation(
        &self,
        _request: Request<GetReputationRequest>,
    ) -> tonic::Result<Response<GetReputationResponse>> {
        self.metrics.request_counter.increment(1);
        unimplemented!("get_reputation not implemented");
    }

    async fn debug_clear_state(
        &self,
        _request: Request<DebugClearStateRequest>,
    ) -> tonic::Result<Response<DebugClearStateResponse>> {
        self.metrics.request_counter.increment(1);
        unimplemented!("debug_clear_state not implemented");
    }

    async fn debug_dump_mempool(
        &self,
        _request: Request<DebugDumpMempoolRequest>,
    ) -> tonic::Result<Response<DebugDumpMempoolResponse>> {
        self.metrics.request_counter.increment(1);
        unimplemented!("debug_dump_mempool not implemented");
    }

    async fn debug_set_reputation(
        &self,
        _request: Request<DebugSetReputationRequest>,
    ) -> tonic::Result<Response<DebugSetReputationResponse>> {
        self.metrics.request_counter.increment(1);
        unimplemented!("debug_set_reputation not implemented");
    }

    async fn debug_dump_reputation(
        &self,
        _request: Request<DebugDumpReputationRequest>,
    ) -> tonic::Result<Response<DebugDumpReputationResponse>> {
        self.metrics.request_counter.increment(1);
        unimplemented!("debug_dump_reputation not implemented");
    }
}
