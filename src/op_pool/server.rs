use std::net::SocketAddr;

use crate::common::protos::op_pool::op_pool_server::{OpPool, OpPoolServer};
use crate::common::protos::op_pool::{
    AddOpRequest, AddOpResponse, DebugClearStateRequest, DebugClearStateResponse,
    DebugDumpMempoolRequest, DebugDumpMempoolResponse, DebugDumpReputationRequest,
    DebugDumpReputationResponse, DebugSetReputationRequest, DebugSetReputationResponse,
    GetOpsRequest, GetOpsResponse, GetReputationRequest, GetReputationResponse,
    GetSupportedEntryPointsRequest, GetSupportedEntryPointsResponse, OP_POOL_FILE_DESCRIPTOR_SET,
};
use tonic::transport::Server;
use tonic::{async_trait, Request, Response};

pub struct OpPoolImpl;

#[async_trait]
impl OpPool for OpPoolImpl {
    async fn get_supported_entry_points(
        &self,
        _request: Request<GetSupportedEntryPointsRequest>,
    ) -> tonic::Result<Response<GetSupportedEntryPointsResponse>> {
        unimplemented!("get_supported_entry_points not implemented");
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

pub async fn start_grpc(addr: SocketAddr) -> anyhow::Result<()> {
    let op_pool_server = OpPoolServer::new(OpPoolImpl);
    let reflection_service = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(OP_POOL_FILE_DESCRIPTOR_SET)
        .build()?;
    Server::builder()
        .add_service(op_pool_server)
        .add_service(reflection_service)
        .serve(addr)
        .await?;
    Ok(())
}
