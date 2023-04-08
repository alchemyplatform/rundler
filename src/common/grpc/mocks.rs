use std::{future::Future, net::SocketAddr, time::Duration};

use mockall::mock;
use tokio::{net::TcpListener, task::AbortHandle, time};
use tonic::{
    async_trait,
    transport::{self, Channel, Server},
    Request, Response,
};

use crate::common::protos::{
    builder::{
        builder_client::BuilderClient,
        builder_server::{Builder, BuilderServer},
        DebugSendBundleNowRequest, DebugSendBundleNowResponse, DebugSetBundlingModeRequest,
        DebugSetBundlingModeResponse,
    },
    op_pool::{
        op_pool_client::OpPoolClient,
        op_pool_server::{OpPool, OpPoolServer},
        AddOpRequest, AddOpResponse, DebugClearStateRequest, DebugClearStateResponse,
        DebugDumpMempoolRequest, DebugDumpMempoolResponse, DebugDumpReputationRequest,
        DebugDumpReputationResponse, DebugSetReputationRequest, DebugSetReputationResponse,
        GetOpsRequest, GetOpsResponse, GetSupportedEntryPointsRequest,
        GetSupportedEntryPointsResponse, RemoveOpsRequest, RemoveOpsResponse,
    },
};

mock! {
    pub OpPool {}

    #[async_trait]
    impl OpPool for OpPool {
        async fn get_supported_entry_points(
            &self,
            _request: Request<GetSupportedEntryPointsRequest>,
        ) -> tonic::Result<Response<GetSupportedEntryPointsResponse>>;

        async fn add_op(&self, request: Request<AddOpRequest>) -> tonic::Result<Response<AddOpResponse>>;

        async fn get_ops(&self, request: Request<GetOpsRequest>) -> tonic::Result<Response<GetOpsResponse>>;

        async fn remove_ops(
            &self,
            request: Request<RemoveOpsRequest>,
        ) -> tonic::Result<Response<RemoveOpsResponse>>;

        async fn debug_clear_state(
            &self,
            _request: Request<DebugClearStateRequest>,
        ) -> tonic::Result<Response<DebugClearStateResponse>>;

        async fn debug_dump_mempool(
            &self,
            request: Request<DebugDumpMempoolRequest>,
        ) -> tonic::Result<Response<DebugDumpMempoolResponse>>;

        async fn debug_set_reputation(
            &self,
            request: Request<DebugSetReputationRequest>,
        ) -> tonic::Result<Response<DebugSetReputationResponse>>;

        async fn debug_dump_reputation(
            &self,
            request: Request<DebugDumpReputationRequest>,
        ) -> tonic::Result<Response<DebugDumpReputationResponse>>;
    }
}

mock! {
    pub Builder {}

    #[async_trait]
    impl Builder for Builder {
        async fn debug_send_bundle_now(
            &self,
            _request: Request<DebugSendBundleNowRequest>,
        ) -> tonic::Result<Response<DebugSendBundleNowResponse>>;

        async fn debug_set_bundling_mode(
            &self,
            _request: Request<DebugSetBundlingModeRequest>,
        ) -> tonic::Result<Response<DebugSetBundlingModeResponse>>;
    }
}

/// A gRPC client packaged with context that when dropped will cause the
/// corresponding server to shut down.
#[derive(Debug)]
pub struct ClientHandle<T> {
    pub client: T,
    abort_handle: AbortHandle,
}

impl<T> Drop for ClientHandle<T> {
    fn drop(&mut self) {
        self.abort_handle.abort();
    }
}

pub type OpPoolHandle = ClientHandle<OpPoolClient<Channel>>;
pub type BuilderHandle = ClientHandle<BuilderClient<Channel>>;

/// Creates an `OpPoolClient` connected to a local gRPC server which uses the
/// provided `mock` to respond to requests. Returns a handle which exposes the
/// client and shuts down the server when dropped.
pub async fn mock_op_pool_client(mock: impl OpPool) -> OpPoolHandle {
    mock_op_pool_client_with_port(mock, 56776).await
}

/// Like `mock_op_pool_client`, but accepts a custom port to avoid conflicts.
pub async fn mock_op_pool_client_with_port(mock: impl OpPool, port: u16) -> OpPoolHandle {
    mock_client_with_port(
        |addr| {
            Server::builder()
                .add_service(OpPoolServer::new(mock))
                .serve(addr)
        },
        OpPoolClient::connect,
        port,
    )
    .await
}

/// Creates a `BuilderClient` connected to a local gRPC server which uses the
/// provided `mock` to respond to requests. Returns a handle which exposes the
/// client and shuts down the server when dropped.
pub async fn mock_builder_client(mock: impl Builder) -> BuilderHandle {
    mock_builder_client_with_port(mock, 52845).await
}

/// Like `mock_builder_client`, but accepts a custom port to avoid conflicts.
pub async fn mock_builder_client_with_port(mock: impl Builder, port: u16) -> BuilderHandle {
    mock_client_with_port(
        |addr| {
            Server::builder()
                .add_service(BuilderServer::new(mock))
                .serve(addr)
        },
        BuilderClient::connect,
        port,
    )
    .await
}

async fn mock_client_with_port<FnS, FutS, FnC, FutC, C>(
    new_server: FnS,
    new_client: FnC,
    port: u16,
) -> ClientHandle<C>
where
    FnS: FnOnce(SocketAddr) -> FutS,
    FutS: Future<Output = Result<(), transport::Error>> + Send + 'static,
    FnC: FnOnce(String) -> FutC,
    FutC: Future<Output = Result<C, transport::Error>>,
{
    let server_addr = format!("[::1]:{port}");
    assert!(
        port_is_available(port).await,
        "port {port} is not available for mock client"
    );
    let client_addr = format!("http://{server_addr}");
    let abort_handle = tokio::spawn(new_server(server_addr.parse().unwrap())).abort_handle();
    // Sleeping any amount of time is enough for the server to become ready.
    time::sleep(Duration::from_millis(1)).await;
    let client = new_client(client_addr)
        .await
        .expect("should connect to mock gRPC server");
    ClientHandle {
        client,
        abort_handle,
    }
}

async fn port_is_available(port: u16) -> bool {
    TcpListener::bind(format!("[::1]:{port}")).await.is_ok()
}

#[cfg(test)]
mod test {
    use tokio::time;

    use super::*;

    #[tokio::test]
    async fn test_op_pool_mock() {
        let mut op_pool = MockOpPool::new();
        op_pool.expect_get_supported_entry_points().returning(|_| {
            Ok(Response::new(GetSupportedEntryPointsResponse {
                chain_id: 1337,
                entry_points: vec![vec![1, 2, 3]],
            }))
        });
        let mut handle = mock_op_pool_client(op_pool).await;
        let response = handle
            .client
            .get_supported_entry_points(GetSupportedEntryPointsRequest {})
            .await
            .expect("should get response from mock")
            .into_inner();
        assert_eq!(response.chain_id, 1337);
        assert_eq!(response.entry_points, vec![vec![1, 2, 3]]);
    }

    #[tokio::test]
    async fn test_builder_mock() {
        let mut builder = MockBuilder::new();
        builder.expect_debug_send_bundle_now().returning(|_| {
            Ok(Response::new(DebugSendBundleNowResponse {
                transaction_hash: vec![1, 2, 3],
            }))
        });
        let mut handle = mock_builder_client(builder).await;
        let transaction_hash = handle
            .client
            .debug_send_bundle_now(DebugSendBundleNowRequest {})
            .await
            .expect("should get response from mock")
            .into_inner()
            .transaction_hash;
        assert_eq!(transaction_hash, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn test_server_shutdown_when_handle_drops() {
        let port = 10000;
        assert!(port_is_available(port).await);
        {
            let _handle = mock_op_pool_client_with_port(MockOpPool::new(), port).await;
            assert!(!port_is_available(port).await);
        }
        // Sleeping any duration is enough for the server to shut down.
        time::sleep(Duration::from_millis(1)).await;
        assert!(port_is_available(port).await);
    }
}
