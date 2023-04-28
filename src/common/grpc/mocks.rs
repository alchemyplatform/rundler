use std::{future::Future, time::Duration};

use mockall::mock;
use tokio::{net::TcpListener, task::AbortHandle, time};
use tokio_stream::wrappers::TcpListenerStream;
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
        GetSupportedEntryPointsResponse, RemoveEntitiesRequest, RemoveEntitiesResponse,
        RemoveOpsRequest, RemoveOpsResponse,
    },
};

/// Maximum number of incrementing ports to try when looking for an open port
/// for a mock server.
const MAX_PORT_ATTEMPTS: u16 = 32;

mock! {
    #[derive(Debug)]
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

        async fn remove_entities(
            &self,
            _request: Request<RemoveEntitiesRequest>,
        ) -> tonic::Result<Response<RemoveEntitiesResponse>>;

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
    #[derive(Debug)]
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
        |listener_stream| {
            Server::builder()
                .add_service(OpPoolServer::new(mock))
                .serve_with_incoming(listener_stream)
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
        |listener_stream| {
            Server::builder()
                .add_service(BuilderServer::new(mock))
                .serve_with_incoming(listener_stream)
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
    FnS: FnOnce(TcpListenerStream) -> FutS,
    FutS: Future<Output = Result<(), transport::Error>> + Send + 'static,
    FnC: FnOnce(String) -> FutC,
    FutC: Future<Output = Result<C, transport::Error>>,
{
    let (port, listener_stream) = find_open_port(port).await;
    let client_addr = format!("http://[::1]:{port}");
    let abort_handle = tokio::spawn(new_server(listener_stream)).abort_handle();
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

async fn find_open_port(starting_port: u16) -> (u16, TcpListenerStream) {
    for i in 0..MAX_PORT_ATTEMPTS {
        let port = starting_port + i;
        if let Ok(listener) = TcpListener::bind(format!("[::1]:{port}")).await {
            return (port, TcpListenerStream::new(listener));
        }
    }
    panic!(
        "couldn't find an open port in {MAX_PORT_ATTEMPTS} attempts starting from {starting_port}"
    );
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
    async fn test_multiple_mocks_avoid_port_collision() {
        let mut op_pool = MockOpPool::new();
        op_pool.expect_get_supported_entry_points().returning(|_| {
            Ok(Response::new(GetSupportedEntryPointsResponse {
                chain_id: 10,
                entry_points: vec![],
            }))
        });
        let mut handle1 = mock_op_pool_client(op_pool).await;
        let mut op_pool = MockOpPool::new();
        op_pool.expect_get_supported_entry_points().returning(|_| {
            Ok(Response::new(GetSupportedEntryPointsResponse {
                chain_id: 20,
                entry_points: vec![],
            }))
        });
        let mut handle2 = mock_op_pool_client(op_pool).await;
        let chain_id1 = handle1
            .client
            .get_supported_entry_points(GetSupportedEntryPointsRequest {})
            .await
            .expect("should get response from mock")
            .into_inner()
            .chain_id;
        assert_eq!(chain_id1, 10);
        let chain_id2 = handle2
            .client
            .get_supported_entry_points(GetSupportedEntryPointsRequest {})
            .await
            .expect("should get response from mock")
            .into_inner()
            .chain_id;
        assert_eq!(chain_id2, 20)
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

    async fn port_is_available(port: u16) -> bool {
        TcpListener::bind(format!("[::1]:{port}")).await.is_ok()
    }
}
