use std::{future::Future, time::Duration};

use mockall::mock;
use tokio::{net::TcpListener, task::AbortHandle, time};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{
    async_trait,
    transport::{self, Channel, Server},
    Request, Response,
};

use crate::common::protos::builder::{
    builder_client::BuilderClient,
    builder_server::{Builder, BuilderServer},
    DebugSendBundleNowRequest, DebugSendBundleNowResponse, DebugSetBundlingModeRequest,
    DebugSetBundlingModeResponse,
};

/// Maximum number of incrementing ports to try when looking for an open port
/// for a mock server.
const MAX_PORT_ATTEMPTS: u16 = 32;

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

pub type BuilderHandle = ClientHandle<BuilderClient<Channel>>;

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
    use super::*;

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
}
