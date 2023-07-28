use ethers::types::{Address, H256};
use tokio::sync::{mpsc, oneshot};
use tonic::async_trait;

use super::server::{ServerRequest, ServerRequestKind, ServerResponse};
use crate::builder::{
    server::{BuilderClient, BuilderResult, BuilderServerError},
    BundlingMode,
};

#[derive(Debug, Clone)]
pub struct LocalBuilderClient {
    sender: mpsc::Sender<ServerRequest>,
}

impl LocalBuilderClient {
    pub fn new(sender: mpsc::Sender<ServerRequest>) -> Self {
        Self { sender }
    }

    async fn send(&self, request: ServerRequestKind) -> BuilderResult<ServerResponse> {
        let (send, recv) = oneshot::channel();
        self.sender
            .send(ServerRequest {
                request,
                response: send,
            })
            .await
            .map_err(|e| anyhow::anyhow!("LocalBuilderServer closed {e:?}"))?;
        recv.await
            .map_err(|e| anyhow::anyhow!("LocalBuilderServer closed {e:?}"))?
    }
}

#[async_trait]
impl BuilderClient for LocalBuilderClient {
    async fn get_supported_entry_points(&self) -> BuilderResult<Vec<Address>> {
        let resp = self
            .send(ServerRequestKind::GetSupportedEntryPoints)
            .await?;
        match resp {
            ServerResponse::GetSupportedEntryPoints {
                entry_points,
                chain_id,
            } => Ok(entry_points),
            _ => Err(BuilderServerError::UnexpectedResponse),
        }
    }

    async fn debug_send_bundle_now(&self) -> BuilderResult<H256> {
        let resp = self.send(ServerRequestKind::DebugSendBundleNow).await?;
        match resp {
            ServerResponse::DebugSendBundleNow { hash } => Ok(hash),
            _ => Err(BuilderServerError::UnexpectedResponse),
        }
    }

    async fn debug_set_bundling_mode(&self, mode: BundlingMode) -> BuilderResult<()> {
        let resp = self
            .send(ServerRequestKind::DebugSetBundlingMode { mode })
            .await?;
        match resp {
            ServerResponse::DebugSetBundlingMode => Ok(()),
            _ => Err(BuilderServerError::UnexpectedResponse),
        }
    }
}
