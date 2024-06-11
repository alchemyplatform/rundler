// This file is part of Rundler.
//
// Rundler is free software: you can redistribute it and/or modify it under the
// terms of the GNU Lesser General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later version.
//
// Rundler is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with Rundler.
// If not, see https://www.gnu.org/licenses/.

use async_trait::async_trait;
use ethers::types::{Address, H256};
use rundler_task::server::{HealthCheck, ServerStatus};
use rundler_types::builder::{Builder, BuilderError, BuilderResult, BundlingMode};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use crate::bundle_sender::{BundleSenderAction, SendBundleRequest, SendBundleResult};

/// Local builder server builder
#[derive(Debug)]
pub struct LocalBuilderBuilder {
    req_sender: mpsc::Sender<ServerRequest>,
    req_receiver: mpsc::Receiver<ServerRequest>,
}

impl LocalBuilderBuilder {
    /// Create a new local builder server builder
    pub fn new(request_capcity: usize) -> Self {
        let (req_sender, req_receiver) = mpsc::channel(request_capcity);
        Self {
            req_sender,
            req_receiver,
        }
    }

    /// Get a handle to the local builder server
    pub fn get_handle(&self) -> LocalBuilderHandle {
        LocalBuilderHandle {
            req_sender: self.req_sender.clone(),
        }
    }

    /// Run the local builder server, consuming the builder
    pub fn run(
        self,
        bundle_sender_actions: Vec<mpsc::Sender<BundleSenderAction>>,
        entry_points: Vec<Address>,
        shutdown_token: CancellationToken,
    ) -> JoinHandle<anyhow::Result<()>> {
        let mut runner =
            LocalBuilderServerRunner::new(self.req_receiver, bundle_sender_actions, entry_points);
        tokio::spawn(async move { runner.run(shutdown_token).await })
    }
}

/// Local builder server handle, used to send requests to the server
#[derive(Debug, Clone)]
pub struct LocalBuilderHandle {
    req_sender: mpsc::Sender<ServerRequest>,
}

struct LocalBuilderServerRunner {
    req_receiver: mpsc::Receiver<ServerRequest>,
    bundle_sender_actions: Vec<mpsc::Sender<BundleSenderAction>>,
    entry_points: Vec<Address>,
}

impl LocalBuilderHandle {
    async fn send(&self, request: ServerRequestKind) -> BuilderResult<ServerResponse> {
        let (response_sender, response_receiver) = oneshot::channel();
        let request = ServerRequest {
            request,
            response: response_sender,
        };
        self.req_sender
            .send(request)
            .await
            .map_err(|_| anyhow::anyhow!("LocalBuilderServer closed"))?;
        response_receiver
            .await
            .map_err(|_| anyhow::anyhow!("LocalBuilderServer closed"))?
    }
}

#[async_trait]
impl Builder for LocalBuilderHandle {
    async fn get_supported_entry_points(&self) -> BuilderResult<Vec<Address>> {
        let req = ServerRequestKind::GetSupportedEntryPoints;
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::GetSupportedEntryPoints { entry_points } => Ok(entry_points),
            _ => Err(BuilderError::UnexpectedResponse),
        }
    }

    async fn debug_send_bundle_now(&self) -> BuilderResult<(H256, u64)> {
        let req = ServerRequestKind::DebugSendBundleNow;
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::DebugSendBundleNow { hash, block_number } => Ok((hash, block_number)),
            _ => Err(BuilderError::UnexpectedResponse),
        }
    }

    async fn debug_set_bundling_mode(&self, mode: BundlingMode) -> BuilderResult<()> {
        let req = ServerRequestKind::DebugSetBundlingMode { mode };
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::DebugSetBundlingMode => Ok(()),
            _ => Err(BuilderError::UnexpectedResponse),
        }
    }
}

#[async_trait]
impl HealthCheck for LocalBuilderHandle {
    fn name(&self) -> &'static str {
        "LocalPoolServer"
    }

    async fn status(&self) -> ServerStatus {
        if self.get_supported_entry_points().await.is_ok() {
            ServerStatus::Serving
        } else {
            ServerStatus::NotServing
        }
    }
}

impl LocalBuilderServerRunner {
    fn new(
        req_receiver: mpsc::Receiver<ServerRequest>,
        bundle_sender_actions: Vec<mpsc::Sender<BundleSenderAction>>,
        entry_points: Vec<Address>,
    ) -> Self {
        Self {
            req_receiver,
            bundle_sender_actions,
            entry_points,
        }
    }

    async fn run(&mut self, shutdown_token: CancellationToken) -> anyhow::Result<()> {
        loop {
            tokio::select! {
                _ = shutdown_token.cancelled() => {
                    return Ok(())
                }
                Some(req) = self.req_receiver.recv() => {
                    let resp: BuilderResult<ServerResponse> = 'a:  {
                        match req.request {
                            ServerRequestKind::GetSupportedEntryPoints => {
                                Ok(ServerResponse::GetSupportedEntryPoints {
                                    entry_points: self.entry_points.clone()
                                })
                            },
                            ServerRequestKind::DebugSendBundleNow => {
                                if self.bundle_sender_actions.len() != 1 {
                                    break 'a Err(anyhow::anyhow!("more than 1 bundle builder not supported in debug mode").into())
                                }

                                let (tx, rx) = oneshot::channel();
                                match self.bundle_sender_actions[0].send(BundleSenderAction::SendBundle(SendBundleRequest{
                                    responder: tx
                                })).await {
                                    Ok(()) => {},
                                    Err(e) => break 'a Err(anyhow::anyhow!("failed to send send bundle request: {}", e.to_string()).into())
                                }

                                let result = match rx.await {
                                    Ok(result) => result,
                                    Err(e) => break 'a Err(anyhow::anyhow!("failed to receive bundle result: {e:?}").into())
                                };

                                match result {
                                    SendBundleResult::Success { tx_hash, block_number, .. } => {
                                        Ok(ServerResponse::DebugSendBundleNow { hash: tx_hash, block_number })
                                    },
                                    SendBundleResult::NoOperationsInitially => {
                                        Err(anyhow::anyhow!("no ops to send").into())
                                    },
                                    SendBundleResult::StalledAtMaxFeeIncreases => Err(anyhow::anyhow!("stalled at max fee increases").into()),
                                    SendBundleResult::Error(e) => Err(anyhow::anyhow!("send bundle error: {e:?}").into()),
                                }
                            },
                            ServerRequestKind::DebugSetBundlingMode { mode } => {
                                if self.bundle_sender_actions.len() != 1 {
                                    break 'a Err(anyhow::anyhow!("more than 1 bundle builder not supported in debug mode").into())
                                }

                                match self.bundle_sender_actions[0].send(BundleSenderAction::ChangeMode(mode)).await {
                                    Ok(()) => {},
                                    Err(e) => break 'a Err(anyhow::anyhow!("failed to change bundler mode: {}", e.to_string()).into())
                                }

                                Ok(ServerResponse::DebugSetBundlingMode)
                            },
                        }
                    };

                    if let Err(e) = req.response.send(resp) {
                        tracing::error!("failed to send response: {:?}", e);
                    }
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
enum ServerRequestKind {
    GetSupportedEntryPoints,
    DebugSendBundleNow,
    DebugSetBundlingMode { mode: BundlingMode },
}

#[derive(Debug)]
struct ServerRequest {
    request: ServerRequestKind,
    response: oneshot::Sender<BuilderResult<ServerResponse>>,
}

#[derive(Clone, Debug)]
enum ServerResponse {
    GetSupportedEntryPoints { entry_points: Vec<Address> },
    DebugSendBundleNow { hash: H256, block_number: u64 },
    DebugSetBundlingMode,
}
