use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use async_trait::async_trait;
use ethers::types::{Address, H256};
use rundler_task::server::{HealthCheck, ServerStatus};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use crate::{
    bundle_sender::{SendBundleRequest, SendBundleResult},
    server::{BuilderResult, BuilderServer, BuilderServerError, BundlingMode},
};

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
        manual_bundling_mode: Arc<AtomicBool>,
        send_bundle_requesters: Vec<mpsc::Sender<SendBundleRequest>>,
        entry_points: Vec<Address>,
        shutdown_token: CancellationToken,
    ) -> JoinHandle<anyhow::Result<()>> {
        let mut runner = LocalBuilderServerRunner::new(
            self.req_receiver,
            manual_bundling_mode,
            send_bundle_requesters,
            entry_points,
        );
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
    send_bundle_requesters: Vec<mpsc::Sender<SendBundleRequest>>,
    manual_bundling_mode: Arc<AtomicBool>,
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
impl BuilderServer for LocalBuilderHandle {
    async fn get_supported_entry_points(&self) -> BuilderResult<Vec<Address>> {
        let req = ServerRequestKind::GetSupportedEntryPoints;
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::GetSupportedEntryPoints { entry_points } => Ok(entry_points),
            _ => Err(BuilderServerError::UnexpectedResponse),
        }
    }

    async fn debug_send_bundle_now(&self) -> BuilderResult<H256> {
        let req = ServerRequestKind::DebugSendBundleNow;
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::DebugSendBundleNow { hash } => Ok(hash),
            _ => Err(BuilderServerError::UnexpectedResponse),
        }
    }

    async fn debug_set_bundling_mode(&self, mode: BundlingMode) -> BuilderResult<()> {
        let req = ServerRequestKind::DebugSetBundlingMode { mode };
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::DebugSetBundlingMode => Ok(()),
            _ => Err(BuilderServerError::UnexpectedResponse),
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
        manual_bundling_mode: Arc<AtomicBool>,
        send_bundle_requesters: Vec<mpsc::Sender<SendBundleRequest>>,
        entry_points: Vec<Address>,
    ) -> Self {
        Self {
            req_receiver,
            manual_bundling_mode,
            send_bundle_requesters,
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
                                if !self.manual_bundling_mode.load(Ordering::Relaxed) {
                                    break 'a Err(anyhow::anyhow!("bundling mode is not manual").into())
                                } else if self.send_bundle_requesters.len() != 1 {
                                    break 'a Err(anyhow::anyhow!("more than 1 bundle builder not supported in debug mode").into())
                                }

                                let (tx, rx) = oneshot::channel();
                                match self.send_bundle_requesters[0].send(SendBundleRequest{
                                    responder: tx
                                }).await {
                                    Ok(()) => {},
                                    Err(e) => break 'a Err(anyhow::anyhow!("failed to send send bundle request: {}", e.to_string()).into())
                                }

                                let result = match rx.await {
                                    Ok(result) => result,
                                    Err(e) => break 'a Err(anyhow::anyhow!("failed to receive bundle result: {e:?}").into())
                                };

                                match result {
                                    SendBundleResult::Success { tx_hash, .. } => {
                                        Ok(ServerResponse::DebugSendBundleNow { hash: tx_hash })
                                    },
                                    SendBundleResult::NoOperationsInitially => {
                                        Err(anyhow::anyhow!("no ops to send").into())
                                    },
                                    SendBundleResult::NoOperationsAfterFeeIncreases { .. } => {
                                        Err(anyhow::anyhow!("bundle initially had operations, but after increasing gas fees it was empty").into())
                                    },
                                    SendBundleResult::StalledAtMaxFeeIncreases => Err(anyhow::anyhow!("stalled at max fee increases").into()),
                                    SendBundleResult::Error(e) => Err(anyhow::anyhow!("send bundle error: {e:?}").into()),
                                }
                            },
                            ServerRequestKind::DebugSetBundlingMode { mode } => {
                                self.manual_bundling_mode.store(mode == BundlingMode::Manual, Ordering::Relaxed);
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
    DebugSendBundleNow { hash: H256 },
    DebugSetBundlingMode,
}
