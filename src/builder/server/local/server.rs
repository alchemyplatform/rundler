use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use ethers::types::{Address, H256};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use crate::builder::{
    bundle_sender::{SendBundleRequest, SendBundleResult},
    server::BuilderResult,
    BundlingMode,
};

pub async fn spawn_local_builder_server(
    req_receiver: mpsc::Receiver<ServerRequest>,
    manual_bundling_mode: Arc<AtomicBool>,
    send_bundle_requester: mpsc::Sender<SendBundleRequest>,
    entry_points: Vec<Address>,
    chain_id: u64,
    shutdown_token: CancellationToken,
) -> anyhow::Result<JoinHandle<anyhow::Result<()>>> {
    let mut server = LocalBuilderServer::new(
        req_receiver,
        manual_bundling_mode,
        send_bundle_requester,
        entry_points,
        chain_id,
    );
    let handle = tokio::spawn(async move { server.run(shutdown_token).await });
    Ok(handle)
}

#[derive(Debug)]
pub struct ServerRequest {
    pub request: ServerRequestKind,
    pub response: oneshot::Sender<BuilderResult<ServerResponse>>,
}

#[derive(Clone, Debug)]
pub enum ServerRequestKind {
    GetSupportedEntryPoints,
    DebugSendBundleNow,
    DebugSetBundlingMode { mode: BundlingMode },
}

#[derive(Clone, Debug)]
pub enum ServerResponse {
    GetSupportedEntryPoints {
        entry_points: Vec<Address>,
        chain_id: u64,
    },
    DebugSendBundleNow {
        hash: H256,
    },
    DebugSetBundlingMode,
}

pub struct LocalBuilderServer {
    req_receiver: mpsc::Receiver<ServerRequest>,
    send_bundle_requester: mpsc::Sender<SendBundleRequest>,
    manual_bundling_mode: Arc<AtomicBool>,
    entry_points: Vec<Address>,
    chain_id: u64,
}

impl LocalBuilderServer {
    pub fn new(
        req_receiver: mpsc::Receiver<ServerRequest>,
        manual_bundling_mode: Arc<AtomicBool>,
        send_bundle_requester: mpsc::Sender<SendBundleRequest>,
        entry_points: Vec<Address>,
        chain_id: u64,
    ) -> Self {
        Self {
            req_receiver,
            manual_bundling_mode,
            send_bundle_requester,
            entry_points,
            chain_id,
        }
    }

    pub async fn run(&mut self, shutdown_token: CancellationToken) -> anyhow::Result<()> {
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
                                    entry_points: self.entry_points.clone(),
                                    chain_id: self.chain_id,
                                })
                            },
                            ServerRequestKind::DebugSendBundleNow => {
                                let (tx, rx) = oneshot::channel();
                                match self.send_bundle_requester.send(SendBundleRequest{
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
