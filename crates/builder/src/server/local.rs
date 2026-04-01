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

use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy_primitives::{Address, B256};
use async_trait::async_trait;
use futures::future::BoxFuture;
use futures_util::StreamExt;
use metrics::Histogram;
use metrics_derive::Metrics;
use rundler_provider::{EvmProvider, FeeEstimator};
use rundler_signer::SignerManager;
use rundler_task::{
    GracefulShutdown,
    server::{HealthCheck, ServerStatus},
};
use rundler_types::{
    authorization::Eip7702Auth,
    builder::{Builder, BuilderError, BuilderResult, BundlingMode},
    pool::{NewHead, Pool},
};
use tokio::sync::{broadcast, mpsc, oneshot};

use crate::{
    bundle_sender::{BundleSenderAction, SendBundleRequest, SendBundleResult},
    delegation_sender::DelegationSender,
};

/// Local builder server builder
pub struct LocalBuilderBuilder {
    req_sender: mpsc::Sender<ServerRequest>,
    req_receiver: mpsc::Receiver<ServerRequest>,
    signer_manager: Arc<dyn SignerManager>,
    pool: Arc<dyn Pool>,
}

#[derive(Metrics, Clone)]
#[metrics(scope = "builder_internal")]
struct LocalBuilderMetrics {
    #[metric(describe = "the duration in milliseconds of send call")]
    send_duration: Histogram,
}

impl LocalBuilderBuilder {
    /// Create a new local builder server builder
    pub fn new(
        request_capacity: usize,
        signer_manager: Arc<dyn SignerManager>,
        pool: Arc<dyn Pool>,
    ) -> Self {
        let (req_sender, req_receiver) = mpsc::channel(request_capacity);
        Self {
            req_sender,
            req_receiver,
            signer_manager,
            pool,
        }
    }

    /// Get a handle to the local builder server
    pub fn get_handle(&self) -> LocalBuilderHandle {
        LocalBuilderHandle {
            req_sender: self.req_sender.clone(),
            metric: LocalBuilderMetrics::default(),
        }
    }

    /// Run the local builder server, consuming the builder.
    ///
    /// `delegation_sender` handles bundler-sponsored EIP-7702 delegation transactions.
    ///
    /// `heads_tx` is the shared new-heads broadcast sender; a fresh receiver is
    /// subscribed for each delegation send so the `DelegationSender` can watch for
    /// mining without polling.
    pub fn run<E, F>(
        self,
        bundle_sender_actions: Vec<mpsc::Sender<BundleSenderAction>>,
        entry_points: Vec<Address>,
        heads_tx: broadcast::Sender<Arc<NewHead>>,
        delegation_sender: DelegationSender<E, F>,
        shutdown: GracefulShutdown,
    ) -> BoxFuture<'static, ()>
    where
        E: EvmProvider + Clone + Send + Sync + 'static,
        F: FeeEstimator + Clone + Send + Sync + 'static,
    {
        let runner = LocalBuilderServerRunner::new(
            self.req_receiver,
            bundle_sender_actions,
            entry_points,
            self.signer_manager,
            self.pool,
            heads_tx,
            delegation_sender,
        );
        Box::pin(runner.run(shutdown))
    }
}

/// Local builder server handle, used to send requests to the server
#[derive(Debug, Clone)]
pub struct LocalBuilderHandle {
    req_sender: mpsc::Sender<ServerRequest>,
    metric: LocalBuilderMetrics,
}

struct LocalBuilderServerRunner<E, F> {
    req_receiver: mpsc::Receiver<ServerRequest>,
    bundle_sender_actions: Vec<mpsc::Sender<BundleSenderAction>>,
    entry_points: Vec<Address>,
    signer_manager: Arc<dyn SignerManager>,
    pool: Arc<dyn Pool>,
    heads_tx: broadcast::Sender<Arc<NewHead>>,
    delegation_sender: DelegationSender<E, F>,
}

impl LocalBuilderHandle {
    async fn send(&self, request: ServerRequestKind) -> BuilderResult<ServerResponse> {
        let (response_sender, response_receiver) = oneshot::channel();
        let begin_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_millis(0))
            .as_millis();

        let request = ServerRequest {
            request,
            response: response_sender,
        };
        self.req_sender
            .send(request)
            .await
            .map_err(|_| anyhow::anyhow!("LocalBuilderServer closed"))?;
        let response = response_receiver
            .await
            .map_err(|_| anyhow::anyhow!("LocalBuilderServer closed"))?;

        let end_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_millis(0))
            .as_millis();
        self.metric
            .send_duration
            .record((end_ms.saturating_sub(begin_ms)) as f64);
        response
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

    async fn debug_send_bundle_now(&self) -> BuilderResult<(B256, u64)> {
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

    async fn send_sponsored_delegation(&self, auth: Eip7702Auth) -> BuilderResult<B256> {
        let req = ServerRequestKind::SendSponsoredDelegation { auth };
        let resp = self.send(req).await?;
        match resp {
            ServerResponse::SendSponsoredDelegation { tx_hash } => Ok(tx_hash),
            _ => Err(BuilderError::UnexpectedResponse),
        }
    }
}

#[async_trait]
impl HealthCheck for LocalBuilderHandle {
    fn name(&self) -> &'static str {
        "LocalBuilderServer"
    }

    async fn status(&self) -> ServerStatus {
        match tokio::time::timeout(Duration::from_secs(1), self.get_supported_entry_points()).await
        {
            Ok(Ok(_)) => ServerStatus::Serving,
            Ok(Err(e)) => {
                tracing::error!(
                    "Healthcheck: failed to get supported entry points in builder: {e:?}"
                );
                ServerStatus::NotServing
            }
            _ => {
                tracing::error!("Healthcheck: timed out getting supported entry points in builder");
                ServerStatus::NotServing
            }
        }
    }
}

impl<E, F> LocalBuilderServerRunner<E, F>
where
    E: EvmProvider + Clone + Send + Sync + 'static,
    F: FeeEstimator + Clone + Send + Sync + 'static,
{
    fn new(
        req_receiver: mpsc::Receiver<ServerRequest>,
        bundle_sender_actions: Vec<mpsc::Sender<BundleSenderAction>>,
        entry_points: Vec<Address>,
        signer_manager: Arc<dyn SignerManager>,
        pool: Arc<dyn Pool>,
        heads_tx: broadcast::Sender<Arc<NewHead>>,
        delegation_sender: DelegationSender<E, F>,
    ) -> Self {
        Self {
            req_receiver,
            bundle_sender_actions,
            entry_points,
            signer_manager,
            pool,
            heads_tx,
            delegation_sender,
        }
    }

    async fn run(mut self, shutdown: GracefulShutdown) {
        let Ok(mut new_heads) = self.pool.subscribe_new_heads(vec![]).await else {
            tracing::error!("Failed to subscribe to new blocks");
            panic!("failed to subscribe to new blocks");
        };

        loop {
            tokio::select! {
                _ = shutdown.clone() => {
                    return;
                }
                new_head = new_heads.next() => {
                    let Some(new_head) = new_head else {
                        tracing::error!("new head stream closed");
                        panic!("new head stream closed");
                    };
                    if !new_head.address_updates.is_empty() {
                        tracing::info!("received new head with address updates: {:?}", new_head);
                        let balances = new_head.address_updates.iter().map(|update| (update.address, update.balance)).collect::<Vec<_>>();
                        self.signer_manager.update_balances(balances);
                    }
                }
                Some(req) = self.req_receiver.recv() => {
                    let resp: BuilderResult<ServerResponse> = match req.request {
                        // Async: spawned task owns the responder and sends when done.
                        // `continue` skips the response send at the bottom of the loop.
                        ServerRequestKind::SendSponsoredDelegation { auth } => {
                            let sender = self.delegation_sender.clone();
                            let heads_rx = self.heads_tx.subscribe();
                            let responder = req.response;
                            tokio::spawn(async move {
                                let resp = sender
                                    .send(auth, heads_rx)
                                    .await
                                    .map(|tx_hash| ServerResponse::SendSponsoredDelegation { tx_hash })
                                    .map_err(Into::into);
                                let _ = responder.send(resp);
                            });
                            continue;
                        }

                        // Sync: response sent below.
                        ServerRequestKind::GetSupportedEntryPoints => {
                            Ok(ServerResponse::GetSupportedEntryPoints {
                                entry_points: self.entry_points.clone()
                            })
                        },
                        ServerRequestKind::DebugSendBundleNow => {
                            if self.bundle_sender_actions.len() != 1 {
                                Err(anyhow::anyhow!("more than 1 bundle builder not supported in debug mode").into())
                            } else {
                                let (tx, rx) = oneshot::channel();
                                match self.bundle_sender_actions[0].send(BundleSenderAction::SendBundle(SendBundleRequest{
                                    responder: tx
                                })).await {
                                    Err(e) => Err(anyhow::anyhow!("failed to send send bundle request: {}", e.to_string()).into()),
                                    Ok(()) => match rx.await {
                                        Err(e) => Err(anyhow::anyhow!("failed to receive bundle result: {e:?}").into()),
                                        Ok(SendBundleResult::Success { tx_hash, block_number, .. }) => {
                                            Ok(ServerResponse::DebugSendBundleNow { hash: tx_hash, block_number })
                                        },
                                        Ok(SendBundleResult::NoOperationsInitially) => {
                                            Err(BuilderError::NoOperationsToSend)
                                        },
                                        Ok(SendBundleResult::Error(e)) => {
                                            Err(anyhow::anyhow!("send bundle error: {e:?}").into())
                                        },
                                    }
                                }
                            }
                        },
                        ServerRequestKind::DebugSetBundlingMode { mode } => {
                            if self.bundle_sender_actions.len() != 1 {
                                Err(anyhow::anyhow!("more than 1 bundle builder not supported in debug mode").into())
                            } else {
                                match self.bundle_sender_actions[0].send(BundleSenderAction::ChangeMode(mode)).await {
                                    Ok(()) => Ok(ServerResponse::DebugSetBundlingMode),
                                    Err(e) => Err(anyhow::anyhow!("failed to change bundler mode: {}", e.to_string()).into()),
                                }
                            }
                        },
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
    SendSponsoredDelegation { auth: Eip7702Auth },
}

#[derive(Debug)]
struct ServerRequest {
    request: ServerRequestKind,
    response: oneshot::Sender<BuilderResult<ServerResponse>>,
}

#[derive(Clone, Debug)]
enum ServerResponse {
    GetSupportedEntryPoints { entry_points: Vec<Address> },
    DebugSendBundleNow { hash: B256, block_number: u64 },
    DebugSetBundlingMode,
    SendSponsoredDelegation { tx_hash: B256 },
}
