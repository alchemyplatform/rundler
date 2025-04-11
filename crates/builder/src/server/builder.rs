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

use std::{sync::Arc, time::Duration};

use alloy_primitives::{Address, B256};
use futures_util::StreamExt;
use rundler_signer::SignerManager;
use rundler_task::GracefulShutdown;
use rundler_types::{
    builder::{BuilderResult, BundlingMode},
    chain::ChainSpec,
    pool::{NewHead, Pool},
};
use tokio::sync::{broadcast, mpsc, oneshot};

use crate::{bundle_sender::SendBundleResult, trigger::TriggerSender};

#[derive(Clone, Debug)]
pub(crate) enum BuilderRequestKind {
    GetSupportedEntryPoints,
    DebugSendBundleNow,
    DebugSetBundlingMode { mode: BundlingMode },
}

#[derive(Debug)]
pub(crate) struct BuilderRequest {
    pub(crate) request: BuilderRequestKind,
    pub(crate) response: oneshot::Sender<BuilderResult<BuilderResponse>>,
}

#[derive(Clone, Debug)]
pub(crate) enum BuilderResponse {
    GetSupportedEntryPoints { entry_points: Vec<Address> },
    DebugSendBundleNow { hash: B256, block_number: u64 },
    DebugSetBundlingMode,
}

pub(crate) struct BuilderSender {
    pub(crate) address: Address,
    pub(crate) trigger: TriggerSender,
}

pub(crate) struct BuilderServerArgs {
    pub(crate) req_receiver: mpsc::Receiver<BuilderRequest>,
    pub(crate) entry_points: Vec<Address>,
    pub(crate) signer_manager: Arc<dyn SignerManager>,
    pub(crate) pool: Arc<dyn Pool>,
    pub(crate) shutdown: GracefulShutdown,
    pub(crate) chain_spec: ChainSpec,
    pub(crate) senders: Vec<BuilderSender>,
    pub(crate) block_broadcaster: broadcast::Sender<NewHead>,
}

pub(crate) async fn run_builder(args: BuilderServerArgs) {
    let BuilderServerArgs {
        mut req_receiver,
        entry_points,
        signer_manager,
        pool,
        shutdown,
        chain_spec,
        mut senders,
        block_broadcaster,
    } = args;

    let mut timer = tokio::time::interval(Duration::from_millis(
        chain_spec.bundle_max_send_interval_millis,
    ));

    let Ok(mut new_heads) = pool
        .subscribe_new_heads(senders.iter().map(|s| s.address).collect())
        .await
    else {
        tracing::error!("Failed to subscribe to new blocks");
        panic!("failed to subscribe to new blocks");
    };

    let mut mode = BundlingMode::Auto;

    loop {
        timer.reset();

        tokio::select! {
            _ = shutdown.clone() => {
                return;
            }
            new_head = new_heads.next() => {
                let Some(new_head) = new_head else {
                    tracing::error!("new head stream closed");
                    panic!("new head stream closed");
                };

                tracing::info!("received new head: {:?}", new_head);
                let balances = new_head.address_updates.iter().map(|update| (update.address, update.balance)).collect();
                signer_manager.update_balances(balances);

                if let Err(e) = block_broadcaster.send(new_head) {
                    tracing::error!("failed to send new head: {:?}", e);
                }

                for sender in senders.iter_mut() {
                    if mode == BundlingMode::Auto {
                        sender.trigger.trigger(oneshot::channel().0);
                    }
                }
            }
            _ = timer.tick() => {
                if mode == BundlingMode::Manual {
                    continue;
                }

                for sender in senders.iter_mut() {
                    sender.trigger.trigger(oneshot::channel().0);
                }
            }
            Some(req) = req_receiver.recv() => {
                let resp: BuilderResult<BuilderResponse> = 'a:  {
                    match req.request {
                        BuilderRequestKind::GetSupportedEntryPoints => {
                            Ok(BuilderResponse::GetSupportedEntryPoints {
                                entry_points: entry_points.clone()
                            })
                        },
                        BuilderRequestKind::DebugSendBundleNow => {
                            if mode != BundlingMode::Manual {
                                break 'a Err(anyhow::anyhow!("bundler is not in manual mode").into())
                            }

                            let responses = senders.iter_mut().map(async |s| {
                                let (tx, rx) = oneshot::channel();
                                s.trigger.trigger(tx);
                                rx.await
                            }).collect::<Vec<_>>();

                            let results = futures::future::join_all(responses).await;
                            let Some(Ok(result)) = results.first() else {
                                break 'a Err(anyhow::anyhow!("no bundle sender results").into())
                            };

                            match result {
                                SendBundleResult::Success { tx_hash, block_number, .. } => {
                                    Ok(BuilderResponse::DebugSendBundleNow { hash: *tx_hash, block_number: *block_number })
                                },
                                SendBundleResult::NoOperationsInitially => {
                                    Err(anyhow::anyhow!("no ops to send").into())
                                },
                                SendBundleResult::Error(e) => Err(anyhow::anyhow!("send bundle error: {e:?}").into()),
                            }
                        },
                        BuilderRequestKind::DebugSetBundlingMode { mode: new_mode } => {
                            mode = new_mode;
                            Ok(BuilderResponse::DebugSetBundlingMode)
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
