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

use std::{collections::VecDeque, sync::Arc, time::Duration};

use alloy_primitives::{Address, B256};
use futures::FutureExt;
use futures_util::StreamExt;
use rundler_signer::SignerManager;
use rundler_task::{GracefulShutdown, TaskSpawner};
use rundler_types::{
    builder::{BuilderResult, BundlingMode},
    chain::ChainSpec,
    pool::{NewHead, Pool},
};
use tokio::sync::{broadcast, mpsc, oneshot};

use crate::{
    assigner::Assigner, bundle_sender::SendBundleResult, factory::BundleSenderTaskFactoryT,
    BuilderSettings,
};

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

pub(crate) struct BuilderServerArgs {
    pub(crate) task_spawner: Box<dyn TaskSpawner>,
    pub(crate) req_receiver: mpsc::Receiver<BuilderRequest>,
    pub(crate) entry_points: Vec<Address>,
    pub(crate) signer_manager: Arc<dyn SignerManager>,
    pub(crate) sender_factory: Box<dyn BundleSenderTaskFactoryT>,
    pub(crate) builders: Vec<BuilderSettings>,
    pub(crate) pool: Arc<dyn Pool>,
    pub(crate) shutdown: GracefulShutdown,
    pub(crate) chain_spec: ChainSpec,
    pub(crate) block_broadcaster: broadcast::Sender<NewHead>,
}

pub(crate) async fn run_builder(args: BuilderServerArgs) {
    let BuilderServerArgs {
        task_spawner,
        mut req_receiver,
        entry_points,
        signer_manager,
        sender_factory,
        builders,
        pool,
        shutdown,
        chain_spec,
        block_broadcaster,
    } = args;

    let mut timer = tokio::time::interval(Duration::from_millis(
        chain_spec.bundle_max_send_interval_millis,
    ));

    let Ok(mut new_heads) = pool.subscribe_new_heads(signer_manager.addresses()).await else {
        tracing::error!("Failed to subscribe to new blocks");
        panic!("failed to subscribe to new blocks");
    };

    let mut mode = BundlingMode::Auto;
    let mut last_block_number = 0;

    tracing::info!("Builders {:?}", builders);
    let mut builder_queue = VecDeque::from(builders);

    let assigner = Assigner::new(pool.clone());

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

                for update in &new_head.address_updates {
                    // TODO make sure this is the latest nonce from the transaction tracker
                    assigner.release_all_operations(update.address);
                }

                last_block_number = new_head.block_number;
                let _ = block_broadcaster.send(new_head);
            }
            _ = timer.tick() => {
                tracing::info!("tick: num available signers: {:?}", signer_manager.available());
                if mode == BundlingMode::Auto {
                    if let Err(e) = trigger_bundles(&assigner, &mut builder_queue, signer_manager.clone(), sender_factory.as_ref(), last_block_number, &block_broadcaster, task_spawner.as_ref(), None).await {
                        tracing::error!("failed to trigger bundles: {:?}", e);
                    }
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
                            } else if builder_queue.len() > 1 {
                                tracing::warn!("builder queue has more than one builder, only one result will be reported");
                            }

                            let (tx, rx) = oneshot::channel();
                            if let Err(e) = trigger_bundles( &assigner, &mut builder_queue, signer_manager.clone(), sender_factory.as_ref(), last_block_number, &block_broadcaster, task_spawner.as_ref(), Some(tx)).await {
                                tracing::error!("failed to trigger bundles: {:?}", e);
                            }

                            match rx.await {
                                Ok(SendBundleResult::Success { tx_hash, block_number, .. }) => {
                                    Ok(BuilderResponse::DebugSendBundleNow { hash: tx_hash, block_number })
                                },
                                Ok(SendBundleResult::NoOperationsInitially) => {
                                    Err(anyhow::anyhow!("no ops to send").into())
                                },
                                Ok(SendBundleResult::Cancelled) => {
                                    Err(anyhow::anyhow!("bundle cancelled").into())
                                },
                                Ok(SendBundleResult::CancelFailed) => {
                                    Err(anyhow::anyhow!("bundle cancel failed").into())
                                },
                                Ok(SendBundleResult::Error(e)) => Err(anyhow::anyhow!("send bundle error: {e:?}").into()),
                                Err(e) => Err(anyhow::anyhow!("failed to receive result: {:?}", e).into()),
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

async fn trigger_bundles(
    assigner: &Assigner,
    builder_queue: &mut VecDeque<BuilderSettings>,
    signer_manager: Arc<dyn SignerManager>,
    sender_factory: &dyn BundleSenderTaskFactoryT,
    last_block_number: u64,
    block_broadcaster: &broadcast::Sender<NewHead>,
    task_spawner: &dyn TaskSpawner,
    mut result_responder: Option<oneshot::Sender<SendBundleResult>>,
) -> anyhow::Result<usize> {
    let mut triggered_count = 0;
    let max_to_trigger = builder_queue.len();

    while let Some(builder) = builder_queue.pop_front() {
        let Some(signer) = signer_manager.lease_signer() else {
            tracing::warn!("no signer available");
            builder_queue.push_front(builder);
            return Ok(triggered_count);
        };
        tracing::info!("signer: {:?}", signer);
        let cloned_lease = signer.clone();

        let Ok(sender) = sender_factory
            .new_task(
                last_block_number,
                block_broadcaster.subscribe(),
                assigner.clone(),
                signer,
                &builder,
            )
            .await
        else {
            builder_queue.push_back(builder);
            anyhow::bail!("failed to create sender task");
        };
        builder_queue.push_back(builder);

        // TODO capture results and return signer lease
        let cloned_manager = signer_manager.clone();
        let result_responder = result_responder.take();
        task_spawner.spawn(
            async move {
                let result = sender.await;
                tracing::info!("sender task result: {:?}", result);
                // TODO we need to make sure this happens regardless of panics
                cloned_manager.return_lease(cloned_lease);
                if let Some(responder) = result_responder {
                    if let Err(e) = responder.send(result) {
                        tracing::error!("failed to send result: {:?}", e);
                    }
                }
            }
            .boxed(),
        );

        triggered_count += 1;
        if triggered_count >= max_to_trigger {
            break;
        }
    }

    Ok(triggered_count)
}
