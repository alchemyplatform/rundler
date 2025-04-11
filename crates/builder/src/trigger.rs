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

use anyhow::Context;
use rundler_types::pool::NewHead;
use tokio::sync::{broadcast, mpsc, oneshot};

use crate::bundle_sender::SendBundleResult;

pub(crate) fn new_trigger_channel(
    block_receiver: broadcast::Receiver<NewHead>,
) -> (TriggerSender, TriggerReceiver) {
    let (trigger, trigger_recv) = mpsc::channel(1);
    (
        TriggerSender { trigger },
        TriggerReceiver {
            trigger: trigger_recv,
            blocks: block_receiver,
        },
    )
}

pub(crate) struct TriggerSender {
    trigger: mpsc::Sender<oneshot::Sender<SendBundleResult>>,
}

pub(crate) struct TriggerReceiver {
    trigger: mpsc::Receiver<oneshot::Sender<SendBundleResult>>,
    blocks: broadcast::Receiver<NewHead>,
}

impl TriggerSender {
    pub(crate) fn trigger(&self, responder: oneshot::Sender<SendBundleResult>) -> bool {
        self.trigger.try_send(responder).is_ok()
    }
}

impl TriggerReceiver {
    pub(crate) async fn wait_for_trigger(
        &mut self,
    ) -> anyhow::Result<oneshot::Sender<SendBundleResult>> {
        self.trigger.recv().await.context("trigger stream closed")
    }

    pub(crate) fn consume_blocks(&mut self) -> anyhow::Result<Vec<NewHead>> {
        // Consume any other blocks that may have been buffered up
        let mut blocks = vec![];
        loop {
            match self.blocks.try_recv() {
                Ok(b) => {
                    blocks.push(b);
                }
                Err(broadcast::error::TryRecvError::Empty) => {
                    return Ok(blocks);
                }
                Err(broadcast::error::TryRecvError::Closed) => {
                    tracing::error!("Block stream closed");
                    anyhow::bail!("Block stream closed");
                }
                Err(broadcast::error::TryRecvError::Lagged(_)) => {
                    // This is fine, we can ignore it
                }
            }
        }
    }

    pub(crate) async fn wait_for_block(&mut self) -> anyhow::Result<NewHead> {
        self.blocks.recv().await.context("block stream closed")
    }
}
