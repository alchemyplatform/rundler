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

use std::sync::Arc;

use alloy_primitives::{Address, B256};
use async_trait::async_trait;
use futures::future::BoxFuture;
use rundler_signer::SignerManager;
use rundler_task::{
    server::{HealthCheck, ServerStatus},
    GracefulShutdown, TaskSpawner,
};
use rundler_types::{
    builder::{Builder, BuilderError, BuilderResult, BundlingMode},
    chain::ChainSpec,
    pool::{NewHead, Pool},
};
use tokio::sync::{broadcast, mpsc, oneshot};

use super::builder::{
    self, BuilderRequest, BuilderRequestKind, BuilderResponse, BuilderServerArgs,
};
use crate::{factory::BundleSenderTaskFactoryT, BuilderSettings};

/// Local builder server builder
pub struct LocalBuilderBuilder {
    req_sender: mpsc::Sender<BuilderRequest>,
    req_receiver: mpsc::Receiver<BuilderRequest>,
    signer_manager: Arc<dyn SignerManager>,
    pool: Arc<dyn Pool>,
}

impl LocalBuilderBuilder {
    /// Create a new local builder server builder
    pub fn new(
        request_capcity: usize,
        signer_manager: Arc<dyn SignerManager>,
        pool: Arc<dyn Pool>,
    ) -> Self {
        let (req_sender, req_receiver) = mpsc::channel(request_capcity);
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
        }
    }

    /// Run the local builder server, consuming the builder
    pub(crate) fn run(
        self,
        task_spawner: Box<dyn TaskSpawner>,
        chain_spec: ChainSpec,
        entry_points: Vec<Address>,
        sender_factory: Box<dyn BundleSenderTaskFactoryT>,
        builders: Vec<BuilderSettings>,
        block_broadcaster: broadcast::Sender<NewHead>,
        shutdown: GracefulShutdown,
    ) -> BoxFuture<'static, ()> {
        let runner = BuilderServerArgs {
            task_spawner,
            req_receiver: self.req_receiver,
            entry_points,
            signer_manager: self.signer_manager,
            sender_factory,
            builders,
            pool: self.pool,
            shutdown,
            chain_spec,
            block_broadcaster,
        };
        Box::pin(builder::run_builder(runner))
    }
}

/// Local builder server handle, used to send requests to the server
#[derive(Debug, Clone)]
pub struct LocalBuilderHandle {
    req_sender: mpsc::Sender<BuilderRequest>,
}

impl LocalBuilderHandle {
    async fn send(&self, request: BuilderRequestKind) -> BuilderResult<BuilderResponse> {
        let (response_sender, response_receiver) = oneshot::channel();
        let request = BuilderRequest {
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
        let req = BuilderRequestKind::GetSupportedEntryPoints;
        let resp = self.send(req).await?;
        match resp {
            BuilderResponse::GetSupportedEntryPoints { entry_points } => Ok(entry_points),
            _ => Err(BuilderError::UnexpectedResponse),
        }
    }

    async fn debug_send_bundle_now(&self) -> BuilderResult<(B256, u64)> {
        let req = BuilderRequestKind::DebugSendBundleNow;
        let resp = self.send(req).await?;
        match resp {
            BuilderResponse::DebugSendBundleNow { hash, block_number } => Ok((hash, block_number)),
            _ => Err(BuilderError::UnexpectedResponse),
        }
    }

    async fn debug_set_bundling_mode(&self, mode: BundlingMode) -> BuilderResult<()> {
        let req = BuilderRequestKind::DebugSetBundlingMode { mode };
        let resp = self.send(req).await?;
        match resp {
            BuilderResponse::DebugSetBundlingMode => Ok(()),
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
        if self.get_supported_entry_points().await.is_ok() {
            ServerStatus::Serving
        } else {
            ServerStatus::NotServing
        }
    }
}
