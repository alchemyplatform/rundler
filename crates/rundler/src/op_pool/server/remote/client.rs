use std::{pin::Pin, str::FromStr};

use ethers::types::{Address, H256};
use futures_util::Stream;
use rundler_types::{Entity, UserOperation};
use tokio::sync::mpsc;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::{
    async_trait,
    transport::{Channel, Uri},
};
use tonic_health::{
    pb::{health_client::HealthClient, HealthCheckRequest},
    ServingStatus,
};

use super::protos::{
    self, add_op_response, debug_clear_state_response, debug_dump_mempool_response,
    debug_dump_reputation_response, debug_set_reputation_response, get_ops_response,
    op_pool_client::OpPoolClient, remove_entities_response, remove_ops_response, AddOpRequest,
    DebugClearStateRequest, DebugDumpMempoolRequest, DebugDumpReputationRequest,
    DebugSetReputationRequest, GetOpsRequest, RemoveEntitiesRequest, RemoveOpsRequest,
    SubscribeNewHeadsRequest, SubscribeNewHeadsResponse,
};
use crate::{
    common::{
        protos::{from_bytes, ConversionError},
        retry::{self, UnlimitedRetryOpts},
        server::{HealthCheck, ServerStatus},
    },
    op_pool::{
        mempool::{PoolOperation, Reputation},
        server::{error::PoolServerError, NewHead, PoolServer},
        PoolResult,
    },
};

#[derive(Debug, Clone)]
pub struct RemotePoolClient {
    op_pool_client: OpPoolClient<Channel>,
    op_pool_health: HealthClient<Channel>,
}

impl RemotePoolClient {
    pub async fn connect(url: String) -> anyhow::Result<Self> {
        let op_pool_client = OpPoolClient::connect(url.clone()).await?;
        let op_pool_health =
            HealthClient::new(Channel::builder(Uri::from_str(&url)?).connect().await?);
        Ok(Self {
            op_pool_client,
            op_pool_health,
        })
    }

    // Handler for the new block subscription. This will attempt to resubscribe if the gRPC
    // connection disconnects using expenential backoff.
    async fn new_heads_subscription_handler(
        client: OpPoolClient<Channel>,
        tx: mpsc::UnboundedSender<NewHead>,
    ) {
        let mut stream = None;

        loop {
            if stream.is_none() {
                stream = Some(
                    retry::with_unlimited_retries(
                        "subscribe new heads",
                        || {
                            let mut c = client.clone();
                            async move { c.subscribe_new_heads(SubscribeNewHeadsRequest {}).await }
                        },
                        UnlimitedRetryOpts::default(),
                    )
                    .await
                    .into_inner(),
                );
            }

            match stream.as_mut().unwrap().message().await {
                Ok(Some(SubscribeNewHeadsResponse { new_head: Some(b) })) => match b.try_into() {
                    Ok(new_head) => {
                        if tx.send(new_head).is_err() {
                            // recv handle dropped
                            return;
                        }
                    }
                    Err(e) => {
                        tracing::error!("error parsing new block: {:?}", e);
                        break;
                    }
                },
                Ok(Some(SubscribeNewHeadsResponse { new_head: None })) | Ok(None) => {
                    tracing::debug!("block subscription closed");
                    stream.take();
                    break;
                }
                Err(e) => {
                    tracing::error!("error in new block subscription: {:?}", e);
                    stream.take();
                    break;
                }
            }
        }
    }
}

#[async_trait]
impl PoolServer for RemotePoolClient {
    async fn get_supported_entry_points(&self) -> PoolResult<Vec<Address>> {
        Ok(self
            .op_pool_client
            .clone()
            .get_supported_entry_points(protos::GetSupportedEntryPointsRequest {})
            .await?
            .into_inner()
            .entry_points
            .into_iter()
            .map(|ep| from_bytes(ep.as_slice()))
            .collect::<Result<_, ConversionError>>()?)
    }

    async fn add_op(&self, entry_point: Address, op: UserOperation) -> PoolResult<H256> {
        let res = self
            .op_pool_client
            .clone()
            .add_op(AddOpRequest {
                entry_point: entry_point.as_bytes().to_vec(),
                op: Some(protos::UserOperation::from(&op)),
            })
            .await?
            .into_inner()
            .result;

        match res {
            Some(add_op_response::Result::Success(s)) => Ok(H256::from_slice(&s.hash)),
            Some(add_op_response::Result::Failure(f)) => Err(f.try_into()?),
            None => Err(PoolServerError::Other(anyhow::anyhow!(
                "should have received result from op pool"
            )))?,
        }
    }

    async fn get_ops(&self, entry_point: Address, max_ops: u64) -> PoolResult<Vec<PoolOperation>> {
        let res = self
            .op_pool_client
            .clone()
            .get_ops(GetOpsRequest {
                entry_point: entry_point.as_bytes().to_vec(),
                max_ops,
            })
            .await?
            .into_inner()
            .result;

        match res {
            Some(get_ops_response::Result::Success(s)) => s
                .ops
                .into_iter()
                .map(PoolOperation::try_from)
                .map(|res| res.map_err(PoolServerError::from))
                .collect(),
            Some(get_ops_response::Result::Failure(f)) => Err(f.try_into()?),
            None => Err(PoolServerError::Other(anyhow::anyhow!(
                "should have received result from op pool"
            )))?,
        }
    }

    async fn remove_ops(&self, entry_point: Address, ops: Vec<H256>) -> PoolResult<()> {
        let res = self
            .op_pool_client
            .clone()
            .remove_ops(RemoveOpsRequest {
                entry_point: entry_point.as_bytes().to_vec(),
                hashes: ops.into_iter().map(|h| h.as_bytes().to_vec()).collect(),
            })
            .await?
            .into_inner()
            .result;

        match res {
            Some(remove_ops_response::Result::Success(_)) => Ok(()),
            Some(remove_ops_response::Result::Failure(f)) => Err(f.try_into()?),
            None => Err(PoolServerError::Other(anyhow::anyhow!(
                "should have received result from op pool"
            )))?,
        }
    }

    async fn remove_entities(&self, entry_point: Address, entities: Vec<Entity>) -> PoolResult<()> {
        let res = self
            .op_pool_client
            .clone()
            .remove_entities(RemoveEntitiesRequest {
                entry_point: entry_point.as_bytes().to_vec(),
                entities: entities.iter().map(protos::Entity::from).collect(),
            })
            .await?
            .into_inner()
            .result;

        match res {
            Some(remove_entities_response::Result::Success(_)) => Ok(()),
            Some(remove_entities_response::Result::Failure(f)) => Err(f.try_into()?),
            None => Err(PoolServerError::Other(anyhow::anyhow!(
                "should have received result from op pool"
            )))?,
        }
    }

    async fn debug_clear_state(&self) -> PoolResult<()> {
        let res = self
            .op_pool_client
            .clone()
            .debug_clear_state(DebugClearStateRequest {})
            .await?
            .into_inner()
            .result;

        match res {
            Some(debug_clear_state_response::Result::Success(_)) => Ok(()),
            Some(debug_clear_state_response::Result::Failure(f)) => Err(f.try_into()?),
            None => Err(PoolServerError::Other(anyhow::anyhow!(
                "should have received result from op pool"
            )))?,
        }
    }

    async fn debug_dump_mempool(&self, entry_point: Address) -> PoolResult<Vec<PoolOperation>> {
        let res = self
            .op_pool_client
            .clone()
            .debug_dump_mempool(DebugDumpMempoolRequest {
                entry_point: entry_point.as_bytes().to_vec(),
            })
            .await?
            .into_inner()
            .result;

        match res {
            Some(debug_dump_mempool_response::Result::Success(s)) => s
                .ops
                .into_iter()
                .map(PoolOperation::try_from)
                .map(|res| res.map_err(PoolServerError::from))
                .collect(),
            Some(debug_dump_mempool_response::Result::Failure(f)) => Err(f.try_into()?),
            None => Err(PoolServerError::Other(anyhow::anyhow!(
                "should have received result from op pool"
            )))?,
        }
    }

    async fn debug_set_reputations(
        &self,
        entry_point: Address,
        reputations: Vec<Reputation>,
    ) -> PoolResult<()> {
        let res = self
            .op_pool_client
            .clone()
            .debug_set_reputation(DebugSetReputationRequest {
                entry_point: entry_point.as_bytes().to_vec(),
                reputations: reputations
                    .into_iter()
                    .map(protos::Reputation::from)
                    .collect(),
            })
            .await?
            .into_inner()
            .result;

        match res {
            Some(debug_set_reputation_response::Result::Success(_)) => Ok(()),
            Some(debug_set_reputation_response::Result::Failure(f)) => Err(f.try_into()?),
            None => Err(PoolServerError::Other(anyhow::anyhow!(
                "should have received result from op pool"
            )))?,
        }
    }

    async fn debug_dump_reputation(&self, entry_point: Address) -> PoolResult<Vec<Reputation>> {
        let res = self
            .op_pool_client
            .clone()
            .debug_dump_reputation(DebugDumpReputationRequest {
                entry_point: entry_point.as_bytes().to_vec(),
            })
            .await?
            .into_inner()
            .result;

        match res {
            Some(debug_dump_reputation_response::Result::Success(s)) => s
                .reputations
                .into_iter()
                .map(Reputation::try_from)
                .map(|res| res.map_err(PoolServerError::from))
                .collect(),
            Some(debug_dump_reputation_response::Result::Failure(f)) => Err(f.try_into()?),
            None => Err(PoolServerError::Other(anyhow::anyhow!(
                "should have received result from op pool"
            )))?,
        }
    }

    async fn subscribe_new_heads(&self) -> PoolResult<Pin<Box<dyn Stream<Item = NewHead> + Send>>> {
        let (tx, rx) = mpsc::unbounded_channel();
        let client = self.op_pool_client.clone();

        tokio::spawn(Self::new_heads_subscription_handler(client, tx));
        Ok(Box::pin(UnboundedReceiverStream::new(rx)))
    }
}

#[async_trait]
impl HealthCheck for RemotePoolClient {
    fn name(&self) -> &'static str {
        "RemotePoolServer"
    }

    async fn status(&self) -> ServerStatus {
        self.op_pool_health
            .clone()
            .check(HealthCheckRequest::default())
            .await
            .ok()
            .filter(|status| status.get_ref().status == ServingStatus::Serving as i32)
            .map(|_| ServerStatus::Serving)
            .unwrap_or(ServerStatus::NotServing)
    }
}
