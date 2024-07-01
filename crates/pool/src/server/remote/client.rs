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

use std::{pin::Pin, str::FromStr};

use anyhow::Context;
use ethers::types::{Address, H256};
use futures_util::Stream;
use rundler_task::{
    grpc::protos::{from_bytes, ConversionError, ToProtoBytes},
    server::{HealthCheck, ServerStatus},
};
use rundler_types::{
    chain::ChainSpec,
    pool::{
        NewHead, PaymasterMetadata, Pool, PoolError, PoolOperation, PoolResult, Reputation,
        ReputationStatus, StakeStatus,
    },
    EntityUpdate, UserOperationId, UserOperationVariant,
};
use rundler_utils::retry::{self, UnlimitedRetryOpts};
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
    self, add_op_response, admin_set_tracking_response, debug_clear_state_response,
    debug_dump_mempool_response, debug_dump_paymaster_balances_response,
    debug_dump_reputation_response, debug_set_reputation_response, get_op_by_hash_response,
    get_ops_response, get_reputation_status_response, get_stake_status_response,
    op_pool_client::OpPoolClient, remove_op_by_id_response, remove_ops_response,
    update_entities_response, AddOpRequest, AdminSetTrackingRequest, DebugClearStateRequest,
    DebugDumpMempoolRequest, DebugDumpPaymasterBalancesRequest, DebugDumpReputationRequest,
    DebugSetReputationRequest, GetOpsRequest, GetReputationStatusRequest, GetStakeStatusRequest,
    RemoveOpsRequest, ReputationStatus as ProtoReputationStatus, SubscribeNewHeadsRequest,
    SubscribeNewHeadsResponse, TryUoFromProto, UpdateEntitiesRequest,
};

/// Remote pool client
///
/// Used to submit requests to a remote pool server.
#[derive(Debug, Clone)]
pub struct RemotePoolClient {
    chain_spec: ChainSpec,
    op_pool_client: OpPoolClient<Channel>,
    op_pool_health: HealthClient<Channel>,
}

impl RemotePoolClient {
    /// Connect to a remote pool server, returning a client for submitting requests.
    pub async fn connect(url: String, chain_spec: ChainSpec) -> anyhow::Result<Self> {
        let op_pool_client = OpPoolClient::connect(url.clone()).await?;
        let op_pool_health =
            HealthClient::new(Channel::builder(Uri::from_str(&url)?).connect().await?);
        Ok(Self {
            chain_spec,
            op_pool_client,
            op_pool_health,
        })
    }

    // Handler for the new block subscription. This will attempt to resubscribe if the gRPC
    // connection disconnects using exponential backoff.
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
impl Pool for RemotePoolClient {
    async fn get_supported_entry_points(&self) -> PoolResult<Vec<Address>> {
        Ok(self
            .op_pool_client
            .clone()
            .get_supported_entry_points(protos::GetSupportedEntryPointsRequest {})
            .await
            .map_err(anyhow::Error::from)?
            .into_inner()
            .entry_points
            .into_iter()
            .map(|ep| from_bytes(ep.as_slice()))
            .collect::<Result<_, ConversionError>>()
            .map_err(anyhow::Error::from)?)
    }

    async fn add_op(&self, entry_point: Address, op: UserOperationVariant) -> PoolResult<H256> {
        let res = self
            .op_pool_client
            .clone()
            .add_op(AddOpRequest {
                entry_point: entry_point.as_bytes().to_vec(),
                op: Some(protos::UserOperation::from(&op)),
            })
            .await
            .map_err(anyhow::Error::from)?
            .into_inner()
            .result;

        match res {
            Some(add_op_response::Result::Success(s)) => Ok(H256::from_slice(&s.hash)),
            Some(add_op_response::Result::Failure(f)) => Err(f.try_into()?),
            None => Err(PoolError::Other(anyhow::anyhow!(
                "should have received result from op pool"
            )))?,
        }
    }

    async fn get_ops(
        &self,
        entry_point: Address,
        max_ops: u64,
        shard_index: u64,
    ) -> PoolResult<Vec<PoolOperation>> {
        let res = self
            .op_pool_client
            .clone()
            .get_ops(GetOpsRequest {
                entry_point: entry_point.as_bytes().to_vec(),
                max_ops,
                shard_index,
            })
            .await
            .map_err(anyhow::Error::from)?
            .into_inner()
            .result;

        match res {
            Some(get_ops_response::Result::Success(s)) => s
                .ops
                .into_iter()
                .map(|proto_uo| {
                    PoolOperation::try_uo_from_proto(proto_uo, &self.chain_spec)
                        .context("should convert proto uo to pool operation")
                })
                .map(|res| res.map_err(PoolError::from))
                .collect(),
            Some(get_ops_response::Result::Failure(f)) => Err(f.try_into()?),
            None => Err(PoolError::Other(anyhow::anyhow!(
                "should have received result from op pool"
            )))?,
        }
    }

    async fn get_op_by_hash(&self, hash: H256) -> PoolResult<Option<PoolOperation>> {
        let res = self
            .op_pool_client
            .clone()
            .get_op_by_hash(protos::GetOpByHashRequest {
                hash: hash.as_bytes().to_vec(),
            })
            .await
            .map_err(anyhow::Error::from)?
            .into_inner()
            .result;

        match res {
            Some(get_op_by_hash_response::Result::Success(s)) => Ok(s
                .op
                .map(|proto_uo| {
                    PoolOperation::try_uo_from_proto(proto_uo, &self.chain_spec)
                        .context("should convert proto uo to pool operation")
                })
                .transpose()?),
            Some(get_op_by_hash_response::Result::Failure(e)) => match e.error {
                Some(_) => Err(e.try_into()?),
                None => Err(PoolError::Other(anyhow::anyhow!(
                    "should have received error from op pool"
                )))?,
            },
            None => Err(PoolError::Other(anyhow::anyhow!(
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
            .await
            .map_err(anyhow::Error::from)?
            .into_inner()
            .result;

        match res {
            Some(remove_ops_response::Result::Success(_)) => Ok(()),
            Some(remove_ops_response::Result::Failure(f)) => Err(f.try_into()?),
            None => Err(PoolError::Other(anyhow::anyhow!(
                "should have received result from op pool"
            )))?,
        }
    }

    async fn remove_op_by_id(
        &self,
        entry_point: Address,
        id: UserOperationId,
    ) -> PoolResult<Option<H256>> {
        let res = self
            .op_pool_client
            .clone()
            .remove_op_by_id(protos::RemoveOpByIdRequest {
                entry_point: entry_point.to_proto_bytes(),
                sender: id.sender.to_proto_bytes(),
                nonce: id.nonce.to_proto_bytes(),
            })
            .await
            .map_err(anyhow::Error::from)?
            .into_inner()
            .result;

        match res {
            Some(remove_op_by_id_response::Result::Success(s)) => {
                if s.hash.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(H256::from_slice(&s.hash)))
                }
            }
            Some(remove_op_by_id_response::Result::Failure(f)) => Err(f.try_into()?),
            None => Err(PoolError::Other(anyhow::anyhow!(
                "should have received result from op pool"
            )))?,
        }
    }

    async fn update_entities(
        &self,
        entry_point: Address,
        entity_updates: Vec<EntityUpdate>,
    ) -> PoolResult<()> {
        let res = self
            .op_pool_client
            .clone()
            .update_entities(UpdateEntitiesRequest {
                entry_point: entry_point.as_bytes().to_vec(),
                entity_updates: entity_updates
                    .iter()
                    .map(protos::EntityUpdate::from)
                    .collect(),
            })
            .await
            .map_err(anyhow::Error::from)?
            .into_inner()
            .result;

        match res {
            Some(update_entities_response::Result::Success(_)) => Ok(()),
            Some(update_entities_response::Result::Failure(f)) => Err(f.try_into()?),
            None => Err(PoolError::Other(anyhow::anyhow!(
                "should have received result from op pool"
            )))?,
        }
    }

    async fn debug_clear_state(
        &self,
        clear_mempool: bool,
        clear_paymaster: bool,
        clear_reputation: bool,
    ) -> PoolResult<()> {
        let res = self
            .op_pool_client
            .clone()
            .debug_clear_state(DebugClearStateRequest {
                clear_mempool,
                clear_paymaster,
                clear_reputation,
            })
            .await
            .map_err(anyhow::Error::from)?
            .into_inner()
            .result;

        match res {
            Some(debug_clear_state_response::Result::Success(_)) => Ok(()),
            Some(debug_clear_state_response::Result::Failure(f)) => Err(f.try_into()?),
            None => Err(PoolError::Other(anyhow::anyhow!(
                "should have received result from op pool"
            )))?,
        }
    }

    async fn admin_set_tracking(
        &self,
        entry_point: Address,
        paymaster: bool,
        reputation: bool,
    ) -> PoolResult<()> {
        let res = self
            .op_pool_client
            .clone()
            .admin_set_tracking(AdminSetTrackingRequest {
                entry_point: entry_point.as_bytes().to_vec(),
                reputation,
                paymaster,
            })
            .await
            .map_err(anyhow::Error::from)?
            .into_inner()
            .result;

        match res {
            Some(admin_set_tracking_response::Result::Success(_)) => Ok(()),
            Some(admin_set_tracking_response::Result::Failure(f)) => Err(f.try_into()?),
            None => Err(PoolError::Other(anyhow::anyhow!(
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
            .await
            .map_err(anyhow::Error::from)?
            .into_inner()
            .result;

        match res {
            Some(debug_dump_mempool_response::Result::Success(s)) => s
                .ops
                .into_iter()
                .map(|proto_uo| {
                    PoolOperation::try_uo_from_proto(proto_uo, &self.chain_spec)
                        .context("should convert proto uo to pool operation")
                })
                .map(|res| res.map_err(PoolError::from))
                .collect(),
            Some(debug_dump_mempool_response::Result::Failure(f)) => Err(f.try_into()?),
            None => Err(PoolError::Other(anyhow::anyhow!(
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
            .await
            .map_err(anyhow::Error::from)?
            .into_inner()
            .result;

        match res {
            Some(debug_set_reputation_response::Result::Success(_)) => Ok(()),
            Some(debug_set_reputation_response::Result::Failure(f)) => Err(f.try_into()?),
            None => Err(PoolError::Other(anyhow::anyhow!(
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
            .await
            .map_err(anyhow::Error::from)?
            .into_inner()
            .result;

        match res {
            Some(debug_dump_reputation_response::Result::Success(s)) => s
                .reputations
                .into_iter()
                .map(Reputation::try_from)
                .map(|res| res.map_err(anyhow::Error::from).map_err(PoolError::from))
                .collect(),
            Some(debug_dump_reputation_response::Result::Failure(f)) => Err(f.try_into()?),
            None => Err(PoolError::Other(anyhow::anyhow!(
                "should have received result from op pool"
            )))?,
        }
    }

    async fn debug_dump_paymaster_balances(
        &self,
        entry_point: Address,
    ) -> PoolResult<Vec<PaymasterMetadata>> {
        let res = self
            .op_pool_client
            .clone()
            .debug_dump_paymaster_balances(DebugDumpPaymasterBalancesRequest {
                entry_point: entry_point.as_bytes().to_vec(),
            })
            .await
            .map_err(anyhow::Error::from)?
            .into_inner()
            .result;

        match res {
            Some(debug_dump_paymaster_balances_response::Result::Success(s)) => s
                .balances
                .into_iter()
                .map(PaymasterMetadata::try_from)
                .map(|res| res.map_err(anyhow::Error::from).map_err(PoolError::from))
                .collect(),
            Some(debug_dump_paymaster_balances_response::Result::Failure(f)) => Err(f.try_into()?),
            None => Err(PoolError::Other(anyhow::anyhow!(
                "should have received result from op pool"
            )))?,
        }
    }

    async fn get_reputation_status(
        &self,
        entry_point: Address,
        address: Address,
    ) -> PoolResult<ReputationStatus> {
        let res = self
            .op_pool_client
            .clone()
            .get_reputation_status(GetReputationStatusRequest {
                entry_point: entry_point.as_bytes().to_vec(),
                address: address.as_bytes().to_vec(),
            })
            .await
            .map_err(anyhow::Error::from)?
            .into_inner()
            .result;

        match res {
            Some(get_reputation_status_response::Result::Success(s)) => {
                Ok(ProtoReputationStatus::try_from(s.status)
                    .map_err(anyhow::Error::from)?
                    .try_into()
                    .map_err(anyhow::Error::from)?)
            }
            Some(get_reputation_status_response::Result::Failure(f)) => Err(f.try_into()?),
            None => Err(PoolError::Other(anyhow::anyhow!(
                "should have received result from op pool"
            )))?,
        }
    }

    async fn get_stake_status(
        &self,
        entry_point: Address,
        address: Address,
    ) -> PoolResult<StakeStatus> {
        let res = self
            .op_pool_client
            .clone()
            .get_stake_status(GetStakeStatusRequest {
                entry_point: entry_point.as_bytes().to_vec(),
                address: address.as_bytes().to_vec(),
            })
            .await
            .map_err(anyhow::Error::from)?
            .into_inner()
            .result;

        match res {
            Some(get_stake_status_response::Result::Success(s)) => {
                Ok(s.status.unwrap_or_default().try_into()?)
            }
            Some(get_stake_status_response::Result::Failure(f)) => Err(f.try_into()?),
            None => Err(PoolError::Other(anyhow::anyhow!(
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
