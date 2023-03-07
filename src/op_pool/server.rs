use std::sync::Arc;

use super::mempool::{ExpectedStorageSlot, Mempool, OperationOrigin, PoolOperation};
use super::metrics::OpPoolMetrics;
use crate::common::protos::op_pool::op_pool_server::OpPool;
use crate::common::protos::op_pool::{
    AddOpRequest, AddOpResponse, DebugClearStateRequest, DebugClearStateResponse,
    DebugDumpMempoolRequest, DebugDumpMempoolResponse, DebugDumpReputationRequest,
    DebugDumpReputationResponse, DebugSetReputationRequest, DebugSetReputationResponse,
    GetOpsRequest, GetOpsResponse, GetSupportedEntryPointsRequest, GetSupportedEntryPointsResponse,
    MempoolOp, RemoveOpsRequest, RemoveOpsResponse, StorageSlot, UserOperation,
};
use crate::common::protos::{to_le_bytes, ProtoBytes, ProtoTimestampMillis};
use anyhow::Context;
use ethers::types::{Address, H256, U256};
use tonic::{async_trait, Request, Response};

pub struct OpPoolImpl<M: Mempool> {
    chain_id: U256,
    mempool: Arc<M>,
    metrics: OpPoolMetrics,
}

impl<M> OpPoolImpl<M>
where
    M: Mempool,
{
    pub fn new(chain_id: U256, mempool: Arc<M>) -> Self {
        Self {
            chain_id,
            metrics: OpPoolMetrics::default(),
            mempool,
        }
    }
}

#[async_trait]
impl<M> OpPool for OpPoolImpl<M>
where
    M: Mempool + 'static,
{
    async fn get_supported_entry_points(
        &self,
        _request: Request<GetSupportedEntryPointsRequest>,
    ) -> tonic::Result<Response<GetSupportedEntryPointsResponse>> {
        self.metrics.request_counter.increment(1);
        let mempool_ep = self.mempool.entry_point();
        let cid: [u8; 32] = self.chain_id.into();
        Ok(Response::new(GetSupportedEntryPointsResponse {
            chain_id: cid.to_vec(),
            entry_points: vec![mempool_ep.as_bytes().to_vec()],
        }))
    }

    async fn add_op(
        &self,
        request: Request<AddOpRequest>,
    ) -> tonic::Result<Response<AddOpResponse>> {
        self.metrics.request_counter.increment(1);

        let req = request.into_inner();
        Self::check_entry_point(&req.entry_point, self.mempool.entry_point())?;

        let proto_op = req.op.ok_or_else(|| {
            tonic::Status::invalid_argument("Operation is required in AddOpRequest")
        })?;

        let pool_op = proto_op.try_into().map_err(|e| {
            tonic::Status::invalid_argument(format!("Failed to parse operation: {e}"))
        })?;

        let hash = self
            .mempool
            .add_operation(OperationOrigin::Local, pool_op)
            .map_err(|e| {
                tonic::Status::internal(format!("Failed to add operation to mempool: {e}"))
            })?;

        Ok(Response::new(AddOpResponse {
            hash: hash.as_bytes().to_vec(),
        }))
    }

    async fn get_ops(
        &self,
        request: Request<GetOpsRequest>,
    ) -> tonic::Result<Response<GetOpsResponse>> {
        self.metrics.request_counter.increment(1);

        let req = request.into_inner();
        Self::check_entry_point(&req.entry_point, self.mempool.entry_point())?;

        let ops = self
            .mempool
            .best_operations(req.max_ops as usize)
            .iter()
            .map(|op| MempoolOp::try_from(&(**op)))
            .collect::<Result<Vec<MempoolOp>, _>>()
            .map_err(|e| {
                tonic::Status::internal(format!("Failed to convert to proto mempool op: {e}"))
            })?;

        Ok(Response::new(GetOpsResponse { ops }))
    }

    async fn remove_ops(
        &self,
        request: Request<RemoveOpsRequest>,
    ) -> tonic::Result<Response<RemoveOpsResponse>> {
        self.metrics.request_counter.increment(1);

        let req = request.into_inner();
        Self::check_entry_point(&req.entry_point, self.mempool.entry_point())?;

        let hashes: Vec<H256> = req
            .hashes
            .into_iter()
            .map(|h| {
                if h.len() != 32 {
                    return Err(tonic::Status::invalid_argument(
                        "Hash must be 32 bytes long",
                    ));
                }
                Ok(H256::from_slice(&h))
            })
            .collect::<Result<Vec<_>, _>>()?;

        self.mempool.remove_operations(&hashes);

        Ok(Response::new(RemoveOpsResponse {}))
    }

    async fn debug_clear_state(
        &self,
        _request: Request<DebugClearStateRequest>,
    ) -> tonic::Result<Response<DebugClearStateResponse>> {
        self.metrics.request_counter.increment(1);
        self.mempool.clear();
        Ok(Response::new(DebugClearStateResponse {}))
    }

    async fn debug_dump_mempool(
        &self,
        request: Request<DebugDumpMempoolRequest>,
    ) -> tonic::Result<Response<DebugDumpMempoolResponse>> {
        self.metrics.request_counter.increment(1);

        let req = request.into_inner();
        Self::check_entry_point(&req.entry_point, self.mempool.entry_point())?;

        let ops = self
            .mempool
            .best_operations(usize::MAX)
            .iter()
            .map(|op| MempoolOp::try_from(&(**op)))
            .collect::<Result<Vec<MempoolOp>, _>>()
            .map_err(|e| {
                tonic::Status::internal(format!("Failed to convert to proto mempool op: {e}"))
            })?;

        Ok(Response::new(DebugDumpMempoolResponse { ops }))
    }

    async fn debug_set_reputation(
        &self,
        request: Request<DebugSetReputationRequest>,
    ) -> tonic::Result<Response<DebugSetReputationResponse>> {
        self.metrics.request_counter.increment(1);

        let req = request.into_inner();
        Self::check_entry_point(&req.entry_point, self.mempool.entry_point())?;

        let rep = req.reputation.ok_or(tonic::Status::invalid_argument(
            "Reputation is required in DebugSetReputationRequest",
        ))?;

        let addr = ProtoBytes(&rep.address)
            .try_into()
            .map_err(|e| tonic::Status::invalid_argument(format!("Invalid address: {e}")))?;

        self.mempool
            .set_reputation(addr, rep.ops_seen, rep.ops_included);

        Ok(Response::new(DebugSetReputationResponse {}))
    }

    async fn debug_dump_reputation(
        &self,
        request: Request<DebugDumpReputationRequest>,
    ) -> tonic::Result<Response<DebugDumpReputationResponse>> {
        self.metrics.request_counter.increment(1);

        let req = request.into_inner();
        Self::check_entry_point(&req.entry_point, self.mempool.entry_point())?;

        let reps = self.mempool.dump_reputation();
        Ok(Response::new(DebugDumpReputationResponse {
            reputations: reps,
        }))
    }
}

impl<M> OpPoolImpl<M>
where
    M: Mempool,
{
    fn check_entry_point(req_entry_point: &[u8], pool_entry_point: Address) -> tonic::Result<()> {
        let req_ep: Address = ProtoBytes(req_entry_point)
            .try_into()
            .map_err(|e| tonic::Status::invalid_argument(format!("Invalid entry point: {e}")))?;
        if req_ep != pool_entry_point {
            return Err(tonic::Status::invalid_argument(format!(
                "Invalid entry point: {req_ep:?}, expected {pool_entry_point:?}"
            )));
        }

        Ok(())
    }
}

impl TryFrom<&PoolOperation> for MempoolOp {
    type Error = anyhow::Error;

    fn try_from(op: &PoolOperation) -> Result<Self, Self::Error> {
        Ok(MempoolOp {
            uo: Some(UserOperation::from(&op.uo)),
            aggregator: op.aggregator.map_or(vec![], |a| a.as_bytes().to_vec()),
            valid_after: op.valid_after.timestamp_millis().try_into()?,
            valid_until: op.valid_until.timestamp_millis().try_into()?,
            expected_code_hash: op.expected_code_hash.as_bytes().to_vec(),
            expected_storage_slots: op.expected_storage_slots.iter().map(|s| s.into()).collect(),
        })
    }
}

impl TryFrom<MempoolOp> for PoolOperation {
    type Error = anyhow::Error;

    fn try_from(op: MempoolOp) -> Result<Self, Self::Error> {
        let uo = op
            .uo
            .context("Mempool op should contain user operation")?
            .try_into()?;

        let aggregator: Option<Address> = if op.aggregator.is_empty() {
            None
        } else {
            Some(ProtoBytes(&op.aggregator).try_into()?)
        };

        let valid_after = ProtoTimestampMillis(op.valid_after).try_into()?;
        let valid_until = ProtoTimestampMillis(op.valid_until).try_into()?;

        let expected_storage_slots = op
            .expected_storage_slots
            .into_iter()
            .map(|s| s.try_into())
            .collect::<Result<Vec<_>, _>>()?;

        let expected_code_hash = H256::from_slice(&op.expected_code_hash);

        Ok(PoolOperation {
            uo,
            aggregator,
            valid_after,
            valid_until,
            expected_code_hash,
            expected_storage_slots,
        })
    }
}

impl TryFrom<StorageSlot> for ExpectedStorageSlot {
    type Error = anyhow::Error;

    fn try_from(ss: StorageSlot) -> Result<Self, Self::Error> {
        let address = ProtoBytes(&ss.address).try_into()?;
        let slot = ProtoBytes(&ss.slot).try_into()?;
        let expected_value = if ss.value.is_empty() {
            None
        } else {
            Some(ProtoBytes(&ss.value).try_into()?)
        };

        Ok(ExpectedStorageSlot {
            address,
            slot,
            expected_value,
        })
    }
}

impl From<&ExpectedStorageSlot> for StorageSlot {
    fn from(ess: &ExpectedStorageSlot) -> Self {
        StorageSlot {
            address: ess.address.as_bytes().to_vec(),
            slot: to_le_bytes(ess.slot),
            value: ess.expected_value.map_or(vec![], to_le_bytes),
        }
    }
}
