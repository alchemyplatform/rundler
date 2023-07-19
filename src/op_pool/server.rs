use std::{collections::HashMap, sync::Arc};

use ethers::{
    types::{Address, H256},
    utils::to_checksum,
};
use prost::Message;
use tonic::{async_trait, Code, Request, Response, Result, Status};

use super::mempool::{error::MempoolError, Mempool, OperationOrigin};
use crate::common::protos::{
    self,
    op_pool::{
        op_pool_server::OpPool, AddOpRequest, AddOpResponse, DebugClearStateRequest,
        DebugClearStateResponse, DebugDumpMempoolRequest, DebugDumpMempoolResponse,
        DebugDumpReputationRequest, DebugDumpReputationResponse, DebugSetReputationRequest,
        DebugSetReputationResponse, ErrorInfo, ErrorMetadataKey, ErrorReason, GetOpsRequest,
        GetOpsResponse, GetSupportedEntryPointsRequest, GetSupportedEntryPointsResponse, MempoolOp,
        RemoveEntitiesRequest, RemoveEntitiesResponse, RemoveOpsRequest, RemoveOpsResponse,
    },
};

pub struct OpPoolImpl<M: Mempool> {
    chain_id: u64,
    mempools: HashMap<Address, Arc<M>>,
}

impl<M> OpPoolImpl<M>
where
    M: Mempool,
{
    pub fn new(chain_id: u64, mempools: HashMap<Address, Arc<M>>) -> Self {
        Self { chain_id, mempools }
    }

    fn get_mempool_for_entry_point(&self, req_entry_point: &[u8]) -> Result<&Arc<M>> {
        let req_ep: Address = protos::from_bytes(req_entry_point)
            .map_err(|e| Status::invalid_argument(format!("Invalid entry point: {e}")))?;
        let Some(mempool) = self.mempools.get(&req_ep) else {
            return Err(Status::invalid_argument(format!(
                "Entry point not supported: {req_ep:?}"
            )));
        };

        Ok(mempool)
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
    ) -> Result<Response<GetSupportedEntryPointsResponse>> {
        let entry_points = self
            .mempools
            .keys()
            .map(|k| k.as_bytes().to_vec())
            .collect();
        Ok(Response::new(GetSupportedEntryPointsResponse {
            chain_id: self.chain_id,
            entry_points,
        }))
    }

    async fn add_op(&self, request: Request<AddOpRequest>) -> Result<Response<AddOpResponse>> {
        let req = request.into_inner();
        let mempool = self.get_mempool_for_entry_point(&req.entry_point)?;

        let proto_op = req
            .op
            .ok_or_else(|| Status::invalid_argument("Operation is required in AddOpRequest"))?;

        let pool_op = proto_op
            .try_into()
            .map_err(|e| Status::invalid_argument(format!("Failed to parse operation: {e}")))?;

        let hash = mempool.add_operation(OperationOrigin::Local, pool_op)?;

        Ok(Response::new(AddOpResponse {
            hash: hash.as_bytes().to_vec(),
        }))
    }

    async fn get_ops(&self, request: Request<GetOpsRequest>) -> Result<Response<GetOpsResponse>> {
        let req = request.into_inner();
        let mempool = self.get_mempool_for_entry_point(&req.entry_point)?;

        let ops = mempool
            .best_operations(req.max_ops as usize)
            .iter()
            .map(|op| MempoolOp::try_from(&(**op)))
            .collect::<Result<Vec<MempoolOp>, _>>()
            .map_err(|e| Status::internal(format!("Failed to convert to proto mempool op: {e}")))?;

        Ok(Response::new(GetOpsResponse { ops }))
    }

    async fn remove_ops(
        &self,
        request: Request<RemoveOpsRequest>,
    ) -> Result<Response<RemoveOpsResponse>> {
        let req = request.into_inner();
        let mempool = self.get_mempool_for_entry_point(&req.entry_point)?;

        let hashes: Vec<H256> = req
            .hashes
            .into_iter()
            .map(|h| {
                if h.len() != 32 {
                    return Err(Status::invalid_argument("Hash must be 32 bytes long"));
                }
                Ok(H256::from_slice(&h))
            })
            .collect::<Result<Vec<_>, _>>()?;

        mempool.remove_operations(&hashes);

        Ok(Response::new(RemoveOpsResponse {}))
    }

    async fn remove_entities(
        &self,
        request: Request<RemoveEntitiesRequest>,
    ) -> Result<Response<RemoveEntitiesResponse>> {
        let req = request.into_inner();
        let mempool = self.get_mempool_for_entry_point(&req.entry_point)?;

        for entity in &req.entities {
            mempool.remove_entity(
                entity
                    .try_into()
                    .map_err(|e| Status::internal(format!("Failed to convert to entity: {e}")))?,
            );
        }

        Ok(Response::new(RemoveEntitiesResponse {}))
    }

    async fn debug_clear_state(
        &self,
        _request: Request<DebugClearStateRequest>,
    ) -> Result<Response<DebugClearStateResponse>> {
        self.mempools.values().for_each(|mempool| mempool.clear());
        Ok(Response::new(DebugClearStateResponse {}))
    }

    async fn debug_dump_mempool(
        &self,
        request: Request<DebugDumpMempoolRequest>,
    ) -> Result<Response<DebugDumpMempoolResponse>> {
        let req = request.into_inner();
        let mempool = self.get_mempool_for_entry_point(&req.entry_point)?;

        let ops = mempool
            .all_operations(usize::MAX)
            .iter()
            .map(|op| MempoolOp::try_from(&(**op)))
            .collect::<Result<Vec<MempoolOp>, _>>()
            .map_err(|e| Status::internal(format!("Failed to convert to proto mempool op: {e}")))?;

        Ok(Response::new(DebugDumpMempoolResponse { ops }))
    }

    async fn debug_set_reputation(
        &self,
        request: Request<DebugSetReputationRequest>,
    ) -> Result<Response<DebugSetReputationResponse>> {
        let req = request.into_inner();
        let mempool = self.get_mempool_for_entry_point(&req.entry_point)?;

        let reps = if req.reputations.is_empty() {
            return Err(Status::invalid_argument(
                "Reputation is required in DebugSetReputationRequest",
            ));
        } else {
            req.reputations
        };

        for rep in reps {
            let addr = protos::from_bytes(&rep.address)
                .map_err(|e| Status::invalid_argument(format!("Invalid address: {e}")))?;

            mempool.set_reputation(addr, rep.ops_seen, rep.ops_included);
        }

        Ok(Response::new(DebugSetReputationResponse {}))
    }

    async fn debug_dump_reputation(
        &self,
        request: Request<DebugDumpReputationRequest>,
    ) -> Result<Response<DebugDumpReputationResponse>> {
        let req = request.into_inner();
        let mempool = self.get_mempool_for_entry_point(&req.entry_point)?;

        let reps = mempool.dump_reputation();
        Ok(Response::new(DebugDumpReputationResponse {
            reputations: reps.into_iter().map(Into::into).collect(),
        }))
    }
}

impl From<MempoolError> for Status {
    fn from(e: MempoolError) -> Self {
        let ei = match &e {
            MempoolError::EntityThrottled(et) => ErrorInfo {
                reason: ErrorReason::EntityThrottled.as_str_name().to_string(),
                metadata: HashMap::from([(et.kind.to_string(), to_checksum(&et.address, None))]),
            },
            MempoolError::MaxOperationsReached(_, _) => ErrorInfo {
                reason: ErrorReason::OperationRejected.as_str_name().to_string(),
                metadata: HashMap::new(),
            },
            MempoolError::ReplacementUnderpriced(prio_fee, fee) => ErrorInfo {
                reason: ErrorReason::ReplacementUnderpriced
                    .as_str_name()
                    .to_string(),
                metadata: HashMap::from([
                    (
                        ErrorMetadataKey::CurrentMaxPriorityFeePerGas
                            .as_str_name()
                            .to_string(),
                        prio_fee.to_string(),
                    ),
                    (
                        ErrorMetadataKey::CurrentMaxFeePerGas
                            .as_str_name()
                            .to_string(),
                        fee.to_string(),
                    ),
                ]),
            },
            MempoolError::DiscardedOnInsert => ErrorInfo {
                reason: ErrorReason::OperationDiscardedOnInsert
                    .as_str_name()
                    .to_string(),
                metadata: HashMap::new(),
            },
            MempoolError::Other(_) => ErrorInfo {
                reason: ErrorReason::Unspecified.as_str_name().to_string(),
                metadata: HashMap::new(),
            },
        };

        let msg = e.to_string();
        let details = tonic_types::Status {
            // code and message are not used by the client
            code: 0,
            message: "".into(),
            details: vec![prost_types::Any {
                type_url: "type.alchemy.com/op_pool.ErrorInfo".to_string(),
                value: ei.encode_to_vec(),
            }],
        };

        Status::with_details(
            Code::FailedPrecondition,
            msg,
            details.encode_to_vec().into(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ADDRESS_ARR: [u8; 20] = [
        0x11, 0xAB, 0xB0, 0x5d, 0x9A, 0xd3, 0x18, 0xbf, 0x65, 0x65, 0x26, 0x72, 0xB1, 0x3b, 0x1d,
        0xcb, 0x0E, 0x6D, 0x4a, 0x32,
    ];

    use crate::{
        common::types::Entity,
        op_pool::{
            event::NewBlockEvent,
            mempool::{error::MempoolResult, PoolOperation},
            reputation::Reputation,
        },
    };

    #[test]
    fn test_check_entry_point() {
        let pool = given_oppool();
        let result = pool.get_mempool_for_entry_point(&TEST_ADDRESS_ARR);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_add_op_fails_with_mismatch_entry_point() {
        let oppool = given_oppool();
        let request = Request::new(AddOpRequest {
            entry_point: [0; 20].to_vec(),
            op: None,
        });

        let result = oppool.add_op(request).await;

        assert!(result.is_err());
        let result = result.unwrap_err();
        assert_eq!(result.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn test_add_op_fails_with_null_uop() {
        let oppool = given_oppool();
        let request = Request::new(AddOpRequest {
            entry_point: TEST_ADDRESS_ARR.to_vec(),
            op: None,
        });

        let result = oppool.add_op(request).await;

        assert!(result.is_err());
        let result = result.unwrap_err();
        assert_eq!(result.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn test_add_op_fails_with_bad_proto_op() {
        let oppool = given_oppool();
        let request = Request::new(AddOpRequest {
            entry_point: TEST_ADDRESS_ARR.to_vec(),
            op: Some(MempoolOp::default()),
        });

        let result = oppool.add_op(request).await;

        assert!(result.is_err());
        let result = result.unwrap_err();
        assert_eq!(result.code(), Code::InvalidArgument);
    }

    fn given_oppool() -> OpPoolImpl<MockMempool> {
        OpPoolImpl::<MockMempool>::new(
            1,
            HashMap::from([(TEST_ADDRESS_ARR.into(), MockMempool::default().into())]),
        )
    }

    pub struct MockMempool {
        entry_point: Address,
    }

    impl Default for MockMempool {
        fn default() -> Self {
            Self {
                entry_point: TEST_ADDRESS_ARR.into(),
            }
        }
    }

    impl Mempool for MockMempool {
        fn entry_point(&self) -> Address {
            self.entry_point
        }

        fn on_new_block(&self, _event: &NewBlockEvent) {}

        fn add_operation(
            &self,
            _origin: OperationOrigin,
            _opp: PoolOperation,
        ) -> MempoolResult<H256> {
            Ok(H256::zero())
        }

        fn add_operations(
            &self,
            _origin: OperationOrigin,
            _operations: impl IntoIterator<Item = PoolOperation>,
        ) -> Vec<MempoolResult<H256>> {
            vec![]
        }

        fn remove_operations<'a>(&self, _hashes: impl IntoIterator<Item = &'a H256>) {}

        fn remove_entity(&self, _entity: Entity) {}

        fn best_operations(&self, _max: usize) -> Vec<Arc<PoolOperation>> {
            vec![]
        }

        fn all_operations(&self, _max: usize) -> Vec<Arc<PoolOperation>> {
            vec![]
        }

        fn clear(&self) {}

        fn dump_reputation(&self) -> Vec<Reputation> {
            vec![]
        }

        fn set_reputation(&self, _address: Address, _ops_seenn: u64, _ops_included: u64) {}
    }
}
