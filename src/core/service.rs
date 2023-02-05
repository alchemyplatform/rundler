use crate::common::protos::core::core_server::Core;
use crate::common::protos::core::op_error::{OpErrorCase, OutOfTimeRange};
use crate::common::protos::core::{
    send_op_response, EstimateGasRequest, EstimateGasResponse, GetEntryPointsRequest,
    GetEntryPointsResponse, GetOpByHashRequest, GetOpByHashResponse, GetOpReceiptRequest,
    GetOpReceiptResponse, OpError, SendOpRequest, SendOpResponse,
};
use crate::common::types::UserOperation;
use tonic::{async_trait, Request, Response, Status};

pub struct CoreImpl;

#[async_trait]
impl Core for CoreImpl {
    async fn send_op(
        &self,
        request: Request<SendOpRequest>,
    ) -> tonic::Result<Response<SendOpResponse>> {
        let op: UserOperation = request.into_inner().op.unwrap_or_default().into();
        println!("{op:#?}");
        // Example of what responses look like.
        // Protobufs make things a smidge verbose. Sad. I wish oneof could be
        // an entire message by itself instead of needing to be a field.
        let response = SendOpResponse {
            result: Some(send_op_response::Result::Err(OpError {
                op_error_case: Some(OpErrorCase::OutOfTimeRange(OutOfTimeRange {
                    valid_after: 0,
                    valid_until: 0,
                    paymaster: vec![],
                })),
            })),
        };
        Ok(Response::new(response))
    }

    async fn estimate_op_gas(
        &self,
        _request: Request<EstimateGasRequest>,
    ) -> Result<Response<EstimateGasResponse>, Status> {
        todo!()
    }

    async fn get_op_by_hash(
        &self,
        _request: Request<GetOpByHashRequest>,
    ) -> Result<Response<GetOpByHashResponse>, Status> {
        todo!()
    }

    async fn get_op_receipt(
        &self,
        _request: Request<GetOpReceiptRequest>,
    ) -> Result<Response<GetOpReceiptResponse>, Status> {
        todo!()
    }

    async fn get_entry_points(
        &self,
        _request: Request<GetEntryPointsRequest>,
    ) -> Result<Response<GetEntryPointsResponse>, Status> {
        todo!()
    }
}
