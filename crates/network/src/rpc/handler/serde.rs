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

use ethers::types::{Address, U256};
use rundler_types::UserOperation;
use ssz::{Decode, DecodeError, Encode};
use ssz_derive::{Decode, Encode};
use tracing::warn;

use crate::rpc::{
    handler::CodecError,
    message::{
        ErrorKind, Goodbye, Metadata, Ping, Pong, PooledUserOpHashesRequest,
        PooledUserOpHashesResponse, PooledUserOpsByHashRequest, PooledUserOpsByHashResponse,
        Request, Response, ResponseError, ResponseResult, Status, MAX_ERROR_MESSAGE_LEN,
        MAX_OPS_PER_REQUEST,
    },
    protocol::ProtocolSchema,
};

// TODO: determine what this actually should be
const MAX_SSZ_SIZE: usize = 1_048_576; // 1MB

/// Wrapper around a response chunk result
///
/// The result can be either a valid chunk or an error chunk
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SszChunkResult(Result<SszChunk, CodedError>);

/// Coded error for a response chunk
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CodedError {
    pub(crate) code: u8,
    pub(crate) message: Vec<u8>,
}

impl From<ResponseError> for CodedError {
    fn from(error: ResponseError) -> Self {
        let mut bytes = error.message.into_bytes();
        if bytes.len() > MAX_ERROR_MESSAGE_LEN {
            warn!("Error message is too long, truncating");
            bytes.truncate(MAX_ERROR_MESSAGE_LEN);
        };

        Self {
            code: error.kind.into(),
            message: bytes,
        }
    }
}

impl From<CodedError> for ResponseError {
    fn from(error: CodedError) -> Self {
        Self {
            kind: error.code.into(),
            message: String::from_utf8_lossy(&error.message).to_string(),
        }
    }
}

/// A chunk of a response
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum SszChunk {
    Status(Status),
    Ping(Pong),
    Metadata(Metadata),
    PooledUserOpHashes(PooledUserOpHashesResponse),
    // This response is much larger than the rest, to save space in the enum
    // we store it in a box.
    PooledUserOpsByHash(Box<PooledUserOpsByHashChunkSsz>),
}

impl SszChunkResult {
    /// Create a ok response chunk
    pub(crate) fn ok(chunk: SszChunk) -> Self {
        Self(Ok(chunk))
    }

    /// Create an error response chunk
    pub(crate) fn err(error: CodedError) -> Self {
        Self(Err(error))
    }

    /// The code associated with a response chunk
    pub(crate) fn code(&self) -> u8 {
        match self.0 {
            Ok(_) => 0,
            Err(CodedError {
                code: error_kind, ..
            }) => error_kind,
        }
    }
}

/// Create a response from a list of chunks for a given protocol schema.
pub(crate) fn response_from_chunks(
    schema: ProtocolSchema,
    mut chunks: Vec<SszChunkResult>,
) -> ResponseResult {
    if chunks.is_empty() || chunks.len() > schema.max_response_chunks() {
        return invalid_response("invalid number of chunks");
    }

    match schema {
        ProtocolSchema::StatusV1 => match chunks.pop().unwrap().0 {
            Ok(SszChunk::Status(status)) => Ok(Response::Status(status)),
            Ok(_) => invalid_response("wrong kind"),
            Err(err) => Err(err)?,
        },
        ProtocolSchema::GoodbyeV1 => invalid_response("goodbye is not a valid response"),
        ProtocolSchema::PingV1 => match chunks.pop().unwrap().0 {
            Ok(SszChunk::Ping(pong)) => Ok(Response::Ping(pong)),
            Ok(_) => invalid_response("wrong kind"),
            Err(err) => Err(err)?,
        },
        ProtocolSchema::MetadataV1 => match chunks.pop().unwrap().0 {
            Ok(SszChunk::Metadata(metadata)) => Ok(Response::Metadata(metadata)),
            Ok(_) => invalid_response("wrong kind"),
            Err(err) => Err(err)?,
        },
        ProtocolSchema::PooledUserOpHashesV1 => match chunks.pop().unwrap().0 {
            Ok(SszChunk::PooledUserOpHashes(hashes)) => Ok(Response::PooledUserOpHashes(hashes)),
            Ok(_) => invalid_response("wrong kind"),
            Err(err) => Err(err)?,
        },
        ProtocolSchema::PooledUserOpsByHashV1 => {
            let mut user_ops = Vec::new();
            for chunk in chunks {
                match chunk.0 {
                    Ok(SszChunk::PooledUserOpsByHash(chunk)) => match chunk.user_op.try_into() {
                        Ok(user_op) => user_ops.push(user_op),
                        Err(_) => return invalid_response("invalid user op"),
                    },
                    Ok(_) => return invalid_response("wrong kind"),
                    Err(err) => return Err(err.into()),
                }
            }
            Ok(Response::PooledUserOpsByHash(PooledUserOpsByHashResponse {
                user_ops,
            }))
        }
    }
}

fn invalid_response(message: &str) -> ResponseResult {
    Err(ResponseError {
        kind: ErrorKind::InvalidRequest,
        message: message.to_string(),
    })
}

/// Create a list of chunks from a response
pub(crate) fn chunks_from_response(
    response: ResponseResult,
) -> Result<Vec<SszChunkResult>, CodecError> {
    let res = match response {
        Ok(response) => match response {
            Response::Status(status) => {
                vec![SszChunkResult::ok(SszChunk::Status(status))]
            }
            Response::Metadata(metadata) => {
                vec![SszChunkResult::ok(SszChunk::Metadata(metadata))]
            }
            Response::Ping(pong) => {
                vec![SszChunkResult::ok(SszChunk::Ping(pong))]
            }
            Response::PooledUserOpHashes(hashes) => {
                vec![SszChunkResult::ok(SszChunk::PooledUserOpHashes(hashes))]
            }
            Response::PooledUserOpsByHash(r) => r
                .user_ops
                .into_iter()
                .map(|op| {
                    SszChunkResult::ok(SszChunk::PooledUserOpsByHash(Box::new(
                        PooledUserOpsByHashChunkSsz { user_op: op.into() },
                    )))
                })
                .collect(),
        },
        Err(error) => {
            vec![SszChunkResult::err(error.into())]
        }
    };
    Ok(res)
}

/// Serialize a request to bytes
pub(crate) fn serialize_request(request: Request) -> Result<Vec<u8>, CodecError> {
    match request {
        Request::Status(r) => Ok(r.as_ssz_bytes()),
        Request::Goodbye(r) => Ok(GoodbyeSsz::from(r).as_ssz_bytes()),
        Request::Ping(r) => Ok(r.as_ssz_bytes()),
        Request::Metadata => Err(CodecError::InvalidSchema),
        Request::PooledUserOpHashes(r) => Ok(r.as_ssz_bytes()),
        Request::PooledUserOpsByHash(r) => Ok(r.as_ssz_bytes()),
    }
}

/// Deserialize a request from bytes
pub(crate) fn deserialize_request(
    schema: ProtocolSchema,
    bytes: &[u8],
) -> Result<Request, CodecError> {
    match schema {
        ProtocolSchema::StatusV1 => Ok(Request::Status(Status::from_ssz_bytes(bytes)?)),
        ProtocolSchema::GoodbyeV1 => {
            let req = GoodbyeSsz::from_ssz_bytes(bytes)?;
            Ok(Request::Goodbye(req.into()))
        }
        ProtocolSchema::PingV1 => Ok(Request::Ping(Ping::from_ssz_bytes(bytes)?)),
        ProtocolSchema::MetadataV1 => Ok(Request::Metadata),
        ProtocolSchema::PooledUserOpHashesV1 => Ok(Request::PooledUserOpHashes(
            PooledUserOpHashesRequest::from_ssz_bytes(bytes)?,
        )),
        ProtocolSchema::PooledUserOpsByHashV1 => Ok(Request::PooledUserOpsByHash(
            PooledUserOpsByHashRequest::from_ssz_bytes(bytes)?,
        )),
    }
}

/// Serialize a response chunk to bytes
pub(crate) fn seraialize_response_chunk(chunk: SszChunkResult) -> Result<Vec<u8>, CodecError> {
    match chunk.0 {
        Ok(SszChunk::Status(r)) => Ok(r.as_ssz_bytes()),
        Ok(SszChunk::Ping(r)) => Ok(r.as_ssz_bytes()),
        Ok(SszChunk::Metadata(r)) => Ok(r.as_ssz_bytes()),
        Ok(SszChunk::PooledUserOpHashes(r)) => Ok(r.as_ssz_bytes()),
        Ok(SszChunk::PooledUserOpsByHash(r)) => Ok(r.as_ssz_bytes()),
        // only serialize the message portion of the error, the code is already written
        Err(error) => Ok(error.message.as_ssz_bytes()),
    }
}

/// Deserialize a response chunk from bytes for a given protocol schema
pub(crate) fn deserialize_response_chunk(
    schema: ProtocolSchema,
    bytes: &[u8],
) -> Result<SszChunk, CodecError> {
    match schema {
        ProtocolSchema::StatusV1 => Ok(SszChunk::Status(Status::from_ssz_bytes(bytes)?)),
        ProtocolSchema::GoodbyeV1 => Err(CodecError::InvalidSchema),
        ProtocolSchema::PingV1 => Ok(SszChunk::Ping(Pong::from_ssz_bytes(bytes)?)),
        ProtocolSchema::MetadataV1 => Ok(SszChunk::Metadata(Metadata::from_ssz_bytes(bytes)?)),
        ProtocolSchema::PooledUserOpHashesV1 => Ok(SszChunk::PooledUserOpHashes(
            PooledUserOpHashesResponse::from_ssz_bytes(bytes)?,
        )),
        ProtocolSchema::PooledUserOpsByHashV1 => Ok(SszChunk::PooledUserOpsByHash(Box::new(
            PooledUserOpsByHashChunkSsz::from_ssz_bytes(bytes)?,
        ))),
    }
}

/// Deserialize an error chunk from bytes
pub(crate) fn deserialize_error_chunk(code: u8, bytes: &[u8]) -> Result<CodedError, CodecError> {
    let bytes = Vec::<u8>::from_ssz_bytes(bytes)?;
    Ok(CodedError {
        code,
        message: bytes,
    })
}

#[derive(Debug, Default, Encode, Decode)]
struct GoodbyeSsz {
    reason: u64,
}

impl From<Goodbye> for GoodbyeSsz {
    fn from(request: Goodbye) -> Self {
        Self {
            reason: request.reason.into(),
        }
    }
}

impl From<GoodbyeSsz> for Goodbye {
    fn from(request: GoodbyeSsz) -> Self {
        Self {
            reason: request.reason.into(),
        }
    }
}

/// Response chunk for pooled user ops by hash
/// This is a wrapper around a user operation that implements ssz
#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub(crate) struct PooledUserOpsByHashChunkSsz {
    pub(crate) user_op: UserOperationSsz,
}

#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub(crate) struct UserOperationSsz {
    sender: Vec<u8>,
    nonce: U256,
    init_code: Vec<u8>,
    call_data: Vec<u8>,
    call_gas_limit: U256,
    verification_gas_limit: U256,
    pre_verification_gas: U256,
    max_fee_per_gas: U256,
    max_priority_fee_per_gas: U256,
    paymaster_and_data: Vec<u8>,
    signature: Vec<u8>,
}

impl From<UserOperation> for UserOperationSsz {
    fn from(uo: UserOperation) -> Self {
        Self {
            sender: uo.sender.as_bytes().to_vec(),
            nonce: uo.nonce,
            init_code: uo.init_code.to_vec(),
            call_data: uo.call_data.to_vec(),
            call_gas_limit: uo.call_gas_limit,
            verification_gas_limit: uo.verification_gas_limit,
            pre_verification_gas: uo.pre_verification_gas,
            max_fee_per_gas: uo.max_fee_per_gas,
            max_priority_fee_per_gas: uo.max_priority_fee_per_gas,
            paymaster_and_data: uo.paymaster_and_data.to_vec(),
            signature: uo.signature.to_vec(),
        }
    }
}

impl TryFrom<UserOperationSsz> for UserOperation {
    type Error = CodecError;

    fn try_from(uo_ssz: UserOperationSsz) -> Result<Self, Self::Error> {
        if uo_ssz.sender.len() != 20 {
            return Err(CodecError::InvalidData("invalid sender bytes".into()));
        }

        Ok(Self {
            sender: Address::from_slice(&uo_ssz.sender),
            nonce: uo_ssz.nonce,
            init_code: uo_ssz.init_code.into(),
            call_data: uo_ssz.call_data.into(),
            call_gas_limit: uo_ssz.call_gas_limit,
            verification_gas_limit: uo_ssz.verification_gas_limit,
            pre_verification_gas: uo_ssz.pre_verification_gas,
            max_fee_per_gas: uo_ssz.max_fee_per_gas,
            max_priority_fee_per_gas: uo_ssz.max_priority_fee_per_gas,
            paymaster_and_data: uo_ssz.paymaster_and_data.into(),
            signature: uo_ssz.signature.into(),
        })
    }
}

impl ProtocolSchema {
    pub(crate) fn ssz_request_limits(&self) -> (usize, usize) {
        match self {
            ProtocolSchema::StatusV1 => (0, MAX_SSZ_SIZE),
            ProtocolSchema::GoodbyeV1 => (
                <GoodbyeSsz as Encode>::ssz_fixed_len(),
                <GoodbyeSsz as Encode>::ssz_fixed_len(),
            ),
            ProtocolSchema::PingV1 => (
                <Ping as Encode>::ssz_fixed_len(),
                <Ping as Encode>::ssz_fixed_len(),
            ),
            ProtocolSchema::MetadataV1 => (0, 0),
            ProtocolSchema::PooledUserOpHashesV1 => (0, MAX_SSZ_SIZE),
            ProtocolSchema::PooledUserOpsByHashV1 => (0, MAX_SSZ_SIZE),
        }
    }

    pub(crate) fn ssz_response_limits(&self) -> (usize, usize) {
        match self {
            ProtocolSchema::StatusV1 => (0, MAX_SSZ_SIZE),
            ProtocolSchema::GoodbyeV1 => (0, 0),
            ProtocolSchema::PingV1 => (
                <Pong as Encode>::ssz_fixed_len(),
                <Pong as Encode>::ssz_fixed_len(),
            ),
            ProtocolSchema::MetadataV1 => (
                <Metadata as Encode>::ssz_fixed_len(),
                <Metadata as Encode>::ssz_fixed_len(),
            ),
            ProtocolSchema::PooledUserOpHashesV1 => (0, MAX_SSZ_SIZE),
            ProtocolSchema::PooledUserOpsByHashV1 => (0, MAX_SSZ_SIZE),
        }
    }

    pub(crate) fn max_response_chunks(&self) -> usize {
        match self {
            ProtocolSchema::StatusV1 => 1,
            ProtocolSchema::GoodbyeV1 => 1,
            ProtocolSchema::PingV1 => 1,
            ProtocolSchema::MetadataV1 => 1,
            ProtocolSchema::PooledUserOpHashesV1 => 1,
            ProtocolSchema::PooledUserOpsByHashV1 => MAX_OPS_PER_REQUEST,
        }
    }
}

impl From<DecodeError> for CodecError {
    fn from(err: DecodeError) -> Self {
        Self::SszDeserializeError(err)
    }
}

#[cfg(test)]
mod test {
    use ethers::types::H256;

    use super::*;

    #[test]
    fn test_status_response_chunk() {
        let resp = ResponseResult::Ok(Response::Status(Status {
            supported_mempools: vec![H256::random()],
        }));
        let chunks = chunks_from_response(resp.clone()).unwrap();
        assert_eq!(chunks.len(), 1);
        let resp_from_chunks = response_from_chunks(ProtocolSchema::StatusV1, chunks);
        assert_eq!(resp, resp_from_chunks);
    }

    #[test]
    fn test_ping_response_chunk() {
        let resp = ResponseResult::Ok(Response::Ping(Pong {
            metadata_seq_number: 1,
        }));
        let chunks = chunks_from_response(resp.clone()).unwrap();
        assert_eq!(chunks.len(), 1);
        let resp_from_chunks = response_from_chunks(ProtocolSchema::PingV1, chunks);
        assert_eq!(resp, resp_from_chunks);
    }

    #[test]
    fn test_metadata_response_chunk() {
        let resp = ResponseResult::Ok(Response::Metadata(Metadata { seq_number: 1 }));
        let chunks = chunks_from_response(resp.clone()).unwrap();
        assert_eq!(chunks.len(), 1);
        let resp_from_chunks = response_from_chunks(ProtocolSchema::MetadataV1, chunks);
        assert_eq!(resp, resp_from_chunks);
    }

    #[test]
    fn test_pooled_user_op_hashes_response_chunk() {
        let resp = ResponseResult::Ok(Response::PooledUserOpHashes(PooledUserOpHashesResponse {
            more_flag: false,
            hashes: vec![H256::random()],
        }));
        let chunks = chunks_from_response(resp.clone()).unwrap();
        assert_eq!(chunks.len(), 1);
        let resp_from_chunks = response_from_chunks(ProtocolSchema::PooledUserOpHashesV1, chunks);
        assert_eq!(resp, resp_from_chunks);
    }

    #[test]
    fn test_pooled_user_ops_by_hash_response_chunk() {
        let resp = ResponseResult::Ok(Response::PooledUserOpsByHash(PooledUserOpsByHashResponse {
            user_ops: vec![UserOperation::default(); 5],
        }));
        let chunks = chunks_from_response(resp.clone()).unwrap();
        assert_eq!(chunks.len(), 5);
        let resp_from_chunks = response_from_chunks(ProtocolSchema::PooledUserOpsByHashV1, chunks);
        assert_eq!(resp, resp_from_chunks);
    }

    #[test]
    fn test_error_response_chunk() {
        let resp = ResponseResult::Err(ResponseError {
            kind: ErrorKind::InvalidRequest,
            message: "invalid request".to_string(),
        });
        let chunks = chunks_from_response(resp.clone()).unwrap();
        assert_eq!(chunks.len(), 1);
        let resp_from_chunks = response_from_chunks(ProtocolSchema::StatusV1, chunks);
        assert_eq!(resp, resp_from_chunks);
    }

    #[test]
    fn test_error_after_ok_chunk() {
        let chunks = vec![
            SszChunkResult::ok(SszChunk::PooledUserOpsByHash(Box::new(
                PooledUserOpsByHashChunkSsz {
                    user_op: UserOperation::default().try_into().unwrap(),
                },
            ))),
            SszChunkResult::err(CodedError {
                code: 1,
                message: "invalid request".to_string().into_bytes(),
            }),
        ];
        let resp_from_chunks = response_from_chunks(ProtocolSchema::PooledUserOpsByHashV1, chunks);
        assert_eq!(
            resp_from_chunks,
            ResponseResult::Err(ResponseError {
                kind: ErrorKind::InvalidRequest,
                message: "invalid request".to_string(),
            })
        );
    }

    #[test]
    fn test_truncate_error() {
        let error = ResponseError {
            kind: ErrorKind::InvalidRequest,
            message: String::from_utf8(vec![b'X'; MAX_ERROR_MESSAGE_LEN * 2]).unwrap(),
        };

        let coded_error = CodedError::from(error);
        assert_eq!(coded_error.message.len(), MAX_ERROR_MESSAGE_LEN);
    }

    #[test]
    fn test_invalid_schema() {
        let chunk = SszChunkResult::ok(SszChunk::Metadata(Metadata { seq_number: 1 }));
        let err = response_from_chunks(ProtocolSchema::GoodbyeV1, vec![chunk]).unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidRequest);
    }

    #[test]
    fn test_empty_chunks() {
        let err = response_from_chunks(ProtocolSchema::StatusV1, vec![]).unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidRequest);
    }

    #[test]
    fn test_too_many_chunks() {
        let chunks = vec![
            SszChunkResult::ok(SszChunk::Status(Status {
                supported_mempools: vec![H256::random()],
            })),
            SszChunkResult::ok(SszChunk::Status(Status {
                supported_mempools: vec![H256::random()],
            })),
        ];
        let err = response_from_chunks(ProtocolSchema::StatusV1, chunks).unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidRequest);
    }

    #[test]
    fn test_too_many_ops() {
        let chunk = SszChunkResult::ok(SszChunk::PooledUserOpsByHash(Box::new(
            PooledUserOpsByHashChunkSsz {
                user_op: UserOperation::default().try_into().unwrap(),
            },
        )));
        let chunks = vec![chunk; MAX_OPS_PER_REQUEST + 1];
        let err = response_from_chunks(ProtocolSchema::PooledUserOpsByHashV1, chunks).unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidRequest);
    }
}
