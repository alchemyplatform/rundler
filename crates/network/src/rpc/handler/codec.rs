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

use std::{
    cmp,
    io::{self, Write},
};

use libp2p::bytes::{BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use super::{
    serde::{self, SszChunkResult},
    snappy::LengthPrefixedSnappyCodec,
};
use crate::rpc::{
    message::{Request, MAX_ERROR_MESSAGE_LEN},
    protocol::{Protocol, ProtocolSchema},
};

/// Error type for the codecs.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CodecError {
    #[error(transparent)]
    IoError(#[from] io::Error),
    #[error("Invalid schema for protocol")]
    InvalidSchema,
    #[error("Invalid data: {0}")]
    InvalidData(String),
    #[error("SSZ deserialize error {0:?}")]
    SszDeserializeError(ssz::DecodeError),
}

/// Inbound codec. Decodes inbound requests and encodes response chunks.
pub(crate) struct InboundCodec {
    protocol: Protocol,
    max_chunk_size: usize,
    inner: LengthPrefixedSnappyCodec,
}

impl InboundCodec {
    /// Create a new codec for a particular protocol.
    pub(crate) fn new(protocol: Protocol, max_chunk_size: usize) -> Self {
        let (min, max) = protocol.schema.ssz_request_limits();

        Self {
            protocol,
            max_chunk_size,
            inner: LengthPrefixedSnappyCodec::new(min, cmp::min(max, max_chunk_size)),
        }
    }
}

impl Encoder<SszChunkResult> for InboundCodec {
    type Error = CodecError;

    fn encode(&mut self, item: SszChunkResult, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let code = item.code();
        let bytes = serde::seraialize_response_chunk(item)?;
        let len = bytes.len();

        if (code > 0 && len > MAX_ERROR_MESSAGE_LEN)
            || ssz_response_length_invalid(len, self.protocol.schema, self.max_chunk_size)
        {
            return Err(CodecError::InvalidData(format!(
                "Invalid response length {}",
                len
            )));
        }

        // response code
        dst.writer().write_all(&[code])?;

        // snappy
        self.inner.encode(bytes, dst)?;

        Ok(())
    }
}

impl Decoder for InboundCodec {
    type Error = CodecError;
    type Item = Request;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.is_empty() {
            return Ok(None);
        }

        if let Some(buf) = self.inner.decode(src)? {
            let req = serde::deserialize_request(self.protocol.schema, &buf)?;
            Ok(Some(req))
        } else {
            Ok(None)
        }
    }
}

/// Outbound codec. Encodes outbound requests and decodes response chunk.
pub(crate) struct OutboundCodec {
    protocol: Protocol,
    max_chunk_size: usize,
    inner: LengthPrefixedSnappyCodec,
    inner_error: LengthPrefixedSnappyCodec,

    // decoder state
    response_code: Option<u8>,
}

impl OutboundCodec {
    /// Create a new codec for a particular protocol.
    pub(crate) fn new(protocol: Protocol, max_chunk_size: usize) -> Self {
        let (min, max) = protocol.schema.ssz_response_limits();

        Self {
            protocol,
            max_chunk_size,
            response_code: None,
            inner: LengthPrefixedSnappyCodec::new(min, cmp::min(max, max_chunk_size)),
            inner_error: LengthPrefixedSnappyCodec::new(0, MAX_ERROR_MESSAGE_LEN),
        }
    }
}

impl Encoder<Request> for OutboundCodec {
    type Error = CodecError;

    fn encode(&mut self, item: Request, dst: &mut BytesMut) -> Result<(), Self::Error> {
        // NOTE: assuming that the chunk type is valid for the protocol
        let bytes = serde::serialize_request(item)?;

        if ssz_request_length_invalid(bytes.len(), self.protocol.schema, self.max_chunk_size) {
            return Err(CodecError::InvalidData(format!(
                "Invalid request length {}",
                bytes.len()
            )));
        }

        // snappy
        // can use either codec since no length checking is done on encode
        self.inner.encode(bytes, dst)?;

        Ok(())
    }
}

impl Decoder for OutboundCodec {
    type Error = CodecError;
    type Item = SszChunkResult;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.is_empty() {
            return Ok(None);
        }

        // get the decoder for the response code
        let response_code = self.response_code.unwrap_or_else(|| {
            let response_code = src.split_to(1)[0];
            self.response_code = Some(response_code);
            response_code
        });

        if response_code > 0 {
            if let Some(buf) = self.inner_error.decode(src)? {
                let err = serde::deserialize_error_chunk(response_code, &buf)?;
                // reset the codec
                self.response_code.take();
                return Ok(Some(SszChunkResult::err(err)));
            }
        } else if let Some(buf) = self.inner.decode(src)? {
            let chunk = serde::deserialize_response_chunk(self.protocol.schema, &buf)?;
            // reset the codec
            self.response_code.take();
            return Ok(Some(SszChunkResult::ok(chunk)));
        }

        Ok(None)
    }
}

impl From<unsigned_varint::decode::Error> for CodecError {
    fn from(e: unsigned_varint::decode::Error) -> Self {
        CodecError::InvalidData(format!("Invalid unsigned varint: {:?}", e))
    }
}

fn ssz_request_length_invalid(
    length: usize,
    protocol: ProtocolSchema,
    max_chunk_size: usize,
) -> bool {
    let (min, max) = protocol.ssz_request_limits();
    length < min || length > cmp::min(max, max_chunk_size)
}

fn ssz_response_length_invalid(
    length: usize,
    protocol: ProtocolSchema,
    max_chunk_size: usize,
) -> bool {
    let (min, max) = protocol.ssz_response_limits();
    length < min || length > cmp::min(max, max_chunk_size)
}

#[cfg(test)]
mod test {
    use ethers::types::{Bytes, H256, U256};
    use rundler_types::UserOperation;

    use super::*;
    use crate::{
        rpc::{
            handler::serde::{CodedError, PooledUserOpsByHashChunkSsz, SszChunk},
            message::{
                ErrorKind, Goodbye, GoodbyeReason, Metadata, Ping, Pong, PooledUserOpHashesRequest,
                PooledUserOpHashesResponse, PooledUserOpsByHashRequest, ResponseError, Status,
            },
        },
        types::{Encoding, UserOperationSsz},
    };

    const MAX_CHUNK_SIZE: usize = 1048576;

    #[test]
    fn test_response_status() {
        let res = SszChunkResult::ok(SszChunk::Status(Status {
            supported_mempools: vec![H256::random()],
        }));
        let protocol = Protocol::new(ProtocolSchema::StatusV1, Encoding::SSZSnappy);
        encode_decode_response(res, protocol);
    }

    #[test]
    fn test_response_ping() {
        let res = SszChunkResult::ok(SszChunk::Ping(Pong {
            metadata_seq_number: 1,
        }));
        let protocol = Protocol::new(ProtocolSchema::PingV1, Encoding::SSZSnappy);
        encode_decode_response(res, protocol);
    }

    #[test]
    fn test_response_metadata() {
        let res = SszChunkResult::ok(SszChunk::Metadata(Metadata { seq_number: 1 }));
        let protocol = Protocol::new(ProtocolSchema::MetadataV1, Encoding::SSZSnappy);
        encode_decode_response(res, protocol);
    }

    #[test]
    fn test_response_pooled_user_op_hashes() {
        let res = SszChunkResult::ok(SszChunk::PooledUserOpHashes(PooledUserOpHashesResponse {
            more_flag: true,
            hashes: vec![H256::random()],
        }));
        let protocol = Protocol::new(ProtocolSchema::PooledUserOpHashesV1, Encoding::SSZSnappy);
        encode_decode_response(res, protocol);
    }

    #[test]
    fn test_response_pooled_user_ops_by_hash() {
        let res = SszChunkResult::ok(SszChunk::PooledUserOpsByHash(Box::new(
            PooledUserOpsByHashChunkSsz {
                user_op: user_op_ssz(),
            },
        )));
        let protocol = Protocol::new(ProtocolSchema::PooledUserOpsByHashV1, Encoding::SSZSnappy);
        encode_decode_response(res, protocol);
    }

    #[test]
    fn test_response_pooled_user_ops_by_hash_multiple() {
        let protocol = Protocol::new(ProtocolSchema::PooledUserOpsByHashV1, Encoding::SSZSnappy);
        let mut inbound = InboundCodec::new(protocol.clone(), MAX_CHUNK_SIZE);
        let mut outbound = OutboundCodec::new(protocol, MAX_CHUNK_SIZE);
        let mut buf = BytesMut::new();
        let mut results = vec![];

        for _ in 0..10 {
            let res = SszChunkResult::ok(SszChunk::PooledUserOpsByHash(Box::new(
                PooledUserOpsByHashChunkSsz {
                    user_op: user_op_ssz(),
                },
            )));
            inbound.encode(res.clone(), &mut buf).unwrap();
            results.push(res);
        }

        for result in results {
            let res = outbound.decode(&mut buf).unwrap().unwrap();
            assert_eq!(res, result);
        }
    }

    #[test]
    fn test_error_response() {
        let protocol = Protocol::new(ProtocolSchema::StatusV1, Encoding::SSZSnappy);
        let res = SszChunkResult::err(
            ResponseError {
                kind: ErrorKind::InvalidRequest,
                message: "this was an invalid request".into(),
            }
            .try_into()
            .unwrap(),
        );
        encode_decode_response(res, protocol);
    }

    #[test]
    fn test_encode_invalid_error_response() {
        let protocol = Protocol::new(ProtocolSchema::StatusV1, Encoding::SSZSnappy);
        let res = SszChunkResult::err(CodedError {
            code: 1,
            message: vec![0; MAX_ERROR_MESSAGE_LEN + 1],
        });
        let mut inbound = InboundCodec::new(protocol.clone(), MAX_CHUNK_SIZE);
        let mut buf = BytesMut::new();
        let err = inbound.encode(res.clone(), &mut buf).unwrap_err();
        assert!(matches!(err, CodecError::InvalidData(_)));
    }

    #[test]
    fn test_request_status() {
        let protocol = Protocol::new(ProtocolSchema::StatusV1, Encoding::SSZSnappy);

        let req = Request::Status(Status {
            supported_mempools: vec![H256::random()],
        });

        encode_decode_request(req, protocol);
    }

    #[test]
    fn test_request_ping() {
        let protocol = Protocol::new(ProtocolSchema::PingV1, Encoding::SSZSnappy);

        let req = Request::Ping(Ping {
            metadata_seq_number: 1,
        });
        encode_decode_request(req, protocol);
    }

    #[test]
    fn test_request_goodbye() {
        let protocol = Protocol::new(ProtocolSchema::GoodbyeV1, Encoding::SSZSnappy);

        let req = Request::Goodbye(Goodbye {
            reason: GoodbyeReason::ClientShutdown,
        });
        encode_decode_request(req, protocol);
    }

    #[test]
    fn test_request_pooled_user_op_hashes() {
        let protocol = Protocol::new(ProtocolSchema::PooledUserOpHashesV1, Encoding::SSZSnappy);

        let req = Request::PooledUserOpHashes(PooledUserOpHashesRequest {
            mempool: H256::random(),
            offset: 0,
        });
        encode_decode_request(req, protocol);
    }

    #[test]
    fn test_request_pooled_user_ops_by_hash() {
        let protocol = Protocol::new(ProtocolSchema::PooledUserOpsByHashV1, Encoding::SSZSnappy);

        let req = Request::PooledUserOpsByHash(PooledUserOpsByHashRequest {
            hashes: vec![H256::random()],
        });
        encode_decode_request(req, protocol);
    }

    fn encode_decode_response(chunk: SszChunkResult, protocol: Protocol) {
        let mut inbound = InboundCodec::new(protocol.clone(), MAX_CHUNK_SIZE);
        let mut outbound = OutboundCodec::new(protocol, MAX_CHUNK_SIZE);

        let mut buf = BytesMut::new();
        inbound.encode(chunk.clone(), &mut buf).unwrap();
        let resp = outbound.decode(&mut buf).unwrap();
        assert_eq!(resp, Some(chunk));
    }

    fn encode_decode_request(request: Request, protocol: Protocol) {
        let mut inbound = InboundCodec::new(protocol.clone(), MAX_CHUNK_SIZE);
        let mut outbound = OutboundCodec::new(protocol, MAX_CHUNK_SIZE);

        let mut buf = BytesMut::new();
        outbound.encode(request.clone(), &mut buf).unwrap();
        let req = inbound.decode(&mut buf).unwrap();
        assert_eq!(req, Some(request));
    }

    fn user_op_ssz() -> UserOperationSsz {
        UserOperation {
            sender: "0x0000000000000000000000000000000000000000"
                .parse()
                .unwrap(),
            nonce: U256::zero(),
            init_code: Bytes::default(),
            call_data: Bytes::default(),
            call_gas_limit: U256::zero(),
            verification_gas_limit: U256::zero(),
            pre_verification_gas: U256::zero(),
            max_fee_per_gas: U256::zero(),
            max_priority_fee_per_gas: U256::zero(),
            paymaster_and_data: Bytes::default(),
            signature: Bytes::default(),
        }
        .try_into()
        .unwrap()
    }
}
