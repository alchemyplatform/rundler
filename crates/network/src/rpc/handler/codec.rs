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
    io::{self, Read, Write},
};

use libp2p::bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};
use unsigned_varint::codec::Uvi;

use super::serde::{self, SszChunkResult};
use crate::rpc::{
    message::{Request, ResponseResult},
    protocol::{Protocol, ProtocolSchema},
};

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

#[derive(Debug)]
pub(crate) struct InboundCodec {
    protocol: Protocol,
    max_chunk_size: usize,
    expected_length: Option<usize>,
}

impl InboundCodec {
    pub fn new(protocol: Protocol, max_chunk_size: usize) -> Self {
        Self {
            protocol,
            max_chunk_size,
            expected_length: None,
        }
    }

    fn encode_chunk(
        &mut self,
        chunk: SszChunkResult,
        dst: &mut BytesMut,
    ) -> Result<(), CodecError> {
        let code = chunk.code();
        let bytes = serde::seraialize_response_chunk(chunk)?;

        if ssz_response_length_invalid(bytes.len(), self.protocol.schema, self.max_chunk_size) {
            return Err(CodecError::InvalidData(format!(
                "Invalid response length {}",
                bytes.len()
            )));
        }

        // response code
        let mut writer = dst.writer();
        writer.write_all(&[code])?;

        // ssz-snappy header
        let mut buf = unsigned_varint::encode::usize_buffer();
        let uvi = unsigned_varint::encode::usize(bytes.len(), &mut buf);
        writer.write_all(uvi)?;

        // ssz-snappy body
        let mut encoder = snap::write::FrameEncoder::new(writer);
        encoder.write_all(&bytes)?;
        encoder.flush()?;

        Ok(())
    }
}

impl Encoder<ResponseResult> for InboundCodec {
    type Error = CodecError;

    fn encode(&mut self, item: ResponseResult, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let chunks = serde::chunks_from_response(item)?;
        for chunk in chunks {
            self.encode_chunk(chunk, dst)?;
        }
        Ok(())
    }
}

impl Decoder for InboundCodec {
    type Error = CodecError;
    type Item = Request;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let Some(length) = handle_length(&mut self.expected_length, src)? else {
            return Ok(None);
        };
        if ssz_request_length_invalid(length, self.protocol.schema, self.max_chunk_size) {
            return Err(CodecError::InvalidData(format!(
                "Invalid request length {}",
                length
            )));
        }

        let max_encoded_len = snap::raw::max_compress_len(length);
        let reader = src.reader().take(max_encoded_len as u64);

        let mut decoder = snap::read::FrameDecoder::new(reader);
        let mut bytes = vec![0; length];
        decoder.read_exact(&mut bytes)?;

        if decoder.read(&mut [0; 1])? > 0 {
            return Err(CodecError::InvalidData(format!(
                "Invalid request length, more bytes than expected length {}",
                length
            )));
        }

        let request = serde::deserialize_request(self.protocol.schema, &bytes)?;
        Ok(Some(request))
    }
}

#[derive(Debug)]
pub(crate) struct OutboundCodec {
    protocol: Protocol,
    max_chunk_size: usize,
    expected_response_chunks: usize,
    current_response_code: Option<u8>,
    expected_length: Option<usize>,
    chunks: Vec<SszChunkResult>,
}

impl OutboundCodec {
    pub fn new(protocol: Protocol, expected_response_chunks: usize, max_chunk_size: usize) -> Self {
        Self {
            protocol,
            max_chunk_size,
            expected_response_chunks,
            current_response_code: None,
            expected_length: None,
            chunks: Vec::new(),
        }
    }

    fn decode_chunk(&mut self, src: &mut BytesMut) -> Result<Option<SszChunkResult>, CodecError> {
        if src.is_empty() {
            return Ok(None);
        }

        // read response code
        let response_code = self.current_response_code.unwrap_or_else(|| {
            let resp_code = src.split_to(1)[0];
            self.current_response_code = Some(resp_code);
            resp_code
        });

        // read response length
        let Some(length) = handle_length(&mut self.expected_length, src)? else {
            return Ok(None);
        };
        if ssz_response_length_invalid(length, self.protocol.schema, self.max_chunk_size) {
            return Err(CodecError::InvalidData(format!(
                "Invalid response length {}",
                length
            )));
        }

        let max_decode_len = snap::raw::max_compress_len(length);
        let reader = src.reader().take(max_decode_len as u64);

        // TODO handle max length for errors.

        // TODO this was taken from lighthouse, but doesn't seem to handle if the stream cannot
        // decode up to length. Likely needs to be a stateful decode. Add tests and modify.
        let mut decoder = snap::read::FrameDecoder::new(reader);
        let mut bytes = vec![0; length];
        decoder.read_exact(&mut bytes)?;

        if decoder.read(&mut [0; 1])? > 0 {
            return Err(CodecError::InvalidData(format!(
                "Invalid request length, more bytes than expected length {}",
                length
            )));
        }

        let chunk = if response_code > 0 {
            SszChunkResult::err(serde::deserialize_error_chunk(response_code, &bytes)?)
        } else {
            SszChunkResult::ok(serde::deserialize_response_chunk(
                self.protocol.schema,
                &bytes,
            )?)
        };

        Ok(Some(chunk))
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

        // ssz-snappy header
        let mut buf = unsigned_varint::encode::usize_buffer();
        let uvi = unsigned_varint::encode::usize(bytes.len(), &mut buf);
        dst.writer().write_all(uvi)?;

        // ssz-snappy body
        let mut encoder = snap::write::FrameEncoder::new(dst.writer());
        encoder.write_all(&bytes)?;
        encoder.flush()?;

        Ok(())
    }
}

impl Decoder for OutboundCodec {
    type Error = CodecError;
    type Item = ResponseResult;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // TODO: what happens when the stream is closed before all chunks are received
        while self.chunks.len() < self.expected_response_chunks {
            if let Some(chunk) = self.decode_chunk(src)? {
                if chunk.is_err() {
                    // error was encountered, throw out the rest of the data and return the error
                    self.chunks.clear();
                    self.chunks.push(chunk);
                    break;
                }
                self.chunks.push(chunk);
            } else {
                return Ok(None);
            }
        }

        Ok(Some(serde::response_from_chunks(
            self.protocol.schema,
            // TODO is there a better way to do this?
            self.chunks.drain(..).collect(),
        )))
    }
}

impl From<unsigned_varint::decode::Error> for CodecError {
    fn from(e: unsigned_varint::decode::Error) -> Self {
        CodecError::InvalidData(format!("Invalid unsigned varint: {:?}", e))
    }
}

fn handle_length(len: &mut Option<usize>, src: &mut BytesMut) -> Result<Option<usize>, CodecError> {
    // len is either cached, or needs to be read from the stream
    let length = if let Some(length) = len {
        *length
    } else if let Some(length) = Uvi::<usize>::default().decode(src)? {
        *len = Some(length);
        length
    } else {
        // not enough bytes to read length
        return Ok(None);
    };

    Ok(Some(length))
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
    use ethers::types::H256;

    use super::*;
    use crate::rpc::{
        message::{Metadata, Pong, PooledUserOpHashesResponse, Response, Status},
        protocol::Encoding,
    };

    const MAX_CHUNK_SIZE: usize = 1048576;

    #[test]
    fn test_response_status() {
        let req: ResponseResult = Ok(Response::Status(Status {
            supported_mempools: vec![H256::random()],
        }));
        let protocol = Protocol::new(ProtocolSchema::StatusV1, Encoding::SSZSnappy);
        encode_decode_response_ok(req, protocol, 1);
    }

    #[test]
    fn test_response_ping() {
        let req: ResponseResult = Ok(Response::Ping(Pong {
            metadata_seq_number: 1,
        }));
        let protocol = Protocol::new(ProtocolSchema::PingV1, Encoding::SSZSnappy);
        encode_decode_response_ok(req, protocol, 1);
    }

    #[test]
    fn test_response_metadata() {
        let req: ResponseResult = Ok(Response::Metadata(Metadata { seq_number: 1 }));
        let protocol = Protocol::new(ProtocolSchema::MetadataV1, Encoding::SSZSnappy);
        encode_decode_response_ok(req, protocol, 1);
    }

    #[test]
    fn test_response_pooled_user_op_hashes() {
        let req: ResponseResult = Ok(Response::PooledUserOpHashes(PooledUserOpHashesResponse {
            more_flag: true,
            hashes: vec![H256::random()],
        }));
        let protocol = Protocol::new(ProtocolSchema::PooledUserOpHashesV1, Encoding::SSZSnappy);
        encode_decode_response_ok(req, protocol, 1);
    }

    fn encode_decode_response_ok(
        response: ResponseResult,
        protocol: Protocol,
        num_expected_chunks: usize,
    ) {
        let mut inbound = InboundCodec::new(protocol.clone(), MAX_CHUNK_SIZE);
        let mut outbound = OutboundCodec::new(protocol, num_expected_chunks, MAX_CHUNK_SIZE);

        let mut buf = BytesMut::new();
        inbound.encode(response.clone(), &mut buf).unwrap();
        let resp = outbound.decode(&mut buf).unwrap();
        assert_eq!(resp, Some(response));
    }
}
