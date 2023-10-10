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

use std::io::{self, Cursor, Read, Write};

use libp2p::bytes::{BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};
use unsigned_varint::codec::Uvi;

use super::CodecError;

pub(crate) struct LengthPrefixedSnappyCodec {
    decode_state: State,
    uvi: Uvi<usize>,
    decode_min_length: usize,
    decode_max_length: usize,
}

enum State {
    Init,
    DecodeLength,
    DecompressPayload {
        max_compressed_len: usize,
        buf: Vec<u8>,
    },
}

impl LengthPrefixedSnappyCodec {
    pub(crate) fn new(decode_min_length: usize, decode_max_length: usize) -> Self {
        Self {
            decode_state: State::Init,
            uvi: Uvi::default(),
            decode_min_length,
            decode_max_length,
        }
    }
}

impl Decoder for LengthPrefixedSnappyCodec {
    type Error = CodecError;
    type Item = Vec<u8>;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        loop {
            match &mut self.decode_state {
                State::Init => {
                    if src.is_empty() {
                        return Ok(None);
                    } else {
                        self.decode_state = State::DecodeLength;
                        continue;
                    }
                }
                State::DecodeLength => {
                    if let Some(length) = self.uvi.decode(src)? {
                        if length < self.decode_min_length || length > self.decode_max_length {
                            return Err(CodecError::InvalidData(format!(
                                "Invalid length: {}",
                                length
                            )));
                        }

                        self.decode_state = State::DecompressPayload {
                            max_compressed_len: snap::raw::max_compress_len(length),
                            buf: vec![0; length],
                        };
                        continue;
                    } else {
                        return Ok(None);
                    }
                }
                State::DecompressPayload {
                    max_compressed_len,
                    buf,
                } => {
                    // Read up to `max_compressed_len bytes` from decoder, writing exactly `length` bytes to buf,
                    // using a cursor to track the number of bytes read to consume from source.
                    // This will not consume from `src` until the entire payload can be decompressed.
                    let reader = Cursor::new(src.as_ref()).take(*max_compressed_len as u64);
                    let mut decoder = snap::read::FrameDecoder::new(reader);
                    let res = decoder.read_exact(buf);
                    let read = decoder.get_ref().get_ref().position() as usize;

                    match res {
                        Ok(()) => {
                            let buf = std::mem::take(buf);
                            let _ = src.split_to(read);
                            self.decode_state = State::Init;
                            return Ok(Some(buf));
                        }
                        Err(e) => match e.kind() {
                            io::ErrorKind::UnexpectedEof => {
                                if read >= *max_compressed_len {
                                    return Err(CodecError::InvalidData(
                                        "Invalid snappy compression".into(),
                                    ));
                                }
                                // not enough data, try again
                                return Ok(None);
                            }
                            _ => {
                                return Err(CodecError::from(e));
                            }
                        },
                    }
                }
            }
        }
    }
}

impl Encoder<Vec<u8>> for LengthPrefixedSnappyCodec {
    type Error = CodecError;

    fn encode(&mut self, item: Vec<u8>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let mut writer = dst.writer();

        // length-prefixed header header
        let mut buf = unsigned_varint::encode::usize_buffer();
        let uvi = unsigned_varint::encode::usize(item.len(), &mut buf);
        writer.write_all(uvi)?;

        // snappy body
        let mut encoder = snap::write::FrameEncoder::new(writer);
        encoder.write_all(&item)?;
        encoder.flush()?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_encode_decode() {
        let mut codec = LengthPrefixedSnappyCodec::new(0, 1024);
        let src = random_bytes(1024);
        let mut buf = BytesMut::new();
        codec.encode(src.clone(), &mut buf).unwrap();
        let dst = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(src, dst);
    }

    #[test]
    fn test_decode_too_many() {
        let mut codec = LengthPrefixedSnappyCodec::new(0, 1024);
        let src = random_bytes(2048);
        let mut buf = BytesMut::new();
        codec.encode(src, &mut buf).unwrap();

        let res = codec.decode(&mut buf).unwrap_err();
        assert!(matches!(res, CodecError::InvalidData(_)));
    }

    #[test]
    fn test_stream() {
        let mut codec = LengthPrefixedSnappyCodec::new(1024, 1024);
        let src = random_bytes(1024);
        let mut buf = BytesMut::new();
        codec.encode(src.clone(), &mut buf).unwrap();

        let encoded_len = buf.len();
        let mut stream_buf = BytesMut::new();

        // feed in bytes one at a time
        for _ in 0..encoded_len - 1 {
            stream_buf.put_u8(buf.split_to(1)[0]);
            let res = codec.decode(&mut stream_buf).unwrap();
            assert!(res.is_none());
        }

        stream_buf.put_u8(buf.split_to(1)[0]);
        let res = codec.decode(&mut stream_buf).unwrap().unwrap();
        assert_eq!(src, res);
    }

    #[test]
    fn test_invalid_compression() {
        let buf = BytesMut::new();
        let mut writer = buf.writer();

        let mut uvi_buf = unsigned_varint::encode::usize_buffer();
        let uvi = unsigned_varint::encode::usize(1024, &mut uvi_buf);
        writer.write_all(uvi).unwrap();

        let mut buf = writer.into_inner();
        let random = random_bytes(4096);
        buf.put_slice(&random);

        let mut codec = LengthPrefixedSnappyCodec::new(0, 1024);
        let res = codec.decode(&mut buf).unwrap_err();
        assert!(matches!(res, CodecError::IoError(_)));
    }

    fn random_bytes(len: usize) -> Vec<u8> {
        (0..len).map(|_| rand::random::<u8>()).collect()
    }
}
