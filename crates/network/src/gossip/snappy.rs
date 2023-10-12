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

// adapted from https://github.com/sigp/lighthouse/blob/stable/beacon_node/lighthouse_network/src/types/pubsub.rs

use std::io;

use libp2p::gossipsub::{DataTransform, Message, RawMessage, TopicHash};
use snap::raw::{Decoder, Encoder};

pub(crate) struct SnappyTransform {
    gossip_max_size: usize,
}

impl SnappyTransform {
    pub(crate) fn new(gossip_max_size: usize) -> Self {
        Self { gossip_max_size }
    }
}

impl DataTransform for SnappyTransform {
    fn inbound_transform(&self, raw_message: RawMessage) -> Result<Message, io::Error> {
        let len = snap::raw::decompress_len(&raw_message.data)?;
        if len > self.gossip_max_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ssz_snappy decoded data > GOSSIP_MAX_SIZE",
            ));
        }

        let mut decoder = Decoder::new();
        let decompressed_data = decoder.decompress_vec(&raw_message.data)?;

        Ok(Message {
            source: raw_message.source,
            data: decompressed_data,
            sequence_number: raw_message.sequence_number,
            topic: raw_message.topic,
        })
    }

    fn outbound_transform(&self, _topic: &TopicHash, data: Vec<u8>) -> Result<Vec<u8>, io::Error> {
        if data.len() > self.gossip_max_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ssz_snappy Encoded data > GOSSIP_MAX_SIZE",
            ));
        }
        let mut encoder = Encoder::new();
        encoder.compress_vec(&data).map_err(Into::into)
    }
}
