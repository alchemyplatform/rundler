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

use ethers::types::{Address, H256, U256};
use libp2p::gossipsub;
use rundler_types::UserOperation;
use sha2::{Digest, Sha256};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};

use super::topic::{Topic, TopicKind};
use crate::types::{Encoding, UserOperationSsz};

const MESSAGE_DOMAIN_VALID_SNAPPY: [u8; 4] = [1, 0, 0, 0];
//const MESSAGE_DOMAIN_INVALID_SNAPPY: [u8; 4] = [0, 0, 0, 0];

/// Gossipsub messages
#[derive(Clone, Debug)]
pub enum Message {
    /// User operations with entrypoint gossip message
    UserOperationsWithEntryPoint(UserOperationsWithEntryPoint),
}

impl Message {
    pub(crate) fn encode(self) -> Vec<u8> {
        match self {
            Message::UserOperationsWithEntryPoint(m) => {
                UserOperationsWithEntryPointSsz::from(m).as_ssz_bytes()
            }
        }
    }

    // TODO error handling
    pub(crate) fn decode(topic: &Topic, data: Vec<u8>) -> Result<Self, &'static str> {
        if topic.encoding() != Encoding::SSZSnappy {
            return Err("invalid encoding");
        }

        match topic.kind() {
            TopicKind::UserOperationsWithEntryPoint => {
                let uo_ssz = UserOperationsWithEntryPointSsz::from_ssz_bytes(&data).unwrap();
                let uo = UserOperationsWithEntryPoint::try_from(uo_ssz).unwrap();
                Ok(Self::UserOperationsWithEntryPoint(uo))
            }
        }
    }

    pub(crate) fn topic(&self, mempool_id: H256) -> Topic {
        match self {
            Message::UserOperationsWithEntryPoint(_) => Topic::new(
                mempool_id,
                TopicKind::UserOperationsWithEntryPoint,
                Encoding::SSZSnappy,
            ),
        }
    }
}

/// User operations with entrypoint gossip message
#[derive(Clone, Debug)]
pub struct UserOperationsWithEntryPoint {
    /// The entry point contract this message targets
    pub entry_point_contract: Address,
    /// The block hash at which these user operations were verified
    pub verified_at_block_hash: H256,
    /// The chain ID of the chain these user operations are for
    pub chain_id: U256,
    /// The user operations
    pub user_operations: Vec<UserOperation>,
}

pub(crate) fn message_id(message: &gossipsub::Message) -> gossipsub::MessageId {
    // NOTE: this message has already gone through the DataTransform layer,
    // so its data is already decompressed, and is valid.
    // this means that MESSAGE_DOMAIN_INVALID_SNAPPY is never used.
    // TODO: check on this.

    // TODO: these message IDs are not scoped to topics. This may be a problem.

    let mut vec = Vec::with_capacity(MESSAGE_DOMAIN_VALID_SNAPPY.len() + message.data.len());
    vec.extend_from_slice(&MESSAGE_DOMAIN_VALID_SNAPPY);
    vec.extend_from_slice(&message.data);
    Sha256::digest(&vec)[..20].into()
}

#[derive(Clone, Debug, Encode, Decode)]
struct UserOperationsWithEntryPointSsz {
    entry_point_contract: Address,
    verified_at_block_hash: H256,
    chain_id: U256,
    user_operations: Vec<UserOperationSsz>,
}

impl From<UserOperationsWithEntryPoint> for UserOperationsWithEntryPointSsz {
    fn from(uo: UserOperationsWithEntryPoint) -> Self {
        Self {
            entry_point_contract: uo.entry_point_contract,
            verified_at_block_hash: uo.verified_at_block_hash,
            chain_id: uo.chain_id,
            user_operations: uo.user_operations.into_iter().map(|uo| uo.into()).collect(),
        }
    }
}

impl TryFrom<UserOperationsWithEntryPointSsz> for UserOperationsWithEntryPoint {
    type Error = &'static str;

    fn try_from(uo_ssz: UserOperationsWithEntryPointSsz) -> Result<Self, Self::Error> {
        Ok(Self {
            entry_point_contract: uo_ssz.entry_point_contract,
            verified_at_block_hash: uo_ssz.verified_at_block_hash,
            chain_id: uo_ssz.chain_id,
            user_operations: uo_ssz
                .user_operations
                .into_iter()
                .map(|uo| uo.try_into())
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}
