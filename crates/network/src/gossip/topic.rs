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

use ethers::types::H256;
use libp2p::gossipsub::{self, TopicHash};

use crate::types::Encoding;

const TOPIC_PREFIX: &str = "account_abstraction";

pub(crate) fn mempool_to_topics(mempool_id: H256) -> Vec<Topic> {
    vec![Topic::new(
        mempool_id,
        TopicKind::UserOperationsWithEntryPoint,
        Encoding::SSZSnappy,
    )]
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum TopicKind {
    UserOperationsWithEntryPoint,
}

impl AsRef<str> for TopicKind {
    fn as_ref(&self) -> &str {
        match self {
            TopicKind::UserOperationsWithEntryPoint => "user_operations_with_entry_point",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Topic {
    mempool_id: H256,
    kind: TopicKind,
    encoding: Encoding,
    id: String,
}

impl Topic {
    pub(crate) fn new(mempool_id: H256, kind: TopicKind, encoding: Encoding) -> Self {
        let id = format!(
            "/{}/{:?}/{}/{}",
            TOPIC_PREFIX,
            mempool_id,
            kind.as_ref(),
            encoding.as_ref()
        );
        Self {
            mempool_id,
            kind,
            encoding,
            id,
        }
    }

    pub(crate) fn mempool_id(&self) -> H256 {
        self.mempool_id
    }

    pub(crate) fn kind(&self) -> &TopicKind {
        &self.kind
    }

    pub(crate) fn encoding(&self) -> Encoding {
        self.encoding
    }
}

impl AsRef<str> for Topic {
    fn as_ref(&self) -> &str {
        self.id.as_ref()
    }
}

impl From<Topic> for TopicHash {
    fn from(topic: Topic) -> Self {
        TopicHash::from_raw(topic.as_ref())
    }
}

impl From<Topic> for gossipsub::IdentTopic {
    fn from(topic: Topic) -> Self {
        gossipsub::IdentTopic::new(topic.as_ref())
    }
}

impl TryFrom<TopicHash> for Topic {
    type Error = &'static str;

    fn try_from(topic: TopicHash) -> Result<Self, Self::Error> {
        let mut parts = topic.as_str().split('/');
        let _ = parts.next();

        if parts.next() != Some(TOPIC_PREFIX) {
            return Err("invalid topic: invalid prefix");
        }

        let mempool_id = parts
            .next()
            .ok_or("invalid topic: missing mempool id")?
            .parse::<H256>()
            .map_err(|_| "invalid topic: invalid mempool id")?;

        let kind = match parts.next() {
            Some("user_operations_with_entry_point") => TopicKind::UserOperationsWithEntryPoint,
            _ => return Err("invalid topic: invalid kind"),
        };

        let encoding = match parts.next() {
            Some("ssz_snappy") => Encoding::SSZSnappy,
            _ => return Err("invalid topic: invalid encoding"),
        };

        if parts.next().is_some() {
            return Err("invalid topic: too many parts");
        }

        Ok(Self::new(mempool_id, kind, encoding))
    }
}
