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

use super::handler::CodecError;
use crate::{rpc::message::Request, types::Encoding};

const PROTOCOL_PREFIX: &str = "/account_abstraction/req";

/// A protocol in the request/response family.
///
/// Identified by a schema and an encoding.
///
/// Its string identifier is of the form:
/// `/account_abstraction_req/{message_name}/{version}/{encoding}`
#[derive(Clone, Debug)]
pub(crate) struct Protocol {
    /// The schema of the protocol. A combination
    /// of the message name and version.
    pub(crate) schema: ProtocolSchema,
    pub(crate) encoding: Encoding,
    id: String,
}

impl AsRef<str> for Protocol {
    fn as_ref(&self) -> &str {
        self.id.as_ref()
    }
}

impl Protocol {
    pub(crate) fn new(schema: ProtocolSchema, encoding: Encoding) -> Self {
        let id = format!(
            "{}/{}/{}",
            PROTOCOL_PREFIX,
            schema.as_ref(),
            encoding.as_ref()
        );
        Self {
            schema,
            encoding,
            id,
        }
    }
}

impl AsRef<str> for Encoding {
    fn as_ref(&self) -> &str {
        match self {
            Encoding::SSZSnappy => "ssz_snappy",
        }
    }
}

/// Known protocol schemas.
#[derive(Copy, Clone, Debug)]
pub(crate) enum ProtocolSchema {
    StatusV1,
    GoodbyeV1,
    PingV1,
    MetadataV1,
    PooledUserOpHashesV1,
    PooledUserOpsByHashV1,
}

impl AsRef<str> for ProtocolSchema {
    fn as_ref(&self) -> &str {
        match self {
            ProtocolSchema::StatusV1 => "status/1",
            ProtocolSchema::GoodbyeV1 => "goodbye/1",
            ProtocolSchema::PingV1 => "ping/1",
            ProtocolSchema::MetadataV1 => "metadata/1",
            ProtocolSchema::PooledUserOpHashesV1 => "pooled_user_op_hashes/1",
            ProtocolSchema::PooledUserOpsByHashV1 => "pooled_user_ops_by_hash/1",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ProtocolError {
    #[error(transparent)]
    CodecError(#[from] CodecError),
    #[error("Stream timeout")]
    StreamTimeout,
    #[error("Stream ended unexpectedly")]
    IncompleteStream,
    #[error("{0}")]
    Internal(String),
}

/// Returns the list of supported protocols by Rundler.
pub(crate) fn supported_protocols() -> Vec<Protocol> {
    vec![
        Protocol::new(ProtocolSchema::StatusV1, Encoding::SSZSnappy),
        Protocol::new(ProtocolSchema::GoodbyeV1, Encoding::SSZSnappy),
        Protocol::new(ProtocolSchema::PingV1, Encoding::SSZSnappy),
        Protocol::new(ProtocolSchema::MetadataV1, Encoding::SSZSnappy),
        Protocol::new(ProtocolSchema::PooledUserOpHashesV1, Encoding::SSZSnappy),
        Protocol::new(ProtocolSchema::PooledUserOpsByHashV1, Encoding::SSZSnappy),
    ]
}

/// Returns the list of protocols supported by the given request.
pub(crate) fn request_protocols(req: &Request) -> Vec<Protocol> {
    match req {
        Request::Status(_) => vec![Protocol::new(ProtocolSchema::StatusV1, Encoding::SSZSnappy)],
        Request::Goodbye(_) => vec![Protocol::new(
            ProtocolSchema::GoodbyeV1,
            Encoding::SSZSnappy,
        )],
        Request::Ping(_) => vec![Protocol::new(ProtocolSchema::PingV1, Encoding::SSZSnappy)],
        Request::Metadata => vec![Protocol::new(
            ProtocolSchema::MetadataV1,
            Encoding::SSZSnappy,
        )],
        Request::PooledUserOpHashes(_) => vec![Protocol::new(
            ProtocolSchema::PooledUserOpHashesV1,
            Encoding::SSZSnappy,
        )],
        Request::PooledUserOpsByHash(_) => vec![Protocol::new(
            ProtocolSchema::PooledUserOpsByHashV1,
            Encoding::SSZSnappy,
        )],
    }
}
