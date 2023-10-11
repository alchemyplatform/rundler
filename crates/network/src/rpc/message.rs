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
use rundler_types::UserOperation;
use ssz_derive::{Decode, Encode};

/// Maximum length of an error message
pub(crate) const MAX_ERROR_MESSAGE_LEN: usize = 256;
/// Maximum number of user ops per request
pub const MAX_OPS_PER_REQUEST: usize = 4096;

/// Request types
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Request {
    Status(Status),
    Goodbye(Goodbye),
    Ping(Ping),
    Metadata,
    PooledUserOpHashes(PooledUserOpHashesRequest),
    PooledUserOpsByHash(PooledUserOpsByHashRequest),
}

impl Request {
    /// Number of expected response chunks for the request
    ///
    /// Codec will wait to receive this many chunks before returning or timing out.
    pub(crate) fn num_expected_response_chunks(&self) -> usize {
        match self {
            Request::Status(_) => 1,
            Request::Goodbye(_) => 0,
            Request::Ping(_) => 1,
            Request::Metadata => 1,
            Request::PooledUserOpHashes(_) => 1,
            // TODO(danc): is this valid? What if the UO isn't found, need to handle less.
            Request::PooledUserOpsByHash(r) => r.hashes.len(),
        }
    }
}

/// Response types
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Response {
    Status(Status),
    Ping(Pong),
    Metadata(Metadata),
    PooledUserOpHashes(PooledUserOpHashesResponse),
    PooledUserOpsByHash(PooledUserOpsByHashResponse),
}

/// Response result
pub(crate) type ResponseResult = Result<Response, ResponseError>;

/// Error for a response
#[derive(Clone, Debug, PartialEq)]
pub struct ResponseError {
    /// Kind of error
    pub kind: ErrorKind,
    /// Error message, may be empty if could not decode as UTF8 string
    pub message: String,
}

/// Error kinds
#[derive(Clone, Debug, PartialEq)]
pub enum ErrorKind {
    /// Request is invalid
    InvalidRequest,
    /// Server error
    ServerError,
    /// Resource unavailable
    ResourceUnavailable,
    /// Unknown error
    Unknown,
}

impl From<u8> for ErrorKind {
    fn from(value: u8) -> Self {
        match value {
            1 => ErrorKind::InvalidRequest,
            2 => ErrorKind::ServerError,
            3 => ErrorKind::ResourceUnavailable,
            _ => ErrorKind::Unknown,
        }
    }
}

impl From<ErrorKind> for u8 {
    fn from(kind: ErrorKind) -> Self {
        match kind {
            ErrorKind::InvalidRequest => 1,
            ErrorKind::ServerError => 2,
            ErrorKind::ResourceUnavailable => 3,
            ErrorKind::Unknown => 255,
        }
    }
}

/// Status request/response
///
/// TODO(danc): should supported mempools be moved to metadata?
#[derive(Clone, Debug, PartialEq, Encode, Decode)]
pub(crate) struct Status {
    /// Hash ids of the supported mempools
    pub(crate) supported_mempools: Vec<H256>,
}

/// Ping request
#[derive(Clone, Debug, PartialEq, Encode, Decode)]
pub(crate) struct Ping {
    /// Metadata sequence number
    pub(crate) metadata_seq_number: u64,
}

/// Pong response
#[derive(Clone, Debug, PartialEq, Encode, Decode)]
pub(crate) struct Pong {
    /// Metadata sequence number
    ///
    /// Upon receipt a sequencer number, check if its greater than
    /// the last one received. If so, request new metadata from the peer.
    pub(crate) metadata_seq_number: u64,
}

// Metadata response
#[derive(Clone, Debug, PartialEq, Encode, Decode)]
pub(crate) struct Metadata {
    /// Metadata sequence number
    pub(crate) seq_number: u64,
    // TODO: spec has an invalid field here, add if needed
}

/// Goodbye request
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Goodbye {
    pub(crate) reason: GoodbyeReason,
}

/// Goodbye reason
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum GoodbyeReason {
    /// Client is shutting down
    ClientShutdown,
    /// Irrelevant network, no mempools in common
    IrrelevantNetwork,
    /// Fault or error
    FaultOrError,
    /// Too many peers, so dropping this one
    TooManyPeers,
    /// Unknown reason
    Unknown,
}

impl From<u64> for GoodbyeReason {
    fn from(value: u64) -> Self {
        match value {
            1 => GoodbyeReason::ClientShutdown,
            2 => GoodbyeReason::IrrelevantNetwork,
            3 => GoodbyeReason::FaultOrError,
            129 => GoodbyeReason::TooManyPeers,
            _ => GoodbyeReason::Unknown,
        }
    }
}

impl From<GoodbyeReason> for u64 {
    fn from(reason: GoodbyeReason) -> Self {
        match reason {
            GoodbyeReason::ClientShutdown => 1,
            GoodbyeReason::IrrelevantNetwork => 2,
            GoodbyeReason::FaultOrError => 3,
            GoodbyeReason::TooManyPeers => 129,
            GoodbyeReason::Unknown => 255,
        }
    }
}

/// Pooled user op hashes request
#[derive(Clone, Debug, PartialEq, Encode, Decode)]
pub struct PooledUserOpHashesRequest {
    /// Hash id of the mempool
    pub mempool: H256,
    /// Offset into the mempool
    pub offset: u64,
}

/// Pooled user op hashes response
#[derive(Clone, Debug, PartialEq, Encode, Decode)]
pub struct PooledUserOpHashesResponse {
    /// More user ops are available
    pub more_flag: bool,
    /// Hashes of the user ops
    pub hashes: Vec<H256>,
}

/// Pooled user ops by hash request
#[derive(Clone, Debug, PartialEq, Encode, Decode)]
pub struct PooledUserOpsByHashRequest {
    /// Hashes of the user ops
    pub hashes: Vec<H256>,
}

/// Pooled user ops by hash response
#[derive(Clone, Debug, PartialEq)]
pub struct PooledUserOpsByHashResponse {
    /// User ops
    pub user_ops: Vec<UserOperation>,
}
