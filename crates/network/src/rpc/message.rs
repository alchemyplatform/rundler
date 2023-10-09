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

pub(crate) const MAX_ERROR_MESSAGE_LEN: usize = 256;
pub(crate) const MAX_OPS_PER_REQUEST: usize = 4096;

/// Request types
#[derive(Clone, Debug)]
pub(crate) enum Request {
    Status(Status),
    Goodbye(Goodbye),
    Ping(Ping),
    Metadata,
    PooledUserOpHashes(PooledUserOpHashesRequest),
    PooledUserOpsByHash(PooledUserOpsByHashRequest),
}

impl Request {
    pub(crate) fn num_expected_response_chunks(&self) -> usize {
        match self {
            Request::Status(_) => 1,
            Request::Goodbye(_) => 0,
            Request::Ping(_) => 1,
            Request::Metadata => 1,
            Request::PooledUserOpHashes(_) => 1,
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

pub(crate) type ResponseResult = Result<Response, ResponseError>;

/// Error for a response
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ResponseError {
    pub kind: ErrorKind,
    pub message: String,
}

/// Error kinds
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum ErrorKind {
    InvalidRequest,
    ServerError,
    ResourceUnavailable,
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

/// Status Request/Response
#[derive(Clone, Debug, PartialEq, Encode, Decode)]
pub(crate) struct Status {
    pub supported_mempools: Vec<H256>,
}

#[derive(Clone, Debug, PartialEq, Encode, Decode)]
pub(crate) struct Ping {
    /// Metadata sequence number
    pub metadata_seq_number: u64,
}

/// Pong Response
#[derive(Clone, Debug, PartialEq, Encode, Decode)]
pub(crate) struct Pong {
    /// Metadata sequence number
    pub metadata_seq_number: u64,
}

#[derive(Clone, Debug, PartialEq, Encode, Decode)]
pub(crate) struct Metadata {
    pub(crate) seq_number: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Goodbye {
    pub reason: GoodbyeReason,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum GoodbyeReason {
    ClientShutdown,
    IrrelevantNetwork,
    FaultOrError,
    TooManyPeers,
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

#[derive(Clone, Debug, PartialEq, Encode, Decode)]
pub(crate) struct PooledUserOpHashesRequest {
    pub mempool: H256,
    pub offset: u64,
}

#[derive(Clone, Debug, PartialEq, Encode, Decode)]
pub(crate) struct PooledUserOpHashesResponse {
    pub more_flag: bool,
    pub hashes: Vec<H256>,
}

#[derive(Clone, Debug, PartialEq, Encode, Decode)]
pub(crate) struct PooledUserOpsByHashRequest {
    pub hashes: Vec<H256>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct PooledUserOpsByHashResponse {
    pub user_ops: Vec<UserOperation>,
}
