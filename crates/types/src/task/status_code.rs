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

//! Response code.
use parse_display::Display;

/// RPC status code.
#[derive(Display)]
#[display(style = "snake_case")]
#[doc(hidden)]
pub enum RpcCode {
    Success,
    Cancelled,
    Other,
    InvalidParams,
    DeadlineExceed,
    MethodNotFound,
    AlreadyExist,
    PermissionDenied,
    ResourceExhaused,
    FailedPrecondition,
    Aborted,
    OutOfRange,
    Unimplemented,
    InternalError,
    Unavailable,
    DataLoss,
    Unauthenticated,
    ParseError,
    InvalidRequest,
    ServerError,
}

/// HTTP status code.
#[doc(hidden)]
#[derive(Display)]
#[display(style = "snake_case")]
pub enum HttpCode {
    TwoHundreds,
    FourHundreds,
    FiveHundreds,
    Other,
}
