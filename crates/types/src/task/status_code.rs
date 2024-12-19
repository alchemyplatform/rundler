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
    ClientSideTimeout,
    MethodNotFound,
    AlreadyExist,
    PermissionDenied,
    ResourceExhausted,
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
    InvalidArgument,
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

/// utility function to conert a http status code to HttpCode object.
pub fn get_http_status_from_code(code: u16) -> HttpCode {
    match code {
        x if (200..=299).contains(&x) => HttpCode::TwoHundreds,
        x if (400..=499).contains(&x) => HttpCode::FourHundreds,
        x if (500..=599).contains(&x) => HttpCode::FiveHundreds,
        _ => HttpCode::Other,
    }
}
