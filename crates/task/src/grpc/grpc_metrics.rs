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

use rundler_types::task::{
    status_code::{HttpCode, RpcCode},
    traits::{RequestExtractor, ResponseExtractor},
};
use tonic::{codegen::http, transport::Error, Result};

/// http request method extractor.
pub struct HttpMethodExtractor;

impl<Body> RequestExtractor<http::Request<Body>> for HttpMethodExtractor {
    fn get_method_name(req: &http::Request<Body>) -> String {
        let method_name = req.uri().path().split('/').last().unwrap_or("unknown");
        method_name.to_string()
    }
}

/// http response extractor.
#[derive(Copy, Clone)]
pub struct HttpResponseCodeExtractor;

impl<B> ResponseExtractor<Result<http::Response<B>>> for HttpResponseCodeExtractor {
    fn get_http_status_code(response: &Result<http::Response<B>>) -> String {
        let http_code = match response {
            Ok(resp) => resp.status().as_u16(),
            Err(_) => 500,
        };
        let http = match http_code {
            x if (200..=299).contains(&x) => HttpCode::TwoHundreds,
            x if (400..=499).contains(&x) => HttpCode::FourHundreds,
            x if (500..=599).contains(&x) => HttpCode::FiveHundreds,
            _ => HttpCode::Other,
        };
        http.to_string()
    }

    fn get_rpc_status_code(response: &Result<http::Response<B>>) -> String {
        let rpc_status = match response {
            Ok(resp) => {
                let rpc_code = resp
                    .headers()
                    .get("grpc-status")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("0")
                    .to_string()
                    .parse::<i32>()
                    .unwrap_or(0);

                let rpc = match rpc_code {
                    0 => RpcCode::Success,
                    1 => RpcCode::Cancelled,
                    2 => RpcCode::Other,
                    3 => RpcCode::InvalidParams,
                    4 => RpcCode::DeadlineExceed,
                    5 => RpcCode::MethodNotFound,
                    6 => RpcCode::AlreadyExist,
                    7 => RpcCode::PermissionDenied,
                    8 => RpcCode::ResourceExhaused,
                    9 => RpcCode::FailedPrecondition,
                    10 => RpcCode::Aborted,
                    11 => RpcCode::OutOfRange,
                    12 => RpcCode::Unimplemented,
                    13 => RpcCode::InternalError,
                    14 => RpcCode::Unavailable,
                    15 => RpcCode::DataLoss,
                    16 => RpcCode::Unauthenticated,
                    _ => RpcCode::Other,
                };
                rpc
            }
            Err(e) => match e.code() {
                tonic::Code::Ok => RpcCode::Success,
                tonic::Code::Cancelled => RpcCode::Cancelled,
                tonic::Code::Unknown => RpcCode::Cancelled,
                tonic::Code::InvalidArgument => RpcCode::InvalidParams,
                tonic::Code::DeadlineExceeded => RpcCode::DeadlineExceed,
                tonic::Code::NotFound => RpcCode::MethodNotFound,
                tonic::Code::AlreadyExists => RpcCode::AlreadyExist,
                tonic::Code::PermissionDenied => RpcCode::PermissionDenied,
                tonic::Code::ResourceExhausted => RpcCode::ResourceExhaused,
                tonic::Code::FailedPrecondition => RpcCode::FailedPrecondition,
                tonic::Code::Aborted => RpcCode::Aborted,
                tonic::Code::OutOfRange => RpcCode::OutOfRange,
                tonic::Code::Unimplemented => RpcCode::Unimplemented,
                tonic::Code::Internal => RpcCode::InternalError,
                tonic::Code::Unavailable => RpcCode::Unavailable,
                tonic::Code::DataLoss => RpcCode::DataLoss,
                tonic::Code::Unauthenticated => RpcCode::Unauthenticated,
            },
        };

        rpc_status.to_string()
    }
}
