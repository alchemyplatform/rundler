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

<<<<<<< HEAD
use jsonrpsee::{types::Request, MethodResponse};
use rundler_types::task::traits::{RequestExtractor, ResponseExtractor};

pub struct RPCMethodExtractor;
=======
use jsonrpsee::{
    core::RpcResult,
    types::{ErrorCode, Request},
};
use rundler_types::task::{
    status_code::{HttpCode, RpcCode},
    traits::{RequestExtractor, ResponseExtractor},
};
#[derive(Copy, Clone)]
struct RPCMethodExtractor;
>>>>>>> 9c40b91 (feat(middleware): add response extractor)

impl RequestExtractor<Request<'static>> for RPCMethodExtractor {
    fn get_method_name(req: &Request<'static>) -> String {
        req.method_name().to_string()
    }
}

/// http response extractor.
#[derive(Copy, Clone)]
pub struct RPCResponseCodeExtractor;

impl<T> ResponseExtractor<RpcResult<T>> for RPCResponseCodeExtractor {
    fn get_http_status_code(response: &RpcResult<T>) -> String {
        let response_code = match response {
            Ok(_) => 200,
            Err(error) => error.code(),
        };
        let http = match Response {
            200 => HttpCode::TwoHundreds,
            ErrorCode::ParseError => HttpCode::FourHundreds,
            ErrorCode::OversizedRequest => HttpCode::FourHundreds,
            ErrorCode::InvalidRequest => HttpCode::FourHundreds,
            ErrorCode::MethodNotFound => HttpCode::FourHundreds,
            ErrorCode::ServerIsBusy => HttpCode::FourHundreds,
            ErrorCode::InvalidParams => HttpCode::FourHundreds,
            ErrorCode::InternalError => HttpCode::FiveHundreds,
            ErrorCode::ServerError(_) => HttpCode::FiveHundreds,
        };
        http.to_string()
    }

    fn get_rpc_status_code(response: &RpcResult<T>) -> String {
        let response_code = match response {
            Ok(_) => 0,
            Err(error) => error.code(),
        };
        let rpc = match response {
            ErrorCode::ParseError => RpcCode::ParseError,
            ErrorCode::OversizedRequest => RpcCode::InvalidParams,
            ErrorCode::InvalidRequest => RpcCode::InvalidParams,
            ErrorCode::MethodNotFound => RpcCode::MethodNotFound,
            ErrorCode::ServerIsBusy => RpcCode::ResourceExhaused,
            ErrorCode::InvalidParams => RpcCode::InvalidParams,
            ErrorCode::InternalError => RpcCode::InternalError,
            ErrorCode::ServerError(_) => RpcCode::InternalError,
            _ => RpcCode::Other,
        };
        rpc.to_string()
    }
}
