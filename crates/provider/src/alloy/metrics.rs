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

use alloy_json_rpc::{RequestPacket, ResponsePacket};
/// Method extractor
use rundler_types::task::{
    status_code::RpcCode,
    traits::{RequestExtractor, ResponseExtractor},
};

#[allow(dead_code, unreachable_pub)]
#[derive(Clone, Copy)]
pub struct AlloyMethodExtractor;

impl RequestExtractor<RequestPacket> for AlloyMethodExtractor {
    fn get_method_name(req: &RequestPacket) -> String {
        match req {
            RequestPacket::Single(request) => request.method().to_string(),
            _ => {
                // can't extract method name for batch.
                "batch".to_string()
            }
        }
    }
}

#[allow(dead_code, unreachable_pub)]
#[derive(Clone, Copy)]
pub struct AlloyResponseCodeExtractor;

impl ResponseExtractor<ResponsePacket> for AlloyMethodExtractor {
    fn get_http_status_code(response: &ResponsePacket) -> String {
        if response.is_error() {
            response.as_error().unwrap().code.to_string()
        } else {
            "200".to_string()
        }
    }

    fn get_rpc_status_code(response_packet: &ResponsePacket) -> String {
        let response: &alloy_json_rpc::Response = match response_packet {
            ResponsePacket::Batch(resps) => &resps[0],
            ResponsePacket::Single(resp) => resp,
        };
        let response_code: i64 = match &response.payload {
            alloy_json_rpc::ResponsePayload::Success(_) => 0,
            alloy_json_rpc::ResponsePayload::Failure(error_payload) => error_payload.code,
        };

        let rpc_code = match response_code {
            -32700 => RpcCode::ParseError,
            -32600 => RpcCode::InvalidRequest,
            -32601 => RpcCode::MethodNotFound,
            -32602 => RpcCode::InvalidParams,
            -32603 => RpcCode::InternalError,
            x if (-32000..=-32099).contains(&x) => RpcCode::ServerError,
            _ => RpcCode::Other,
        };
        rpc_code.to_string()
    }
}
