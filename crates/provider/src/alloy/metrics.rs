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
use rundler_types::task::traits::RequestExtractor;
use alloy_json_rpc::RequestPacket;

#[allow(dead_code)]
/// Method extractor for Alloy providers
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

#[allow(dead_code)]
#[derive(Clone, Copy)]
pub struct AlloyResponseCodeExtractor;

impl ResponseExtractor<ResponsePacket> for AlloyMethodExtractor {
    fn get_response_code(response: &ResponsePacket) -> String {
        if response.is_error() {
            response.as_error().unwrap().code.to_string()
        } else {
            "200".to_string()
        }
    }
}
