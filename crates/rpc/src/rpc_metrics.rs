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

use jsonrpsee::{types::Request, MethodResponse};
use rundler_types::task::traits::{RequestExtractor, ResponseExtractor};

pub struct RPCMethodExtractor;

impl RequestExtractor<Request<'static>> for RPCMethodExtractor {
    fn get_method_name(req: &Request<'static>) -> String {
        req.method_name().to_string()
    }
}

/// http response extractor.
#[derive(Copy, Clone)]
pub struct RPCResponseCodeExtractor;

impl ResponseExtractor<MethodResponse> for RPCResponseCodeExtractor {
    fn get_response_code(response: &MethodResponse) -> String {
        if response.is_error() {
            response.as_error_code().unwrap().to_string()
        } else {
            "200".to_string()
        }
    }
}
