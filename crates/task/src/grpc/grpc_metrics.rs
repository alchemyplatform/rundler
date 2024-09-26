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

use rundler_types::task::traits::{RequestExtractor, ResponseExtractor};
use tonic::codegen::http;

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

impl<B> ResponseExtractor<http::Response<B>> for HttpResponseCodeExtractor {
    fn get_response_code(response: &http::Response<B>) -> String {
        response.status().to_string()
    }
}
