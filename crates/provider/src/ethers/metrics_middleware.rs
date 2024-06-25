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

use core::fmt::Debug;
use std::time::Duration;

use async_trait::async_trait;
use ethers::providers::{HttpClientError, JsonRpcClient};
use metrics::{counter, histogram};
use parse_display::Display;
use reqwest::StatusCode;
use serde::{de::DeserializeOwned, Serialize};
use tokio::time::Instant;

#[derive(Display)]
#[display(style = "snake_case")]
enum RpcCode {
    ServerError,
    InternalError,
    InvalidParams,
    MethodNotFound,
    InvalidRequest,
    ParseError,
    ExecutionFailed,
    Success,
    Other,
}

#[derive(Display)]
#[display(style = "snake_case")]
enum HttpCode {
    TwoHundreds,
    FourHundreds,
    FiveHundreds,
    Other,
}

#[derive(Debug)]
/// Metrics middleware struct to hold the inner http client
pub struct MetricsMiddleware<C> {
    inner: C,
}

impl<C> MetricsMiddleware<C>
where
    C: JsonRpcClient<Error = HttpClientError>,
{
    /// Constructor for middleware
    pub fn new(inner: C) -> Self {
        Self { inner }
    }

    fn instrument_request<R>(
        &self,
        method: &str,
        duration: Duration,
        request: &Result<R, C::Error>,
    ) {
        let method_str = method.to_string();

        let mut http_code = StatusCode::OK.as_u16() as u64;
        let mut rpc_code = 0;

        if let Err(error) = request {
            match error {
                HttpClientError::ReqwestError(req_err) => {
                    http_code = req_err.status().unwrap_or_default().as_u16() as u64;
                }
                HttpClientError::JsonRpcError(rpc_err) => {
                    rpc_code = rpc_err.code;
                }
                _ => {}
            }
        }

        let http = match http_code {
            x if (500..=599).contains(&x) => HttpCode::FiveHundreds,
            x if (400..=499).contains(&x) => HttpCode::FourHundreds,
            x if (200..=299).contains(&x) => HttpCode::TwoHundreds,
            _ => HttpCode::Other,
        };

        let rpc = match rpc_code {
            -32700 => RpcCode::ParseError,
            -32000 => RpcCode::ExecutionFailed,
            -32600 => RpcCode::InvalidRequest,
            -32601 => RpcCode::MethodNotFound,
            -32602 => RpcCode::InvalidParams,
            -32603 => RpcCode::InternalError,
            x if (-32099..=-32000).contains(&x) => RpcCode::ServerError,
            x if x >= 0 => RpcCode::Success,
            _ => RpcCode::Other,
        };

        counter!(
            "internal_http_response_code",
            &[("method", method_str.clone()), ("status", http.to_string())]
        )
        .increment(1);

        counter!(
            "internal_rpc_response_code",
            &[("method", method_str.clone()), ("status", rpc.to_string())]
        )
        .increment(1);

        histogram!("internal_rpc_method_response_time", "method" => method_str).record(duration);
    }
}

#[async_trait]
impl<C: JsonRpcClient<Error = HttpClientError>> JsonRpcClient for MetricsMiddleware<C> {
    type Error = HttpClientError;

    async fn request<T, R>(&self, method: &str, params: T) -> Result<R, Self::Error>
    where
        T: Debug + Serialize + Send + Sync,
        R: DeserializeOwned + Send,
    {
        let start_time = Instant::now();
        let result: Result<R, C::Error> = self.inner.request(method, params).await;
        let duration = start_time.elapsed();
        self.instrument_request(method, duration, &result);

        result
    }
}
