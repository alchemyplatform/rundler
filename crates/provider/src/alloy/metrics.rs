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

use std::task::{Context, Poll};

use alloy_json_rpc::{RequestPacket, ResponsePacket};
use alloy_transport::{BoxFuture, TransportError};
use futures_util::FutureExt;
use rundler_types::task::{
    metric_recorder::MethodSessionLogger,
    status_code::{HttpCode, RpcCode},
};
use tower::{Layer, Service};

/// Alloy provider metric layer.
#[derive(Default)]
pub(crate) struct AlloyMetricLayer {}

impl AlloyMetricLayer {}

impl<S> Layer<S> for AlloyMetricLayer
where
    S: Service<RequestPacket, Response = ResponsePacket, Error = TransportError> + Sync,
{
    // type Service = S;
    type Service = AlloyMetricMiddleware<S>;

    fn layer(&self, service: S) -> Self::Service {
        AlloyMetricMiddleware::new(service)
    }
}

pub struct AlloyMetricMiddleware<S> {
    service: S,
}

impl<S> AlloyMetricMiddleware<S>
where
    S: Service<RequestPacket, Response = ResponsePacket, Error = TransportError> + Sync,
{
    /// carete an alloy provider metric layer.
    pub fn new(service: S) -> Self {
        Self { service }
    }
}

impl<S> Clone for AlloyMetricMiddleware<S>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            service: self.service.clone(),
        }
    }
}

impl<S> Service<RequestPacket> for AlloyMetricMiddleware<S>
where
    S: Service<RequestPacket, Response = ResponsePacket, Error = TransportError>
        + Sync
        + Send
        + Clone
        + 'static,
    S::Future: Send,
{
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }
    fn call(&mut self, request: RequestPacket) -> Self::Future {
        let method_name = get_method_name(&request);
        let mut method_logger = MethodSessionLogger::new(
            "alloy_provider_client".to_string(),
            method_name,
            "rpc".to_string(),
        );
        method_logger.start();
        let mut svc = self.service.clone();
        async move {
            let response = svc.call(request).await;
            method_logger.done();
            match &response {
                Ok(resp) => {
                    method_logger.record_http(HttpCode::TwoHundreds);
                    method_logger.record_rpc(get_rpc_status_code(resp));
                }
                Err(e) => match e {
                    alloy_json_rpc::RpcError::ErrorResp(_) => {
                        method_logger.record_http(HttpCode::FiveHundreds);
                        method_logger.record_rpc(RpcCode::ServerError);
                    }
                    alloy_json_rpc::RpcError::NullResp => {
                        method_logger.record_http(HttpCode::FiveHundreds);
                        method_logger.record_rpc(RpcCode::InternalError);
                    }
                    alloy_json_rpc::RpcError::UnsupportedFeature(_) => {
                        method_logger.record_http(HttpCode::FourHundreds);
                        method_logger.record_rpc(RpcCode::MethodNotFound);
                    }
                    alloy_json_rpc::RpcError::LocalUsageError(_) => {
                        method_logger.record_http(HttpCode::FourHundreds);
                        method_logger.record_rpc(RpcCode::InvalidRequest);
                    }
                    alloy_json_rpc::RpcError::SerError(_) => {
                        method_logger.record_http(HttpCode::FiveHundreds);
                        method_logger.record_rpc(RpcCode::InternalError);
                    }
                    alloy_json_rpc::RpcError::DeserError { .. } => {
                        method_logger.record_http(HttpCode::FourHundreds);
                        method_logger.record_rpc(RpcCode::ParseError);
                    }
                    alloy_json_rpc::RpcError::Transport(transport_error) => {
                        method_logger.record_http(HttpCode::FiveHundreds);
                        method_logger.record_rpc(RpcCode::ServerError);
                    }
                },
            }
            response
        }
        .boxed()
    }
}

/// Get the method name from the request
fn get_method_name(req: &RequestPacket) -> String {
    match req {
        RequestPacket::Single(request) => request.method().to_string(),
        RequestPacket::Batch(_) => {
            // can't extract method name for batch.
            "batch".to_string()
        }
    }
}

fn get_rpc_status_code(response_packet: &ResponsePacket) -> RpcCode {
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
    rpc_code
}
