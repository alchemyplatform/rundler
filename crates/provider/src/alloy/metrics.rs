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

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use alloy_json_rpc::{RequestPacket, ResponsePacket};
use alloy_transport::TransportError;
use pin_project::pin_project;
use rundler_types::task::{
    metrics::MethodSessionLogger,
    status_code::{HttpCode, RpcCode},
};
use tower::{Layer, Service};

#[allow(dead_code)]
/// Alloy provider metric layer.
pub(crate) struct AlloyMetricLayer {}

impl AlloyMetricLayer {
    #[allow(dead_code)]
    pub(crate) fn new() -> Self {
        Self {}
    }
}

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

pub(crate) struct AlloyMetricMiddleware<S> {
    service: S,
}

impl<S> AlloyMetricMiddleware<S>
where
    S: Service<RequestPacket, Response = ResponsePacket, Error = TransportError> + Sync,
{
    /// carete an alloy provider metric layer.
    pub(crate) fn new(service: S) -> Self {
        Self { service }
    }
}

impl<S> Service<RequestPacket> for AlloyMetricMiddleware<S>
where
    S: Service<RequestPacket, Response = ResponsePacket, Error = TransportError> + Sync + Send,
{
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = ResponseFuture<S::Future>;

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
        let call_future = self.service.call(request);

        ResponseFuture {
            response_future: call_future,
            method_logger,
        }
    }
}
#[pin_project]
pub struct ResponseFuture<F> {
    #[pin]
    response_future: F,
    method_logger: MethodSessionLogger,
}

impl<F> Future for ResponseFuture<F>
where
    F: Future<Output = Result<ResponsePacket, TransportError>>,
{
    type Output = Result<ResponsePacket, TransportError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let res = this.response_future.poll(cx);
        match &res {
            Poll::Ready(response) => {
                this.method_logger.done();
                match response {
                    Ok(ref resp) => {
                        this.method_logger.record_http(HttpCode::TwoHundreds);
                        this.method_logger.record_rpc(get_rpc_status_code(resp));
                    }
                    Err(ref e) => match e {
                        alloy_json_rpc::RpcError::ErrorResp(_) => {
                            this.method_logger.record_http(HttpCode::FiveHundreds);
                            this.method_logger.record_rpc(RpcCode::ServerError);
                        }
                        alloy_json_rpc::RpcError::NullResp => {
                            this.method_logger.record_http(HttpCode::FiveHundreds);
                            this.method_logger.record_rpc(RpcCode::InternalError);
                        }
                        alloy_json_rpc::RpcError::UnsupportedFeature(_) => {
                            this.method_logger.record_http(HttpCode::FourHundreds);
                            this.method_logger.record_rpc(RpcCode::MethodNotFound);
                        }
                        alloy_json_rpc::RpcError::LocalUsageError(_) => {
                            this.method_logger.record_http(HttpCode::FourHundreds);
                            this.method_logger.record_rpc(RpcCode::InvalidRequest);
                        }
                        alloy_json_rpc::RpcError::SerError(_) => {
                            this.method_logger.record_http(HttpCode::FiveHundreds);
                            this.method_logger.record_rpc(RpcCode::InternalError);
                        }
                        alloy_json_rpc::RpcError::DeserError { .. } => {
                            this.method_logger.record_http(HttpCode::FourHundreds);
                            this.method_logger.record_rpc(RpcCode::ParseError);
                        }
                        alloy_json_rpc::RpcError::Transport(_) => {
                            this.method_logger.record_http(HttpCode::FiveHundreds);
                            this.method_logger.record_rpc(RpcCode::ServerError);
                        }
                    },
                }
            }
            Poll::Pending => {}
        };
        res
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
