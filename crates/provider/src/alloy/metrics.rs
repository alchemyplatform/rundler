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
use alloy_transport::{BoxFuture, HttpError, TransportError, TransportErrorKind};
use futures_util::FutureExt;
use rundler_types::task::{
    metric_recorder::MethodSessionLogger,
    status_code::{HttpCode, RpcCode},
};
use tower::{Layer, Service};

use crate::transaction;

/// Alloy provider metric layer.
#[derive(Default)]
pub(crate) struct AlloyMetricLayer {}

impl AlloyMetricLayer {}

impl<S> Layer<S> for AlloyMetricLayer
where
    S: Service<RequestPacket, Response = ResponsePacket, Error = TransportError> + Sync,
{
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
        let method_logger = MethodSessionLogger::start(
            "alloy_provider_client".to_string(),
            method_name.clone(),
            "rpc".to_string(),
        );
        let fut = self.service.call(request);
        async move {
            let response = fut.await;
            method_logger.done();
            match &response {
                Ok(resp) => {
                    method_logger.record_http(HttpCode::TwoHundreds);
                    if resp.as_error().is_none_or(|error| {
                        should_record_rpc_status(&method_name, &error.message, error.code)
                    }) {
                        method_logger.record_rpc(get_rpc_status_code(resp));
                    }
                    if resp.is_error() {
                        let error = resp.as_error().unwrap();
                        if error.code < 0 {
                            tracing::warn!(
                                "alloy provider of method {} response with error: {}",
                                &method_name,
                                error
                            );
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "alloy provider of method {} response with error: {e:?}",
                        &method_name,
                    );
                    match e {
                        alloy_json_rpc::RpcError::ErrorResp(rpc_error) => {
                            method_logger.record_http(HttpCode::TwoHundreds);
                            if should_record_rpc_status(
                                &method_name,
                                &rpc_error.message,
                                rpc_error.code,
                            ) {
                                method_logger.record_rpc(get_rpc_status_from_code(rpc_error.code));
                            }
                        }
                        alloy_json_rpc::RpcError::Transport(TransportErrorKind::HttpError(
                            HttpError { status, body: _ },
                        )) => {
                            method_logger.record_http(get_http_status_from_code(*status));
                        }
                        alloy_json_rpc::RpcError::NullResp => {
                            method_logger.record_http(HttpCode::TwoHundreds);
                            method_logger.record_rpc(RpcCode::Success);
                        }
                        // for timeout error
                        alloy_json_rpc::RpcError::LocalUsageError(_) => {
                            method_logger.record_http(HttpCode::FourHundreds);
                            method_logger.record_rpc(RpcCode::ClientSideTimeout);
                        }
                        _ => {}
                    }
                }
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

fn should_record_rpc_status(method_name: &str, message: &str, code: i64) -> bool {
    if !matches!(
        method_name,
        "eth_sendRawTransaction"
            | "eth_sendRawTransactionConditional"
            | "eth_sendRawTransactionPrivate"
    ) {
        return true;
    }

    transaction::classify_submission_error(message, code).is_none()
}

fn get_rpc_status_from_code(code: i64) -> RpcCode {
    match code {
        -32700 => RpcCode::ParseError,
        -32600 => RpcCode::InvalidRequest,
        -32601 => RpcCode::MethodNotFound,
        -32602 => RpcCode::InvalidParams,
        -32603 => RpcCode::InternalError,
        x if (-32099..=-32000).contains(&x) => RpcCode::ServerError,
        x if x >= 0 => RpcCode::Success,
        _ => RpcCode::Other,
    }
}

fn get_http_status_from_code(code: u16) -> HttpCode {
    match code {
        x if (200..=299).contains(&x) => HttpCode::TwoHundreds,
        x if (400..=499).contains(&x) => HttpCode::FourHundreds,
        x if (500..=599).contains(&x) => HttpCode::FiveHundreds,
        _ => HttpCode::Other,
    }
}

fn get_rpc_status_code(response_packet: &ResponsePacket) -> RpcCode {
    let response: &alloy_json_rpc::Response = match response_packet {
        ResponsePacket::Batch(resps) => {
            if resps.is_empty() {
                return RpcCode::Success;
            }
            &resps[0]
        }
        ResponsePacket::Single(resp) => resp,
    };
    let response_code: i64 = match &response.payload {
        alloy_json_rpc::ResponsePayload::Success(_) => 0,
        alloy_json_rpc::ResponsePayload::Failure(error_payload) => error_payload.code,
    };
    get_rpc_status_from_code(response_code)
}

#[cfg(test)]
mod tests {
    #[test]
    fn filters_handled_transaction_submission_errors() {
        let cases = [
            ("nonce too low", -32000),
            ("replacement transaction underpriced", -32000),
            ("transaction underpriced", -32000),
            ("insufficient funds for gas * price + value", -32000),
            ("storage slot value condition not met", -32000),
            ("future transaction tries to replace pending", -32000),
        ];
        let methods = [
            "eth_sendRawTransaction",
            "eth_sendRawTransactionConditional",
            "eth_sendRawTransactionPrivate",
        ];

        for method in methods {
            for (message, code) in cases {
                assert!(
                    !super::should_record_rpc_status(method, message, code),
                    "method: {method}, message: {message}"
                );
            }
        }
    }

    #[test]
    fn records_unknown_transaction_submission_errors() {
        assert!(super::should_record_rpc_status(
            "eth_sendRawTransaction",
            "internal error",
            -32000,
        ));
    }

    #[test]
    fn records_known_error_for_other_rpc_methods() {
        assert!(super::should_record_rpc_status(
            "eth_call",
            "nonce too low",
            -32000,
        ));
    }
}
