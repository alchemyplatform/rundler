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
                    method_logger.record_rpc(get_rpc_status_code(&method_name, resp));
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
                            method_logger.record_rpc(get_rpc_status_from_error(
                                &method_name,
                                &rpc_error.message,
                                rpc_error.code,
                            ));
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

/// Maps an RPC error to the status code recorded in metrics.
///
/// Known transaction submission errors are handled by Rundler and tracked by dedicated
/// builder metrics, so they are recorded as success here to keep them out of provider
/// RPC error alerting.
fn get_rpc_status_from_error(method_name: &str, message: &str, code: i64) -> RpcCode {
    let is_submission_method = matches!(
        method_name,
        "eth_sendRawTransaction"
            | "eth_sendRawTransactionConditional"
            | "eth_sendRawTransactionPrivate"
    );
    if is_submission_method && transaction::classify_submission_error(message, code).is_some() {
        RpcCode::Success
    } else {
        get_rpc_status_from_code(code)
    }
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

fn get_rpc_status_code(method_name: &str, response_packet: &ResponsePacket) -> RpcCode {
    let response: &alloy_json_rpc::Response = match response_packet {
        ResponsePacket::Batch(resps) => {
            if resps.is_empty() {
                return RpcCode::Success;
            }
            &resps[0]
        }
        ResponsePacket::Single(resp) => resp,
    };
    match &response.payload {
        alloy_json_rpc::ResponsePayload::Success(_) => RpcCode::Success,
        alloy_json_rpc::ResponsePayload::Failure(error_payload) => {
            get_rpc_status_from_error(method_name, &error_payload.message, error_payload.code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RpcCode;

    #[test]
    fn maps_handled_transaction_submission_errors_to_success() {
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
                    matches!(
                        super::get_rpc_status_from_error(method, message, code),
                        RpcCode::Success
                    ),
                    "method: {method}, message: {message}"
                );
            }
        }
    }

    #[test]
    fn maps_unknown_transaction_submission_errors_to_server_error() {
        assert!(matches!(
            super::get_rpc_status_from_error("eth_sendRawTransaction", "internal error", -32000),
            RpcCode::ServerError
        ));
    }

    #[test]
    fn maps_known_error_to_server_error_for_other_rpc_methods() {
        assert!(matches!(
            super::get_rpc_status_from_error("eth_call", "nonce too low", -32000),
            RpcCode::ServerError
        ));
    }
}
