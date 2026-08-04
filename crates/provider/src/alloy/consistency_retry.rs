use std::{
    sync::LazyLock,
    task::{Context, Poll},
    time::Duration,
};

use alloy_json_rpc::{RequestPacket, ResponsePacket, RpcError};
use alloy_transport::{BoxFuture, HttpError, TransportError, TransportErrorKind};
use futures_util::FutureExt;
use metrics::Counter;
use metrics_derive::Metrics;
use regex::Regex;
use tokio::time::sleep;
use tower::{Layer, Service};
use tracing::{trace, warn};

static BLOCK_NOT_FOUND_RE: LazyLock<Regex> = LazyLock::new(|| {
    // case-insensitive; matches these strings anywhere in the error message
    Regex::new(r"(?i)(block 0x[0-9a-f]{64} not found|unknown block|block not found|header not found|is not currently canonical|header for hash not found)").unwrap()
});

/// A Transport Layer that is responsible for retrying requests based on the
/// consistency issues.
///
/// A consistency issue is when we are querying for a block that is not found.
/// This typically happens when we receive a block number via `eth_getBlockByNumber(latest)`
/// but subsequent queries for the same block number return block not found (or similar).
///
/// This is detected by checking the JSON-RPC error message, see [`consistency_error_message`]
/// for the response shapes that are inspected.
#[derive(Debug, Clone)]
pub(crate) struct ConsistencyRetryLayer {
    /// The maximum number of retries for consistency issues
    max_retries: u32,
    /// The initial backoff in milliseconds
    initial_backoff: u64,
    /// The maximum backoff in milliseconds
    max_backoff: u64,
}

impl ConsistencyRetryLayer {
    /// Creates a new consistency retry layer with the given parameters.
    pub(crate) const fn new(max_retries: u32, initial_backoff: u64, max_backoff: u64) -> Self {
        Self {
            max_retries,
            initial_backoff,
            max_backoff,
        }
    }
}

impl<S> Layer<S> for ConsistencyRetryLayer {
    type Service = ConsistencyRetryService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ConsistencyRetryService {
            inner,
            max_retries: self.max_retries,
            initial_backoff: self.initial_backoff,
            max_backoff: self.max_backoff,
        }
    }
}

/// A Tower Service used by the ConsistencyRetryLayer that is responsible for retrying requests based
/// on consistency issues.
#[derive(Debug, Clone)]
pub(crate) struct ConsistencyRetryService<S> {
    /// The service
    inner: S,
    /// The maximum number of retries for consistency issues
    max_retries: u32,
    /// The initial backoff in milliseconds
    initial_backoff: u64,
    /// The maximum backoff in milliseconds
    max_backoff: u64,
}

impl<S> ConsistencyRetryService<S> {
    const fn initial_backoff(&self) -> Duration {
        Duration::from_millis(self.initial_backoff)
    }

    const fn max_backoff(&self) -> Duration {
        Duration::from_millis(self.max_backoff)
    }
}

impl<S> Service<RequestPacket> for ConsistencyRetryService<S>
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
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: RequestPacket) -> Self::Future {
        let max_retries = self.max_retries;
        let initial_backoff = self.initial_backoff();
        let max_backoff = self.max_backoff();
        let mut inner = self.inner.clone();

        async move {
            let metrics = ConsistencyRetryMetrics::default();
            let mut retry_number: u32 = 0;
            loop {
                let resp = inner.call(request.clone()).await;

                let Some(err_message) = consistency_error_message(&resp) else {
                    return resp;
                };

                if retry_number < max_retries {
                    retry_number += 1;
                    metrics.retries.increment(1);
                    let next_backoff = initial_backoff
                        .saturating_mul(2u32.saturating_pow(retry_number - 1))
                        .min(max_backoff);

                    trace!(
                        next_backoff_millis = next_backoff.as_millis(),
                        "(all in ms) backing off due to provider consistency error"
                    );

                    sleep(next_backoff).await;
                } else {
                    // We should retry but have exceeded max retries
                    metrics.max_retries_exceeded.increment(1);
                    warn!("Max retries exceeded for consistency error: {err_message}");
                    return resp;
                }
            }
        }
        .boxed()
    }
}

/// Returns the error message that identifies `resp` as a consistency error, if there is one.
///
/// A node can report a consistency error in three different shapes, all of which are inspected
/// here:
///
/// * A JSON-RPC error payload returned with HTTP 200. Alloy converts a `Failure` payload into
///   [`RpcError::ErrorResp`] in `transform_response`, which runs *above* the transport stack, so a
///   transport layer receives it as `Ok(ResponsePacket)` with a `Failure` payload. This is the
///   common shape: nodes answering `-32000 header not found` do so with HTTP 200.
/// * An [`RpcError::ErrorResp`], in case a layer above this one has already performed that
///   conversion.
/// * A non-2xx HTTP response carrying the message in its body.
///
/// For batch responses, any sub-response reporting a consistency error retries the whole packet.
/// Rundler only issues single requests today, and retrying the successful sub-requests of a batch
/// is harmless for the read methods this layer protects.
fn consistency_error_message(resp: &Result<ResponsePacket, TransportError>) -> Option<String> {
    let message = match resp {
        Ok(packet) => {
            return packet
                .iter_errors()
                .map(|err_payload| err_payload.message.as_ref())
                .find(|message| should_retry_error(message))
                .map(ToString::to_string);
        }
        Err(RpcError::ErrorResp(err_payload)) => err_payload.message.as_ref(),
        Err(RpcError::Transport(TransportErrorKind::HttpError(HttpError { status: _, body }))) => {
            body.as_str()
        }
        Err(_) => return None,
    };

    should_retry_error(message).then(|| message.to_string())
}

// Determine if we should retry based on the error message.
fn should_retry_error(error: &str) -> bool {
    BLOCK_NOT_FOUND_RE.is_match(error)
}

#[derive(Metrics)]
#[metrics(scope = "provider_consistency_retry")]
struct ConsistencyRetryMetrics {
    #[metric(describe = "the count of consistency retries.")]
    retries: Counter,
    #[metric(describe = "the count of failures due to max retries exceeded.")]
    max_retries_exceeded: Counter,
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use alloy_json_rpc::{ErrorPayload, Id, Request, Response, ResponsePayload};
    use alloy_primitives::B256;
    use serde_json::value::RawValue;
    use tower::{ServiceExt, util::service_fn};

    use super::*;

    const MAX_RETRIES: u32 = 3;

    #[tokio::test(start_paused = true)]
    async fn retries_error_payload_delivered_as_ok() {
        // A node answering "-32000 header not found" over HTTP 200 reaches a transport layer as
        // `Ok(ResponsePacket)` with a `Failure` payload, not as `Err(RpcError::ErrorResp)`.
        let calls = call_service(|_| async { Ok(error_packet("header not found")) }).await;

        assert_eq!(calls, MAX_RETRIES + 1);
    }

    #[tokio::test(start_paused = true)]
    async fn retries_error_resp() {
        let calls =
            call_service(|_| async { Err(RpcError::ErrorResp(error_payload("header not found"))) })
                .await;

        assert_eq!(calls, MAX_RETRIES + 1);
    }

    #[tokio::test(start_paused = true)]
    async fn retries_http_error_body() {
        let calls = call_service(|_| async {
            Err(TransportErrorKind::http_error(
                503,
                "header not found".to_string(),
            ))
        })
        .await;

        assert_eq!(calls, MAX_RETRIES + 1);
    }

    #[tokio::test(start_paused = true)]
    async fn retries_batch_with_consistency_error() {
        let calls = call_service(|_| async {
            Ok(ResponsePacket::Batch(vec![
                success_response(Id::Number(1)),
                Response {
                    id: Id::Number(2),
                    payload: ResponsePayload::Failure(error_payload("header not found")),
                },
            ]))
        })
        .await;

        assert_eq!(calls, MAX_RETRIES + 1);
    }

    #[tokio::test(start_paused = true)]
    async fn returns_response_once_consistent() {
        let calls = Arc::new(AtomicUsize::new(0));
        let response = call_counting_service(calls.clone(), |call_number| async move {
            if call_number == 0 {
                Ok(error_packet("header not found"))
            } else {
                Ok(ResponsePacket::Single(success_response(Id::Number(1))))
            }
        })
        .await
        .expect("should return the successful response");

        assert!(response.is_success());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn does_not_retry_success() {
        let calls =
            call_service(|_| async { Ok(ResponsePacket::Single(success_response(Id::Number(1)))) })
                .await;

        assert_eq!(calls, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn does_not_retry_unrelated_error_payload() {
        let calls = call_service(|_| async { Ok(error_packet("execution reverted")) }).await;

        assert_eq!(calls, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn does_not_retry_unrelated_transport_error() {
        let calls = call_service(|_| async { Err(TransportErrorKind::backend_gone()) }).await;

        assert_eq!(calls, 1);
    }

    #[test]
    fn matches_known_consistency_errors() {
        let messages = [
            "header not found",
            "Header not found",
            "block not found",
            "unknown block",
            "header for hash not found",
            "requested epoch was a null round, or is not currently canonical",
            &format!("block {:#x} not found", B256::repeat_byte(1)),
        ];

        for message in messages {
            assert!(should_retry_error(message), "message: {message}");
        }
    }

    #[test]
    fn ignores_unrelated_errors() {
        for message in ["execution reverted", "insufficient funds", "nonce too low"] {
            assert!(!should_retry_error(message), "message: {message}");
        }
    }

    // Calls the layer with a service built from `respond`, returning how many times the inner
    // service was called.
    async fn call_service<F, Fut>(respond: F) -> u32
    where
        F: FnMut(usize) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = Result<ResponsePacket, TransportError>> + Send,
    {
        let calls = Arc::new(AtomicUsize::new(0));
        let _ = call_counting_service(calls.clone(), respond).await;
        calls.load(Ordering::SeqCst) as u32
    }

    // Drives one request through the layer, passing the current call count to `respond` and
    // incrementing it on every call.
    async fn call_counting_service<F, Fut>(
        calls: Arc<AtomicUsize>,
        mut respond: F,
    ) -> Result<ResponsePacket, TransportError>
    where
        F: FnMut(usize) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = Result<ResponsePacket, TransportError>> + Send,
    {
        let inner = service_fn(move |_: RequestPacket| {
            let call_number = calls.fetch_add(1, Ordering::SeqCst);
            respond(call_number)
        });
        // Backoffs are irrelevant under a paused clock, but keep them small anyway.
        let mut service = ConsistencyRetryLayer::new(MAX_RETRIES, 1, 10).layer(inner);

        service.ready().await.unwrap().call(request()).await
    }

    fn request() -> RequestPacket {
        RequestPacket::Single(
            Request::new("eth_getBlockByNumber", Id::Number(1), ())
                .serialize()
                .unwrap(),
        )
    }

    fn error_packet(message: &str) -> ResponsePacket {
        ResponsePacket::Single(Response {
            id: Id::Number(1),
            payload: ResponsePayload::Failure(error_payload(message)),
        })
    }

    fn error_payload(message: &str) -> ErrorPayload {
        ErrorPayload {
            code: -32000,
            message: message.to_string().into(),
            data: None,
        }
    }

    fn success_response(id: Id) -> Response {
        Response {
            id,
            payload: ResponsePayload::Success(
                RawValue::from_string("\"0x1\"".to_string()).unwrap(),
            ),
        }
    }
}
