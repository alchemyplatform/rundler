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
/// This is detected by checking the JSON-RPC error message.
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

                let err = match &resp {
                    Ok(_) => return resp,
                    Err(e) => e,
                };

                // Extract the error message from the error
                let err_payload = match &err {
                    RpcError::ErrorResp(err_payload) => err_payload.message.to_string(),
                    RpcError::Transport(TransportErrorKind::HttpError(HttpError {
                        status: _,
                        body,
                    })) => body.to_string(),
                    _ => return resp,
                };

                let should_retry = should_retry_error(&err_payload);
                if should_retry && retry_number < max_retries {
                    retry_number += 1;
                    metrics.retries.increment(1);
                    let next_backoff = initial_backoff
                        .saturating_mul(2u32.saturating_pow(retry_number - 1))
                        .min(max_backoff);

                    trace!(
                        next_backoff_millis = next_backoff.as_millis(),
                        "(all in ms) backing off due to provider server error"
                    );

                    sleep(next_backoff).await;
                } else {
                    if should_retry {
                        // We should retry but have exceeded max retries
                        metrics.max_retries_exceeded.increment(1);
                        warn!("Max retries exceeded for consistency error: {err_payload}");
                    }
                    return resp;
                }
            }
        }
        .boxed()
    }
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
