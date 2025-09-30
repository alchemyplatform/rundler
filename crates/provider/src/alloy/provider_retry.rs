use std::{
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};

use alloy_json_rpc::{ErrorPayload, RequestPacket, ResponsePacket};
use alloy_transport::{RpcError, TransportError, TransportErrorKind, TransportFut};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Deserialize;
#[cfg(not(target_family = "wasm"))]
use tokio::time::sleep;
use tower::{Layer, Service};
use tracing::trace;
#[cfg(target_family = "wasm")]
use wasmtimer::tokio::sleep;

static BLOCK_NOT_FOUND_RE: Lazy<Regex> = Lazy::new(|| {
    // case-insensitive; 0x + 64 hex chars
    Regex::new(r"(?i)^block 0x[0-9a-fA-F]{64} not found$").unwrap()
});

/// The default average cost of a request in compute units (CU).
const DEFAULT_AVG_COST: u64 = 17u64;

/// A Transport Layer that is responsible for retrying requests based on the
/// error type. See [`TransportError`].
///
/// TransportError: crate::error::TransportError
#[derive(Debug, Clone)]
pub(crate) struct RetryBackoffLayer<P: RetryPolicy = ProviderRetryPolicy> {
    /// The maximum number of retries for rate limit errors
    max_retries: u32,
    /// The initial backoff in milliseconds
    initial_backoff: u64,
    /// The number of compute units per second for this provider
    compute_units_per_second: u64,
    /// The average cost of a request. Defaults to [DEFAULT_AVG_COST]
    avg_cost: u64,
    /// The [RetryPolicy] to use. Defaults to [ProviderRetryPolicy]
    policy: P,
}

impl RetryBackoffLayer {
    /// Creates a new retry layer with the given parameters and the default [ProviderRetryPolicy].
    pub(crate) const fn new(
        max_retries: u32,
        initial_backoff: u64,
        compute_units_per_second: u64,
    ) -> Self {
        Self {
            max_retries,
            initial_backoff,
            compute_units_per_second,
            avg_cost: DEFAULT_AVG_COST,
            policy: ProviderRetryPolicy,
        }
    }
}

/// [ProviderRetryPolicy] implements [RetryPolicy] to determine whether to retry depending on the
/// err.
#[derive(Debug, Copy, Clone, Default)]
#[non_exhaustive]
pub(crate) struct ProviderRetryPolicy;

/// [RetryPolicy] defines logic for which [TransportError] instances should
/// the client retry the request and try to recover from.
pub(crate) trait RetryPolicy: Send + Sync + std::fmt::Debug {
    /// Whether to retry the request based on the given `error`
    fn should_retry(&self, error: &TransportError) -> bool;

    /// Providers may include the `backoff` in the error response directly
    fn backoff_hint(&self, error: &TransportError) -> Option<std::time::Duration>;
}

impl RetryPolicy for ProviderRetryPolicy {
    fn should_retry(&self, error: &TransportError) -> bool {
        error.is_retryable()
    }

    /// Provides a backoff hint if the error response contains it
    fn backoff_hint(&self, error: &TransportError) -> Option<std::time::Duration> {
        error.backoff_hint()
    }
}

/// Extension trait to implement methods for [`RpcError<TransportErrorKind, E>`].
pub(crate) trait RpcErrorExt {
    /// Analyzes whether to retry the request depending on the error.
    fn is_retryable(&self) -> bool;

    /// Fetches the backoff hint from the error message if present
    fn backoff_hint(&self) -> Option<std::time::Duration>;
}

impl RpcErrorExt for RpcError<TransportErrorKind> {
    fn is_retryable(&self) -> bool {
        match self {
            // There was a transport-level error. This is either a non-retryable error,
            // or a server error that should be retried.
            Self::Transport(err) => err.is_retry_err(),
            // The transport could not serialize the error itself. The request was malformed from
            // the start.
            Self::SerError(_) => false,
            Self::DeserError { text, .. } => {
                if let Ok(resp) = serde_json::from_str::<ErrorPayload>(text) {
                    return resp.is_retry_err();
                }

                // some providers send invalid JSON RPC in the error case (no `id:u64`), but the
                // text should be a `JsonRpcError`
                #[derive(Deserialize)]
                struct Resp {
                    error: ErrorPayload,
                }

                if let Ok(resp) = serde_json::from_str::<Resp>(text) {
                    return resp.error.is_retry_err();
                }

                false
            }
            Self::ErrorResp(err) => {
                err.is_retry_err() || {
                    // Not only rate limit errors should be retried, but also spefified server errors from node providers.
                    BLOCK_NOT_FOUND_RE.is_match(&err.message)
                }
            }
            Self::NullResp => true,
            _ => false,
        }
    }

    fn backoff_hint(&self) -> Option<std::time::Duration> {
        if let Self::ErrorResp(resp) = self {
            let data = resp.try_data_as::<serde_json::Value>();
            if let Some(Ok(data)) = data {
                // if daily rate limit exceeded, infura returns the requested backoff in the error
                // response
                let backoff_seconds = &data["rate"]["backoff_seconds"];
                // infura rate limit error
                if let Some(seconds) = backoff_seconds.as_u64() {
                    return Some(std::time::Duration::from_secs(seconds));
                }
                if let Some(seconds) = backoff_seconds.as_f64() {
                    return Some(std::time::Duration::from_secs(seconds as u64 + 1));
                }
            }
        }
        None
    }
}

impl<S, P: RetryPolicy + Clone> Layer<S> for RetryBackoffLayer<P> {
    type Service = RetryBackoffService<S, P>;

    fn layer(&self, inner: S) -> Self::Service {
        RetryBackoffService {
            inner,
            policy: self.policy.clone(),
            max_retries: self.max_retries,
            initial_backoff: self.initial_backoff,
            compute_units_per_second: self.compute_units_per_second,
            requests_enqueued: Arc::new(AtomicU32::new(0)),
            avg_cost: self.avg_cost,
        }
    }
}

/// A Tower Service used by the RetryBackoffLayer that is responsible for retrying requests based
/// on the error type. See [TransportError] and [ProviderRetryPolicy].
#[derive(Debug, Clone)]
pub(crate) struct RetryBackoffService<S, P: RetryPolicy = ProviderRetryPolicy> {
    /// The inner service
    inner: S,
    /// The [RetryPolicy] to use.
    policy: P,
    /// The maximum number of retries for rate limit errors
    max_retries: u32,
    /// The initial backoff in milliseconds
    initial_backoff: u64,
    /// The number of compute units per second for this service
    compute_units_per_second: u64,
    /// The number of requests currently enqueued
    requests_enqueued: Arc<AtomicU32>,
    /// The average cost of a request.
    avg_cost: u64,
}

impl<S, P: RetryPolicy> RetryBackoffService<S, P> {
    const fn initial_backoff(&self) -> Duration {
        Duration::from_millis(self.initial_backoff)
    }
}

impl<S, P> Service<RequestPacket> for RetryBackoffService<S, P>
where
    S: Service<RequestPacket, Future = TransportFut<'static>, Error = TransportError>
        + Send
        + 'static
        + Clone,
    P: RetryPolicy + Clone + 'static,
{
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = TransportFut<'static>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Our middleware doesn't care about backpressure, so it's ready as long
        // as the inner service is ready.
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: RequestPacket) -> Self::Future {
        let inner = self.inner.clone();
        let this = self.clone();
        let mut inner = std::mem::replace(&mut self.inner, inner);
        Box::pin(async move {
            let ahead_in_queue = this.requests_enqueued.fetch_add(1, Ordering::SeqCst) as u64;
            let mut retry_number: u32 = 0;
            loop {
                let err;
                let res = inner.call(request.clone()).await;

                match res {
                    Ok(res) => {
                        if let Some(e) = res.as_error() {
                            err = TransportError::ErrorResp(e.clone())
                        } else {
                            this.requests_enqueued.fetch_sub(1, Ordering::SeqCst);
                            return Ok(res);
                        }
                    }
                    Err(e) => err = e,
                }

                let should_retry = this.policy.should_retry(&err);
                if should_retry {
                    retry_number += 1;
                    if retry_number > this.max_retries {
                        return Err(TransportErrorKind::custom_str(&format!(
                            "Max retries exceeded {err}"
                        )));
                    }
                    trace!(%err, "retrying request");

                    let current_queued_reqs = this.requests_enqueued.load(Ordering::SeqCst) as u64;

                    // try to extract the requested backoff from the error or compute the next
                    // backoff based on retry count
                    let backoff_hint = this.policy.backoff_hint(&err);
                    let next_backoff = backoff_hint.unwrap_or_else(|| this.initial_backoff());

                    let seconds_to_wait_for_compute_budget = compute_unit_offset_in_secs(
                        this.avg_cost,
                        this.compute_units_per_second,
                        current_queued_reqs,
                        ahead_in_queue,
                    );
                    let total_backoff = next_backoff
                        + std::time::Duration::from_secs(seconds_to_wait_for_compute_budget);

                    trace!(
                        total_backoff_millis = total_backoff.as_millis(),
                        budget_backoff_millis = seconds_to_wait_for_compute_budget * 1000,
                        default_backoff_millis = next_backoff.as_millis(),
                        backoff_hint_millis = backoff_hint.map(|d| d.as_millis()),
                        "(all in ms) backing off due to rate limit"
                    );

                    sleep(total_backoff).await;
                } else {
                    this.requests_enqueued.fetch_sub(1, Ordering::SeqCst);
                    return Err(err);
                }
            }
        })
    }
}

/// Calculates an offset in seconds by taking into account the number of currently queued requests,
/// number of requests that were ahead in the queue when the request was first issued, the average
/// cost a weighted request (heuristic), and the number of available compute units per seconds.
///
/// Returns the number of seconds (the unit the remote endpoint measures compute budget) a request
/// is supposed to wait to not get rate limited. The budget per second is
/// `compute_units_per_second`, assuming an average cost of `avg_cost` this allows (in theory)
/// `compute_units_per_second / avg_cost` requests per seconds without getting rate limited.
/// By taking into account the number of concurrent request and the position in queue when the
/// request was first issued and determine the number of seconds a request is supposed to wait, if
/// at all
fn compute_unit_offset_in_secs(
    avg_cost: u64,
    compute_units_per_second: u64,
    current_queued_requests: u64,
    ahead_in_queue: u64,
) -> u64 {
    let request_capacity_per_second = compute_units_per_second.saturating_div(avg_cost).max(1);
    if current_queued_requests > request_capacity_per_second {
        current_queued_requests
            .min(ahead_in_queue)
            .saturating_div(request_capacity_per_second)
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_units_per_second() {
        let offset = compute_unit_offset_in_secs(17, 10, 0, 0);
        assert_eq!(offset, 0);
        let offset = compute_unit_offset_in_secs(17, 10, 2, 2);
        assert_eq!(offset, 2);
    }
}
