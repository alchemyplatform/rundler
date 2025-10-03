use std::{
    task::{Context, Poll},
    time::Duration,
};

use alloy_json_rpc::{ErrorPayload, RequestPacket, ResponsePacket};
use alloy_transport::{BoxFuture, TransportError, TransportErrorKind, TransportFut};
use futures_util::FutureExt;
use once_cell::sync::Lazy;
use regex::Regex;
use tokio::time::sleep;
use tower::{Layer, Service};
use tracing::trace;

static BLOCK_NOT_FOUND_RE: Lazy<Regex> = Lazy::new(|| {
    // case-insensitive; 0x + 64 hex chars
    Regex::new(r"(?i)^block 0x[0-9a-f]{64} not found$").unwrap()
});

/// A Transport Layer that is responsible for retrying requests based on the
/// error type. See [`TransportError`].
///
/// TransportError: crate::error::TransportError
#[derive(Debug, Clone)]
pub(crate) struct RetryBackoffLayer {
    /// The maximum number of retries for rate limit errors
    max_retries: u32,
    /// The initial backoff in milliseconds
    initial_backoff: u64,
    /// The maximum backoff in milliseconds
    max_backoff: u64,
}

impl RetryBackoffLayer {
    /// Creates a new retry layer with the given parameters.
    pub(crate) const fn new(max_retries: u32, initial_backoff: u64, max_backoff: u64) -> Self {
        Self {
            max_retries,
            initial_backoff,
            max_backoff,
        }
    }
}

impl<S> Layer<S> for RetryBackoffLayer {
    type Service = RetryBackoffService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RetryBackoffService {
            inner,
            max_retries: self.max_retries,
            initial_backoff: self.initial_backoff,
            max_backoff: self.max_backoff,
        }
    }
}

/// A Tower Service used by the RetryBackoffLayer that is responsible for retrying requests based
/// on the server error ErrorPayload message.
#[derive(Debug, Clone)]
pub(crate) struct RetryBackoffService<S> {
    /// The inner service
    inner: S,
    /// The maximum number of retries for rate limit errors
    max_retries: u32,
    /// The initial backoff in milliseconds
    initial_backoff: u64,
    /// The maximum backoff in milliseconds
    max_backoff: u64,
}

impl<S> RetryBackoffService<S> {
    const fn initial_backoff(&self) -> Duration {
        Duration::from_millis(self.initial_backoff)
    }

    const fn max_backoff(&self) -> Duration {
        Duration::from_millis(self.max_backoff)
    }
}

impl<S> Service<RequestPacket> for RetryBackoffService<S>
where
    S: Service<RequestPacket, Future = TransportFut<'static>, Error = TransportError>
        + Send
        + 'static
        + Clone,
{
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Our middleware doesn't care about backpressure, so it's ready as long
        // as the inner service is ready.
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: RequestPacket) -> Self::Future {
        let inner = self.inner.clone();
        let this = self.clone();
        let mut inner = std::mem::replace(&mut self.inner, inner);
        async move {
            let mut retry_number: u32 = 0;
            loop {
                // Immediately return error if the transport itself failed.
                let resp = inner.call(request.clone()).await?;

                // Immediately return if it is success response.
                let err = match resp.as_error() {
                    Some(e) => e,
                    None => return Ok(resp),
                };

                let should_retry = this.should_retry(err);
                if should_retry {
                    retry_number += 1;
                    if retry_number > this.max_retries {
                        return Err(TransportErrorKind::custom_str(&format!(
                            "Max retries exceeded {err}"
                        )));
                    }

                    trace!(%err, "retrying request");

                    let next_backoff = this
                        .initial_backoff()
                        .saturating_mul(2u32.saturating_pow(retry_number - 1))
                        .min(this.max_backoff());

                    trace!(
                        next_backoff_millis = next_backoff.as_millis(),
                        "(all in ms) backing off due to provider server error"
                    );

                    sleep(next_backoff).await;
                } else {
                    return Err(TransportError::ErrorResp(err.clone()));
                }
            }
        }
        .boxed()
    }
}

impl<S> RetryBackoffService<S> {
    /// Determines if we should retry based on the error type.
    fn should_retry(&self, error: &ErrorPayload) -> bool {
        BLOCK_NOT_FOUND_RE.is_match(&error.message)
    }
}
