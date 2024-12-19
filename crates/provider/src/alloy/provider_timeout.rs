//! Middleware that applies a timeout to requests.
//!
//! If the response does not complete within the specified timeout, the response
//! will be aborted.

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use alloy_json_rpc::{RequestPacket, ResponsePacket};
use alloy_transport::TransportError;
use pin_project::pin_project;
use tokio::time::Sleep;
use tower::{Layer, Service};

/// Applies a timeout to requests via the supplied inner service.
#[derive(Debug, Clone)]
pub(crate) struct ProviderTimeoutLayer {
    timeout: Duration,
}

impl ProviderTimeoutLayer {
    /// Create a timeout from a duration
    pub(crate) fn new(timeout: Duration) -> Self {
        ProviderTimeoutLayer { timeout }
    }
}

impl<S> Layer<S> for ProviderTimeoutLayer
where
    S: Service<RequestPacket, Response = ResponsePacket, Error = TransportError> + Sync,
{
    type Service = ProviderTimeout<S>;

    fn layer(&self, service: S) -> Self::Service {
        ProviderTimeout::new(service, self.timeout)
    }
}

/// Applies a timeout to requests.
#[derive(Debug)]
pub struct ProviderTimeout<S> {
    service: S,
    timeout: Duration,
}

// ===== impl Timeout =====

impl<S> ProviderTimeout<S>
where
    S: Service<RequestPacket, Response = ResponsePacket, Error = TransportError> + Sync,
{
    /// Creates a new [`Timeout`]
    pub const fn new(service: S, timeout: Duration) -> Self {
        ProviderTimeout { service, timeout }
    }
}

impl<S> Clone for ProviderTimeout<S>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            service: self.service.clone(),
            timeout: self.timeout,
        }
    }
}
impl<S> Service<RequestPacket> for ProviderTimeout<S>
where
    S: Service<RequestPacket, Response = ResponsePacket, Error = TransportError>
        + Sync
        + Send
        + Clone
        + 'static,
    S::Future: Send,
{
    type Response = S::Response;
    type Error = TransportError;
    type Future = ResponseFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match self.service.poll_ready(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(r) => Poll::Ready(r.map_err(Into::into)),
        }
    }

    fn call(&mut self, request: RequestPacket) -> Self::Future {
        let response = self.service.call(request);
        let sleep = tokio::time::sleep(self.timeout);
        ResponseFuture::new(response, sleep)
    }
}

#[pin_project]
#[derive(Debug)]
pub struct ResponseFuture<T> {
    #[pin]
    response: T,
    #[pin]
    sleep: Sleep,
}

impl<T> ResponseFuture<T> {
    pub(crate) fn new(response: T, sleep: Sleep) -> Self {
        ResponseFuture { response, sleep }
    }
}

impl<F, T> Future for ResponseFuture<F>
where
    F: Future<Output = Result<T, TransportError>>,
{
    type Output = Result<T, TransportError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        // First, try polling the future
        match this.response.poll(cx) {
            Poll::Ready(v) => return Poll::Ready(v.map_err(Into::into)),
            Poll::Pending => {}
        }
        // Now check the sleep
        match this.sleep.poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(_) => Poll::Ready(Err(TransportError::local_usage_str(
                "provider request timeout from client side",
            ))),
        }
    }
}
