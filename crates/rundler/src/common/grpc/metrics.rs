use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use pin_project::pin_project;
use tonic::codegen::http;
use tower::{Layer, Service};

#[derive(Debug, Clone)]
pub struct GrpcMetricsLayer {
    scope: String,
}

impl GrpcMetricsLayer {
    pub fn new(scope: String) -> Self {
        GrpcMetricsLayer { scope }
    }
}

impl<S> Layer<S> for GrpcMetricsLayer {
    type Service = GrpcMetrics<S>;

    fn layer(&self, service: S) -> Self::Service {
        GrpcMetrics::new(service, self.scope.clone())
    }
}

#[derive(Clone, Debug)]
pub struct GrpcMetrics<S> {
    inner: S,
    scope: String,
}

impl<S> GrpcMetrics<S> {
    pub fn new(inner: S, scope: String) -> Self {
        Self { inner, scope }
    }
}

impl<S, Body> Service<http::Request<Body>> for GrpcMetrics<S>
where
    S: Service<http::Request<Body>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = ResponseFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Our middleware doesn't care about backpressure so its ready as long
        // as the inner service is ready.
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        let uri = request.uri().clone();
        let method_name = uri.path().split('/').last().unwrap_or("unknown");
        GrpcMetricsRecorder::increment_num_requests(method_name, &self.scope);
        GrpcMetricsRecorder::increment_open_requests(method_name, &self.scope);

        ResponseFuture {
            response_future: self.inner.call(request),
            start_time: Instant::now(),
            scope: self.scope.clone(),
            method_name: method_name.to_string(),
        }
    }
}

// checkout: https://github.com/tower-rs/tower/blob/master/guides/building-a-middleware-from-scratch.md
// for details on the use of Pin here
#[pin_project]
pub struct ResponseFuture<F> {
    #[pin]
    response_future: F,

    start_time: Instant,
    method_name: String,
    scope: String,
}

impl<F, Response, Error> Future for ResponseFuture<F>
where
    F: Future<Output = Result<Response, Error>>,
{
    type Output = Result<Response, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let res = this.response_future.poll(cx);
        if res.is_ready() {
            GrpcMetricsRecorder::decrement_open_requests(this.method_name, this.scope);
            GrpcMetricsRecorder::record_request_latency(
                this.method_name,
                this.scope,
                this.start_time.elapsed(),
            );
        }

        if let Poll::Ready(Err(_)) = res {
            GrpcMetricsRecorder::increment_rpc_error_count(this.method_name, this.scope);
        }

        res
    }
}

struct GrpcMetricsRecorder;

impl GrpcMetricsRecorder {
    pub fn increment_num_requests(method_name: &str, scope: &str) {
        metrics::increment_counter!("grpc_num_requests", "method_name" => method_name.to_string(), "service" => scope.to_string())
    }

    pub fn increment_open_requests(method_name: &str, scope: &str) {
        metrics::increment_gauge!("grpc_open_requests", 1_f64, "method_name" => method_name.to_string(), "service" => scope.to_string())
    }

    pub fn decrement_open_requests(method_name: &str, scope: &str) {
        metrics::decrement_gauge!("grpc_open_requests", 1_f64, "method_name" => method_name.to_string(), "service" => scope.to_string())
    }

    pub fn increment_rpc_error_count(method_name: &str, scope: &str) {
        metrics::increment_counter!("grpc_error_count", "method_name" => method_name.to_string(), "service" => scope.to_string())
    }

    pub fn record_request_latency(method_name: &str, scope: &str, latency: Duration) {
        metrics::histogram!("grpc_request_latency", latency, "method_name" => method_name.to_string(), "service" => scope.to_string())
    }
}
