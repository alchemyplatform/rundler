use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use jsonrpsee::server::HttpBody;
use pin_project::pin_project;
use tower::{Layer, Service};
use tonic::codegen::http;

#![allow(dead_code)]

pub fn get_method_name(request : http::Request<Body>) -> String {
    let uri = request.uri();
    let method_name = uri.path().split('/').last().unwrap_or("unknown");
    method_name.to_string()
}

pub fn get_method_name<'a>(request : jsonrpsee::types::Request<'a>) -> String {
    request.method_name().to_string()
}
#[derive(Debug, Clone)]
pub struct MetricsLayer {
    service_name: String,
}

impl MetricsLayer {
    pub fn new(service_name: String, protocal: String) -> Self {
        MetricsLayer {
            service_name,
        }
    }
}

impl<S> Layer<S> for MetricsLayer {
    type Service = MetricsMiddleware<S>;
    fn layer(&self, service: S) -> Self::Service {
        MetricsMiddleware::new(service, self.service_name.clone())
    }
}


#[derive(Clone, Debug)]
pub struct MetricsMiddleware<S> {
    inner: S,
    service_name: String,
    service_metrics: ServiceMetrics,
}

impl<S> MetricsMiddleware<S> {
    pub fn new(inner: S, service_name: String) -> Self {
        Self {
            inner: inner,
            service_name: service_name,
            service_metrics: ServiceMetrics::new(service_name.as_str()),
        }
    }
}

#[pin_project]
pub struct ResponseFuture<F> {
    #[pin]
    response_future: F,
    start_time: Instant,
    method_name: String,
    service_name: String,
}

impl<S> Service<RequestInfo> for MetricsMiddleware<S>
where
    S: Service<RequestInfo>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = ResponseFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        let uri = request.uri().clone();
        let method_name = uri.path().split('/').last().unwrap_or("unknown");
        {
            let mut metric = method_metric.lock().unwarp();
            MethodMetrics::increment_num_requests(self.service_name.as_str(), method_name);
            MethodMetrics::increment_open_requests(self.service_name.as_str(), method_name);
        }
        ResponseFuture{
            response_future: self.inner.call(request),
            start_time: Instant::now(),
            method_name: method_name.to_string(),
            service_name: self.service_name.clone(),
        }
    }
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
            MethodMetrics::decrement_open_requests(self.service_name.as_str(), method_name);
            MethodMetrics::record_request_latency(self.service_name.as_str(), method_name, this.start_time.elapsed());
        }
        if let Poll::Ready(Err(_)) = res {
            MethodMetrics::increment_error_count(self.service_name.as_str(), method_name);
        }
        res
    }
}

#[pin_project]
pub struct ResponseFuture<F> {
    #[pin]
    response_future: F,
    start_time: Instant,
    method_name: String,
}


#[derive(Clone)]
// service metrics tracks all method metrics of specific service.
struct ServiceMetrics {
    service_name: &str,
}

impl ServiceMetrics {
    fn new(service_name: &str) -> Self {
        Self {
            service_name: service_name
        }
    }
}

#[derive(Clone)]
struct MethodMetrics {}

impl MethodMetrics {
    fn increment_num_requests(&self, method_name: String, service_name: String) {
        metrics::counter!("num_requests", "method_name" => method_name.to_string(), "service_name" => service_name.to_string()).increment(1)
    }

    fn increment_open_requests(&self, method_name: String, service_name: String) {
        metrics::gauge!("open_requests", "method_name" => method_name.to_string(), "service_name" => service_name.to_string()).increment(1_f64)
    }

    fn decrement_open_requests(&self, method_name: String, service_name: String) {
        metrics::gauge!("open_requests", "method_name" => method_name.to_string(), "service_name" => service_name.to_string()).decrement(1_f64)
    }

    fn increment_error_count(&self, method_name: String, service_name: String) {
        metrics::counter!("open_requests", "method_name" => method_name.to_string(), "service_name" => service_name.to_string()).increment(1)
    }

    fn record_request_latency(&self, , method_name: String, service_name: String, latency: Duration) {
        metrics::histogram!("request_latency", "method_name" => method_name.to_string(), "service_name" => service_name.to_string()).record(latency)
    }
}
