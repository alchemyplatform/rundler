use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use futures::{future::BoxFuture, FutureExt};
use jsonrpsee::server::HttpBody;
use pin_project::pin_project;
use tower::{Layer, Service};
use tonic::codegen::http;

#![allow(dead_code)]

pub trait RequestInfo {
    pub fn get_method_name(&self) -> String;
}

pub struct MethodExtractor<Request> 
{}

impl<Request> MethodExtractor<Request> where Request: RequestInfo
{
    pub fn new () -> Self {
        Self { }
    }
    pub fn extract_method_name(&self, request: Request) -> String{
        request.get_method_name()
    }
}

impl<Body> RequestInfo for http::Request<Body>{
    fn get_method_name(&self) -> String {
        let method_name = self.uri().path().split('/').last().unwrap_or("unknown");
        method_name.to_string()
    }
}

impl<'a> RequestInfo for jsonrpsee::types::Request<'a>{
    fn get_method_name<'a>(&self) -> String {
        self.
        request.method_name().to_string()
    }
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
pub struct MetricsMiddleware<S, Request> {
    inner: S,
    service_name: String,
    service_metrics: ServiceMetrics,
    method_extractor: MethodExtractor<Request>
}

impl<S, Request> MetricsMiddleware<S, Request> 
where Request: RequestInfo
{
    pub fn new(inner: S, service_name: String) -> Self {
        Self {
            inner: inner,
            service_name: service_name,
            service_metrics: ServiceMetrics::new(service_name.as_str()),
            method_extractor: MethodExtractor<Request>::new(),
        }
    }
}

impl<S, Request> Service<Request> for MetricsMiddleware<S>
where
    S: Service<Request>,
    Request: RequestInfo,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<Response>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let method_name = self.method_extractor.extract_method_name(request);
        MethodMetrics::increment_num_requests(self.service_name.clone(), method_name.to_string());
        MethodMetrics::increment_open_requests(self.service_name.clone(), method_name);

        let start = Instant::now();
        let svc = self.inner.clone();
        let service_name = self.service_name.clone();
        async move{ 
            let rsp: Result<Response, Error> = svc.call(request).await;
            MethodMetrics::record_request_latency(method_name, service_name, start.elapsed());
            MethodMetrics::decrement_open_requests(method_name, service_name);
            if rsp.is_err(){
                MethodMetrics::increment_error_count(method_name, service_name);
            }
            rsp
        }
        .boxed()
    }
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
    fn increment_num_requests(method_name: String, service_name: String) {
        metrics::counter!("num_requests", "method_name" => method_name.to_string(), "service_name" => service_name.to_string()).increment(1)
    }

    fn increment_open_requests(method_name: String, service_name: String) {
        metrics::gauge!("open_requests", "method_name" => method_name.to_string(), "service_name" => service_name.to_string()).increment(1_f64)
    }

    fn decrement_open_requests( method_name: String, service_name: String) {
        metrics::gauge!("open_requests", "method_name" => method_name.to_string(), "service_name" => service_name.to_string()).decrement(1_f64)
    }

    fn increment_error_count( method_name: String, service_name: String) {
        metrics::counter!("open_requests", "method_name" => method_name.to_string(), "service_name" => service_name.to_string()).increment(1)
    }

    fn record_request_latency( method_name: String, service_name: String, latency: Duration) {
        metrics::histogram!("request_latency", "method_name" => method_name.to_string(), "service_name" => service_name.to_string()).record(latency)
    }
}
