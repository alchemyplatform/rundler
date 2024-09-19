use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
    sync::{Arc, Mutex},
};

use jsonrpsee::server::HttpBody;
use pin_project::pin_project;
use tower::{Layer, Service};
use tonic::codegen::http;

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
    method_metric: Arc<Mutex<MethodMetrics>>,
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
        let mut method_metric = self.service_metrics.get_method_metrics(method_name);

        {
            let mut metric = method_metric.lock().unwarp();
            metric.increment_num_requests();
            metric.increment_open_requests();
        }
        ResponseFuture{
            response_future: self.inner.call(request),
            start_time: Instant::now(),
            method_name: method_name.to_string(),
            service_name: self.service_name.clone(),
            method_metric: method_metric.clone(),
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

        // Get the duration here so it won't count the time of acquiring lock.
        let duration = this.start_time.elapsed();
        let mut metric = self.method_metric.lock().unwrap();
        if res.is_ready() {
            metric.decrement_open_requests();
            metric.record_request_latency(duration);
        }
        if let Poll::Ready(Err(_)) = res {
            metric.increment_error_count();
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

impl<F, Response, Error> Future for ResponseFuture<F>
where
    F: Future<Output = Result<Response, Error>>,
{
    type Output = Result<Response, Error>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.project();
        let res = this.response_future.poll(cx);
        if res.is_ready() {
            MetricsRecorder::decrement_open_requests(this.method_name, this.service_name);
            MetricsRecorder::record_request_latency(
                this.method_name,
                this.service_name,
                this.start_time.elapsed(),
            );
        }

        if let Poll::Ready(Err(_)) = res {
            MetricsRecorder::increment_rpc_error_count(this.method_name, this.service_name);
        }

        res
    }
}


#[derive(Clone)]
// service metrics tracks all method metrics of specific service.
struct ServiceMetrics {
    service_name: &str,
    method_metrics: HashMap<&'static str, Arc<Mutex<MethodMetrics>>>,
}

impl ServiceMetrics {
    fn new(service_name: &str) -> Self {
        Self {
            service_name: service_name,
            method_metrics: HashMap::new(),
        }
    }

    fn get_method_metrics(mut self, method_name: &str) -> Arc<Mutex<MethodMetrics>> {
        self.method_metrics
            .entry(&method_name)
            .or_insert(
                Arc::new(Mutex::new(MethodMetrics::new(self.service_name, method_name))))
    }
}

#[derive(Clone)]
struct MethodMetrics {
    num_requests: Counter,
    open_requests: Gauge,
    error_count: Counter,
    request_latency: Histogram,
}

impl MethodMetrics {
    fn new(service_name: &str, method_name: &str) -> Self {
        Self {
            num_requests: metrics::counter!("num_requests", "method_name" => method_name.to_string(), "service_name" => service_name.to_string()),
            open_requests: metrics::gauge!("open_requests", "method_name" => method_name.to_string(), "service_name" => service_name.to_string()),
            error_count: metrics::counter!("open_requests", "method_name" => method_name.to_string(), "service_name" => service_name.to_string()),
            request_latency: metrics::histogram!("request_latency", "method_name" => method_name.to_string(), "service_name" => service_name.to_string()),
        }
    }
    fn increment_num_requests(&self) {
        self.num_requests.increment(1)
    }

    fn increment_open_requests(&self) {
        self.open_requests.increment(1_f64)
    }

    fn decrement_open_requests(&self) {
        self.open_requests.decrement(1_f64)
    }

    fn increment_error_count(&self) {
        self.error_count.increment(1)
    }

    fn record_request_latency(&self, latency: Duration) {
        self.request_latency.record(latency)
    }
}
