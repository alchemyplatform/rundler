use std::time::{Duration, Instant};

use jsonrpsee::server::logger::Logger;

#[derive(Clone)]
pub struct RpcMetricsLogger;

impl Logger for RpcMetricsLogger {
    type Instant = Instant;

    fn on_connect(
        &self,
        _remote_addr: std::net::SocketAddr,
        _request: &jsonrpsee::server::logger::HttpRequest,
        _t: jsonrpsee::server::logger::TransportProtocol,
    ) {
    }

    fn on_request(
        &self,
        _transport: jsonrpsee::server::logger::TransportProtocol,
    ) -> Self::Instant {
        Instant::now()
    }

    fn on_call(
        &self,
        method_name: &str,
        _params: jsonrpsee::types::Params,
        _kind: jsonrpsee::server::logger::MethodKind,
        _transport: jsonrpsee::server::logger::TransportProtocol,
    ) {
        RpcMetrics::increment_num_requests(method_name.to_string());
        RpcMetrics::increment_open_requests(method_name.to_string());
    }

    fn on_result(
        &self,
        method_name: &str,
        success: bool,
        started_at: Self::Instant,
        _transport: jsonrpsee::server::logger::TransportProtocol,
    ) {
        RpcMetrics::record_request_latency(method_name.to_string(), started_at.elapsed());
        RpcMetrics::decrement_open_requests(method_name.to_string());

        if !success {
            RpcMetrics::increment_rpc_error_count(method_name.to_string());
        }
    }

    fn on_response(
        &self,
        _result: &str,
        _started_at: Self::Instant,
        _transport: jsonrpsee::server::logger::TransportProtocol,
    ) {
    }

    fn on_disconnect(
        &self,
        _remote_addr: std::net::SocketAddr,
        _transport: jsonrpsee::server::logger::TransportProtocol,
    ) {
    }
}

pub struct RpcMetrics {}

impl RpcMetrics {
    fn increment_num_requests(method_name: String) {
        metrics::increment_counter!("rpc_num_requests", "method_name" => method_name)
    }

    fn increment_open_requests(method_name: String) {
        metrics::increment_gauge!("rpc_open_requests", 1_f64, "method_name" => method_name)
    }

    fn decrement_open_requests(method_name: String) {
        metrics::decrement_gauge!("rpc_open_requests", 1_f64, "method_name" => method_name)
    }

    fn increment_rpc_error_count(method_name: String) {
        metrics::increment_counter!("rpc_error_count", "method_name" => method_name)
    }

    fn record_request_latency(method_name: String, latency: Duration) {
        metrics::histogram!("rpc_request_latency", latency, "method_name" => method_name)
    }
}
