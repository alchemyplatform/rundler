// This file is part of Rundler.
//
// Rundler is free software: you can redistribute it and/or modify it under the
// terms of the GNU Lesser General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later version.
//
// Rundler is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with Rundler.
// If not, see https://www.gnu.org/licenses/.

use std::time::{Duration, Instant};

use jsonrpsee::{helpers::MethodResponseResult, server::logger::Logger};

#[derive(Clone)]
pub(crate) struct RpcMetricsLogger;

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
        _params: jsonrpsee::types::Params<'_>,
        _kind: jsonrpsee::server::logger::MethodKind,
        _transport: jsonrpsee::server::logger::TransportProtocol,
    ) {
        RpcMetrics::increment_num_requests(method_name.to_string());
        RpcMetrics::increment_open_requests(method_name.to_string());
    }

    fn on_result(
        &self,
        method_name: &str,
        result: MethodResponseResult,
        started_at: Self::Instant,
        _transport: jsonrpsee::server::logger::TransportProtocol,
    ) {
        RpcMetrics::record_request_latency(method_name.to_string(), started_at.elapsed());
        RpcMetrics::decrement_open_requests(method_name.to_string());

        if let MethodResponseResult::Failed(_) = result {
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

pub(crate) struct RpcMetrics {}

impl RpcMetrics {
    fn increment_num_requests(method_name: String) {
        metrics::counter!("rpc_num_requests", "method_name" => method_name).increment(1);
    }

    fn increment_open_requests(method_name: String) {
        metrics::gauge!("rpc_open_requests", "method_name" => method_name).increment(1_f64);
    }

    fn decrement_open_requests(method_name: String) {
        metrics::gauge!("rpc_open_requests", "method_name" => method_name).decrement(1_f64);
    }

    fn increment_rpc_error_count(method_name: String) {
        metrics::counter!("rpc_error_count", "method_name" => method_name).increment(1);
    }

    fn record_request_latency(method_name: String, latency: Duration) {
        metrics::histogram!("rpc_request_latency", "method_name" => method_name).record(latency);
    }
}
