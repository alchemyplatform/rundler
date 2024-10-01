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

use metrics::{counter, gauge, histogram};

use super::status_code::{HttpCode, RpcCode};

/// method logger to log one method invoke session.
pub struct MethodSessionLogger {
    start_time: Instant,
    service_name: String,
    method_name: String,
    protocol: String,
}

impl MethodSessionLogger {
    pub fn new(service_name: String, method_name: String, protocol: String) -> Self {
        Self {
            start_time: Instant::now(),
            method_name: method_name.clone(),
            service_name: service_name.clone(),
            protocol: protocol.clone(),
        }
    }
    /// start the session. time will be initialized.
    pub fn start(&mut self) {
        self.start_time = Instant::now();
        MethodMetrics::increment_num_requests(
            &self.method_name,
            &self.service_name,
            &self.protocol,
        );
        MethodMetrics::increment_open_requests(
            &self.method_name,
            &self.service_name,
            &self.protocol,
        );
    }

    /// record a rpc status code.
    pub fn record_rpc(&self, rpc_code: RpcCode) {
        MethodMetrics::increment_rpc_response_code(&self.method_name, &self.service_name, rpc_code);
    }

    /// record a http status code.
    pub fn record_http(&self, http_code: HttpCode) {
        MethodMetrics::increment_http_response_code(
            &self.method_name,
            &self.service_name,
            http_code,
        );
    }

    /// end of the session. Record the session duration.
    pub fn done(&self) {
        MethodMetrics::record_request_latency(
            &self.method_name,
            &self.service_name,
            &self.protocol,
            self.start_time.elapsed(),
        );
        MethodMetrics::decrement_open_requests(
            &self.method_name,
            &self.service_name,
            &self.protocol,
        );
    }
}

struct MethodMetrics {}

impl MethodMetrics {
    pub(crate) fn increment_num_requests(method_name: &str, service_name: &str, protocol: &str) {
        counter!("num_requests", "method_name" => method_name.to_string(), "service_name" => service_name.to_string(), "protocol" => protocol.to_string()).increment(1)
    }

    pub(crate) fn increment_open_requests(method_name: &str, service_name: &str, protocol: &str) {
        gauge!("open_requests", "method_name" => method_name.to_string(), "service_name" => service_name.to_string(), "protocol" => protocol.to_string()).increment(1_f64)
    }

    pub(crate) fn decrement_open_requests(method_name: &str, service_name: &str, protocol: &str) {
        gauge!("open_requests", "method_name" => method_name.to_string(), "service_name" => service_name.to_string(), "protocol" => protocol.to_string()).decrement(1_f64)
    }

    pub(crate) fn increment_http_response_code(
        method_name: &str,
        service_name: &str,
        http_status_code: HttpCode,
    ) {
        counter!("http_response_status", "method_name" => method_name.to_string(), "service_name" => service_name.to_string(), "protocol" => "http", "response_code" => http_status_code.to_string()).increment(1)
    }

    pub(crate) fn increment_rpc_response_code(
        method_name: &str,
        service_name: &str,
        rpc_status_code: RpcCode,
    ) {
        counter!("rpc_response_status", "method_name" => method_name.to_string(), "service_name" => service_name.to_string(), "protocol" => "rpc", "response_code" => rpc_status_code.to_string()).increment(1)
    }

    pub(crate) fn record_request_latency(
        method_name: &str,
        service_name: &str,
        protocol: &str,
        latency: Duration,
    ) {
        histogram!("request_latency", "method_name" => method_name.to_string(), "service_name" => service_name.to_string(), "protocol" => protocol.to_string()).record(latency)
    }
}
