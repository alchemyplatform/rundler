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

//! Traits and utilities for interacting with Rundler server implementations

use std::{future::Future, time::Duration};

use anyhow::{bail, Context};
use async_trait::async_trait;
use rundler_utils::retry::{self, RetryOpts};

/// Format a server address from a host, port, and secure flag.
pub fn format_server_addr(host: &String, port: u16, secure: bool) -> String {
    if secure {
        format!("https://{}:{}", host, port)
    } else {
        format!("http://{}:{}", host, port)
    }
}

/// Format a socket address from a host and port.
pub fn format_socket_addr(host: &String, port: u16) -> String {
    format!("{}:{}", host, port)
}

/// Connect to a server with retries until it is available, or the shutdown signal is received.
pub async fn connect_with_retries_shutdown<F, C, FutF, S, R, E>(
    server_name: &str,
    url: &str,
    func: F,
    shutdown_signal: S,
) -> anyhow::Result<C>
where
    F: Fn(String) -> FutF,
    FutF: Future<Output = anyhow::Result<C>> + Send + 'static,
    S: Future<Output = Result<R, E>> + Send + 'static,
{
    tokio::select! {
        _ = shutdown_signal => {
            bail!("shutdown signal received")
        }
        res = connect_with_retries(server_name, url, func) => {
            res
        }
    }
}

/// Connect to a server with retries until it is available.
pub async fn connect_with_retries<F, C, FutF>(
    server_name: &str,
    url: &str,
    func: F,
) -> anyhow::Result<C>
where
    F: Fn(String) -> FutF,
    FutF: Future<Output = anyhow::Result<C>> + Send + 'static,
{
    let description = format!("connect to {server_name} at {url}");
    retry::with_retries(
        &description,
        || func(url.to_owned()),
        RetryOpts {
            max_attempts: 10,
            min_nonzero_wait: Duration::from_secs(1),
            max_wait: Duration::from_secs(10),
            max_jitter: Duration::from_secs(1),
        },
    )
    .await
    .context("should connect to server when retrying")
}

/// Status of a server.
#[derive(Debug)]
pub enum ServerStatus {
    /// Server is serving requests.
    Serving,
    /// Server is not serving requests.
    NotServing,
}

/// A health check for a server.
#[async_trait]
pub trait HealthCheck: Send + Sync + 'static {
    /// Name of the server
    fn name(&self) -> &'static str;

    /// Check the status of the server.
    async fn status(&self) -> ServerStatus;
}
