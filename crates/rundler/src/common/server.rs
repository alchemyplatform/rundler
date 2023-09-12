use std::{future::Future, time::Duration};

use anyhow::{bail, Context};
use tonic::async_trait;

use crate::common::{retry, retry::RetryOpts};

pub fn format_server_addr(host: &String, port: u16, secure: bool) -> String {
    if secure {
        format!("https://{}:{}", host, port)
    } else {
        format!("http://{}:{}", host, port)
    }
}

pub fn format_socket_addr(host: &String, port: u16) -> String {
    format!("{}:{}", host, port)
}

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

#[derive(Debug)]
pub enum ServerStatus {
    Serving,
    NotServing,
}

#[async_trait]
pub trait HealthCheck: Send + Sync + 'static {
    fn name(&self) -> &'static str;

    async fn status(&self) -> ServerStatus;
}
