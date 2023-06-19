use std::{cmp, future::Future, time::Duration};

use anyhow::bail;
use rand::Rng;

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

pub async fn connect_with_retries<F, C, FutF>(
    server_name: &str,
    url: &str,
    func: F,
) -> anyhow::Result<C>
where
    F: Fn(String) -> FutF,
    FutF: Future<Output = Result<C, tonic::transport::Error>> + Send + 'static,
{
    for i in 0..10 {
        match func(url.to_owned()).await {
            Ok(client) => return Ok(client),
            Err(e) => tracing::warn!(
                "Failed to connect to {server_name} at {url} {e:?} (attempt {})",
                i
            ),
        }
        let sleep_dur = {
            let mut rng = rand::thread_rng();
            let jitter = rng.gen_range(0..1000);
            let millis = cmp::min(10, 2_u64.pow(i)) * 1000 + jitter;
            Duration::from_millis(millis)
        };
        tokio::time::sleep(sleep_dur).await;
    }
    bail!("Failed to connect to {server_name} at {url} after 10 attempts");
}
