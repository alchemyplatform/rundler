use std::net::SocketAddr;

use metrics_exporter_prometheus::PrometheusBuilder;
use metrics_util::layers::{PrefixLayer, Stack};

pub fn initialize(listen_addr: SocketAddr) -> anyhow::Result<()> {
    let (recorder, exporter) = PrometheusBuilder::new()
        .with_http_listener(listen_addr)
        .build()?;
    tokio::spawn(exporter);
    Stack::new(recorder)
        .push(PrefixLayer::new("alchemy-bundler"))
        .install()?;

    Ok(())
}
