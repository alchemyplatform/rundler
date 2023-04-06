use std::net::SocketAddr;

use itertools::Itertools;
use metrics_exporter_prometheus::PrometheusBuilder;
use metrics_util::layers::{PrefixLayer, Stack};

pub fn initialize<'a>(
    listen_addr: SocketAddr,
    tags: impl IntoIterator<Item = &'a String>,
) -> anyhow::Result<()> {
    let mut builder = PrometheusBuilder::new().with_http_listener(listen_addr);

    let tags: Vec<(&str, &str)> = tags
        .into_iter()
        .filter_map(|t| t.split('=').collect_tuple())
        .collect();
    for (k, v) in tags {
        builder = builder.add_global_label(k, v);
    }

    let (recorder, exporter) = builder.build()?;
    tokio::spawn(exporter);
    Stack::new(recorder)
        .push(PrefixLayer::new("rundler"))
        .install()?;

    Ok(())
}
