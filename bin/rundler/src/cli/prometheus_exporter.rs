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

use std::{net::SocketAddr, time::Duration};

use itertools::Itertools;
use metrics_exporter_prometheus::PrometheusBuilder;
use metrics_process::Collector;
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

    tokio::spawn(async {
        let collector = Collector::default();
        loop {
            collector.collect();
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });

    Ok(())
}
