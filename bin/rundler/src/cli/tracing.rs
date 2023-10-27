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

use std::io;

pub use tracing::*;
use tracing::{subscriber, subscriber::Interest, Metadata, Subscriber};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_log::LogTracer;
use tracing_subscriber::{layer::SubscriberExt, EnvFilter, FmtSubscriber, Layer};

use super::LogsArgs;

pub fn configure_logging(config: &LogsArgs) -> anyhow::Result<WorkerGuard> {
    let (appender, guard) = if let Some(log_file) = &config.file {
        tracing_appender::non_blocking(tracing_appender::rolling::never(".", log_file))
    } else {
        tracing_appender::non_blocking(io::stdout())
    };

    let subscriber_builder = FmtSubscriber::builder()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(appender);
    if config.json {
        subscriber::set_global_default(
            subscriber_builder
                .json()
                .finish()
                .with(TargetBlacklistLayer),
        )?;
    } else {
        subscriber::set_global_default(
            subscriber_builder
                .pretty()
                .finish()
                .with(TargetBlacklistLayer),
        )?;
    }

    // Redirect logs from external crates using `log` to the tracing subscriber
    LogTracer::init()?;

    Ok(guard)
}

const BLACKLISTED_TARGETS: &[&str] = &["h2", "hyper", "tower::buffer"];

struct TargetBlacklistLayer;

impl<S: Subscriber> Layer<S> for TargetBlacklistLayer {
    fn register_callsite(&self, metadata: &'static Metadata<'static>) -> Interest {
        let matches_blacklist = BLACKLISTED_TARGETS
            .iter()
            .any(|target| metadata.target().starts_with(target));
        if matches_blacklist {
            Interest::never()
        } else {
            Interest::always()
        }
    }
}
