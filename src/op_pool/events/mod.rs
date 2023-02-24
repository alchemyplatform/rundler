use ethers::{
    prelude::StreamExt,
    providers::{Provider, Ws},
    types::Address,
};
use std::{sync::Arc, time::Duration};
use tokio::sync::broadcast::Receiver;

use crate::common::contracts::entry_point::EntryPoint;

pub struct EventListener {
    entry_point: EntryPoint<Provider<Ws>>,
}

impl EventListener {
    pub async fn connect(ws_url: String, entry_point: Address) -> anyhow::Result<Self> {
        let provider = Arc::new(
            Provider::<Ws>::connect(ws_url)
                .await?
                .interval(Duration::from_millis(100)),
        );
        let entry_point = EntryPoint::new(entry_point, provider);
        Ok(Self { entry_point })
    }

    pub async fn listen_with_shutdown(&self, mut shutdown_rx: Receiver<()>) -> anyhow::Result<()> {
        let events = self.entry_point.events();
        let mut stream = events.stream().await?;

        loop {
            tokio::select! {
                stream_event = stream.next() => {
                    match stream_event {
                        Some(event) => {
                            // TODO(danc): Handle events
                            tracing::info!("Event: {:?}", event);
                        }
                        None => {
                            // TODO(danc): Handle reconnect retries
                            tracing::info!("Stream ended");
                            break;
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    tracing::info!("Shutting down event listener");
                    break;
                }
            }
        }

        Ok(())
    }
}
