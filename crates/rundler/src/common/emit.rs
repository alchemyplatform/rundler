use std::fmt::Display;

use ethers::types::Address;
use tokio::{
    sync::broadcast::{self, error::RecvError},
    task::JoinHandle,
};
use tracing::{info, warn};

// Events should be in the tens of kilobytes at most (they can contain the
// contents of an op or transaction), so allocating tens of megabytes for the
// channel should be fine.
pub const EVENT_CHANNEL_CAPACITY: usize = 1000;

#[derive(Clone, Debug)]
pub struct WithEntryPoint<T> {
    pub entry_point: Address,
    pub event: T,
}

impl<T> WithEntryPoint<T> {
    pub fn of<U: Into<T>>(value: WithEntryPoint<U>) -> Self {
        Self {
            entry_point: value.entry_point,
            event: value.event.into(),
        }
    }
}

impl<T: Display> Display for WithEntryPoint<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}    Entrypoint: {:?}", self.event, self.entry_point)
    }
}

pub fn receive_events<T>(
    description: &'static str,
    mut rx: broadcast::Receiver<T>,
    handler: impl Fn(T) + Send + 'static,
) -> JoinHandle<()>
where
    T: Clone + Send + 'static,
{
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(event) => handler(event),
                Err(RecvError::Closed) => {
                    info!("Event stream for {description} closed. Logging complete");
                    break;
                }
                Err(RecvError::Lagged(count)) => {
                    warn!("Event stream for {description} lagged. Missed {count} messages.")
                }
            }
        }
    })
}

pub fn receive_and_log_events_with_filter<T>(
    rx: broadcast::Receiver<T>,
    filter: impl (Fn(&T) -> bool) + Send + 'static,
) -> JoinHandle<()>
where
    T: Clone + Display + Send + 'static,
{
    receive_events("logging", rx, move |event| {
        if filter(&event) {
            info!("{}", event);
        }
    })
}
