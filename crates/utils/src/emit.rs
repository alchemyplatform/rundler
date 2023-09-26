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

//! Utilities for emitting/collecting events from runtime components

use std::fmt::Display;

use ethers::types::Address;
use tokio::{
    sync::broadcast::{self, error::RecvError},
    task::JoinHandle,
};
use tracing::{info, warn};

/// Capacity of the event channels.
/// Events should be in the tens of kilobytes at most (they can contain the
/// contents of an op or transaction), so allocating tens of megabytes for the
/// channel should be fine.
pub const EVENT_CHANNEL_CAPACITY: usize = 1000;

/// A wrapper for an event that also contains the entry point that it
/// is associated with.
#[derive(Clone, Debug)]
pub struct WithEntryPoint<T> {
    /// Entry point address associated with the event
    pub entry_point: Address,
    /// The event itself
    pub event: T,
}

impl<T> WithEntryPoint<T> {
    /// Convert one `WithEntryPoint` type event to another
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

/// Receive events from a event broadcast channel and call
/// the given handler function for each event.
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

/// An event handler that simply logs the event at an INFO level.
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
