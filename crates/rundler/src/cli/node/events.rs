use std::fmt::Display;

use ethers::types::Address;
use rundler_builder::BuilderEvent;
use rundler_pool::PoolEvent;

#[derive(Clone, Debug)]
pub enum Event {
    PoolEvent(PoolEvent),
    BuilderEvent(BuilderEvent),
}

#[derive(Clone, Debug)]
pub struct WithEntryPoint<T> {
    pub entry_point: Address,
    pub event: T,
}

impl From<PoolEvent> for Event {
    fn from(event: PoolEvent) -> Self {
        Self::PoolEvent(event)
    }
}

impl From<BuilderEvent> for Event {
    fn from(event: BuilderEvent) -> Self {
        Self::BuilderEvent(event)
    }
}

impl Display for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Event::PoolEvent(event) => event.fmt(f),
            Event::BuilderEvent(event) => event.fmt(f),
        }
    }
}
