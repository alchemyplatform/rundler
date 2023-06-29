use std::fmt::Display;

use ethers::types::Address;

use crate::{builder::emit::BuilderEvent, op_pool::emit::OpPoolEvent};

#[derive(Clone, Debug)]
pub enum Event {
    OpPoolEvent(OpPoolEvent),
    BuilderEvent(BuilderEvent),
}

#[derive(Clone, Debug)]
pub struct WithEntryPoint<T> {
    pub entry_point: Address,
    pub event: T,
}

impl From<OpPoolEvent> for Event {
    fn from(event: OpPoolEvent) -> Self {
        Self::OpPoolEvent(event)
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
            Event::OpPoolEvent(event) => event.fmt(f),
            Event::BuilderEvent(event) => event.fmt(f),
        }
    }
}
