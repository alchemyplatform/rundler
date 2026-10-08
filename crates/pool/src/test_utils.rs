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

use std::{fmt, sync::Arc};

use parking_lot::Mutex;
use tracing::{
    Event, Metadata, Subscriber,
    field::{Field, Visit},
    span,
};

/// A tracing subscriber that collects the message of every event, at every level.
#[derive(Clone, Default)]
pub(crate) struct MessageCollector(Arc<Mutex<Vec<String>>>);

impl MessageCollector {
    /// The messages collected so far.
    pub(crate) fn messages(&self) -> Vec<String> {
        self.0.lock().clone()
    }
}

impl Visit for MessageCollector {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            self.0.lock().push(format!("{value:?}"));
        }
    }
}

impl Subscriber for MessageCollector {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _span: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }

    fn record(&self, _span: &span::Id, _values: &span::Record<'_>) {}

    fn record_follows_from(&self, _span: &span::Id, _follows: &span::Id) {}

    fn event(&self, event: &Event<'_>) {
        event.record(&mut self.clone());
    }

    fn enter(&self, _span: &span::Id) {}

    fn exit(&self, _span: &span::Id) {}
}
