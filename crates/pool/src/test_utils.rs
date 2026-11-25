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

use std::{
    cell::RefCell,
    fmt,
    sync::{Arc, Once},
};

use parking_lot::Mutex;
use tracing::{
    Event, Metadata, Subscriber,
    field::{Field, Visit},
    span,
    subscriber::Interest,
};

/// Collects the message of every event, at every level, emitted on the thread it is installed
/// on.
#[derive(Clone, Default)]
pub(crate) struct MessageCollector(Arc<Mutex<Vec<String>>>);

thread_local! {
    static INSTALLED: RefCell<Option<MessageCollector>> = const { RefCell::new(None) };
}

/// Removes the thread's collector when dropped.
pub(crate) struct CollectorGuard(());

impl Drop for CollectorGuard {
    fn drop(&mut self) {
        INSTALLED.with(|c| c.borrow_mut().take());
    }
}

impl MessageCollector {
    /// Collects events emitted on this thread until the guard drops.
    ///
    /// A per-test `set_default` subscriber is racy: `tracing` caches per callsite whether any
    /// subscriber is interested, and a parallel test thread that hits a callsite first can cache
    /// "not interested" for it, so this test's collector never sees the event. Instead, one
    /// global [`Router`] is interested in every callsite and forwards events to the collector
    /// installed on the emitting thread.
    pub(crate) fn install(&self) -> CollectorGuard {
        static ROUTER: Once = Once::new();
        ROUTER.call_once(|| {
            tracing::subscriber::set_global_default(Router)
                .expect("no other global subscriber in pool tests");
        });
        INSTALLED.with(|c| *c.borrow_mut() = Some(self.clone()));
        CollectorGuard(())
    }

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

/// Global subscriber that forwards each event to the [`MessageCollector`] installed on the
/// emitting thread, if any.
struct Router;

impl Subscriber for Router {
    fn register_callsite(&self, _metadata: &'static Metadata<'static>) -> Interest {
        // Never cache an answer: whether a collector is installed changes per thread and test.
        Interest::sometimes()
    }

    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        INSTALLED.with(|c| c.borrow().is_some())
    }

    fn new_span(&self, _span: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }

    fn record(&self, _span: &span::Id, _values: &span::Record<'_>) {}

    fn record_follows_from(&self, _span: &span::Id, _follows: &span::Id) {}

    fn event(&self, event: &Event<'_>) {
        INSTALLED.with(|c| {
            if let Some(collector) = c.borrow().as_ref() {
                event.record(&mut collector.clone());
            }
        });
    }

    fn enter(&self, _span: &span::Id) {}

    fn exit(&self, _span: &span::Id) {}
}
