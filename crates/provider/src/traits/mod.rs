//! Traits for the provider module.

mod entry_point;
#[cfg(feature = "test-utils")]
pub use entry_point::MockEntryPoint;
pub use entry_point::{EntryPoint, HandleOpsOut};

mod provider;
#[cfg(feature = "test-utils")]
pub use provider::MockProvider;
pub use provider::{AggregatorOut, AggregatorSimOut, Provider};
