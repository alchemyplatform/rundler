#![warn(missing_docs, unreachable_pub)]
#![deny(unused_must_use, rust_2018_idioms)]
#![doc(test(
    no_crate_inject,
    attr(deny(warnings, rust_2018_idioms), allow(dead_code, unused_variables))
))]

//! Rundler common types

mod user_operation;
pub use user_operation::UserOperationId;

/// Generated contracts module
#[allow(non_snake_case)]
#[rustfmt::skip]
#[allow(clippy::all)]
#[allow(missing_docs)]
pub mod contracts;
pub use contracts::shared_types::{UserOperation, UserOpsPerAggregator};

mod entity;
pub use entity::{Entity, EntityType};

mod gas;
pub use gas::GasFees;
