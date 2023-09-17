#![warn(missing_docs, unreachable_pub)]
#![deny(unused_must_use, rust_2018_idioms)]
#![doc(test(
    no_crate_inject,
    attr(deny(warnings, rust_2018_idioms), allow(dead_code, unused_variables))
))]
//! Interfaces and utilities for building core Rundler tasks.

pub mod block_watcher;
pub mod grpc;
pub mod server;

mod task;
pub use task::*;
