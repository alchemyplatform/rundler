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

#![warn(missing_docs, unreachable_pub, unused_crate_dependencies)]
#![deny(unused_must_use, rust_2018_idioms)]
#![doc(test(
    no_crate_inject,
    attr(deny(warnings, rust_2018_idioms), allow(dead_code, unused_variables))
))]
//! Interfaces and utilities for building core Rundler tasks.

pub mod block_watcher;
pub mod grpc;
pub mod server;

pub use reth_tasks::{
    shutdown::GracefulShutdown, TaskSpawner, TaskSpawnerExt as RethTaskSpawnerExt,
    TokioTaskExecutor,
};

/// A trait that extends Reth's `TaskSpawner` with additional methods.
pub trait TaskSpawnerExt: TaskSpawner + RethTaskSpawnerExt + Clone + 'static {}

impl<T: TaskSpawner + RethTaskSpawnerExt + Clone + 'static> TaskSpawnerExt for T {}
