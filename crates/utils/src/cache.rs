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

//! Caching utilities

use core::hash::BuildHasher;
use std::{
    fmt::{self, Debug, Display, Formatter},
    hash::Hash,
};

use derive_more::{Deref, DerefMut};
use itertools::Itertools;
use schnellru::{ByLength, Limiter, RandomState};

/// Wrapper of [`schnellru::LruMap`] that implements [`fmt::Debug`].
/// Adapted from [Reth](https://github.com/paradigmxyz/reth/blob/main/crates/net/network/src/cache.rs)
#[derive(Deref, DerefMut, Default)]
pub struct LruMap<K, V, L = ByLength, S = RandomState>(schnellru::LruMap<K, V, L, S>)
where
    K: Hash + PartialEq,
    L: Limiter<K, V>,
    S: BuildHasher;

impl<K, V, L, S> Debug for LruMap<K, V, L, S>
where
    K: Hash + PartialEq + Display,
    V: Debug,
    L: Limiter<K, V> + Debug,
    S: BuildHasher,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut debug_struct = f.debug_struct("LruMap");

        debug_struct.field("limiter", self.limiter());

        debug_struct.field(
            "res_fn_iter",
            &format_args!(
                "Iter: {{{} }}",
                self.iter().map(|(k, v)| format!(" {k}: {v:?}")).format(",")
            ),
        );

        debug_struct.finish()
    }
}

impl<K, V> LruMap<K, V>
where
    K: Hash + PartialEq,
{
    /// Returns a new cache with default limiter and hash builder.
    pub fn new(max_length: u32) -> Self {
        LruMap(schnellru::LruMap::new(ByLength::new(max_length)))
    }
}
