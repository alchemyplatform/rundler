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

use std::collections::HashMap;

use alloy_primitives::Address;

use crate::bundle_proposer::BundleProposerT;

/// Registry key: (entrypoint address, filter_id)
/// This allows multiple configurations per entrypoint address (virtual entrypoints)
pub(crate) type RegistryKey = (Address, Option<String>);

/// Single registry holding all entrypoint-specific resources, keyed by (address, filter_id)
pub(crate) struct EntrypointRegistry {
    entries: HashMap<RegistryKey, EntrypointEntry>,
}

/// All resources for a single entrypoint configuration
pub(crate) struct EntrypointEntry {
    /// Bundle proposer for this entrypoint
    pub proposer: Box<dyn BundleProposerT>,
}

impl EntrypointEntry {
    /// Create a new entrypoint entry
    pub(crate) fn new(proposer: Box<dyn BundleProposerT>) -> Self {
        Self { proposer }
    }
}

impl EntrypointRegistry {
    /// Create a new empty registry
    pub(crate) fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Insert an entry for an entrypoint configuration
    pub(crate) fn insert(&mut self, key: RegistryKey, entry: EntrypointEntry) {
        self.entries.insert(key, entry);
    }

    /// Get the entry for an entrypoint by (address, filter_id)
    pub(crate) fn get(&self, key: &RegistryKey) -> Option<&EntrypointEntry> {
        self.entries.get(key)
    }
}
