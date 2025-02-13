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

use std::collections::{btree_map, BTreeMap};

use alloy_primitives::{Address, B256, U256};
use anyhow::bail;
use serde::{Deserialize, Serialize};

/// The expected storage values for a user operation that must
/// be checked to determine if this operation is valid.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ExpectedStorage(pub BTreeMap<Address, BTreeMap<B256, B256>>);

impl ExpectedStorage {
    /// Insert a new storage slot value for a given address.
    pub fn insert(&mut self, address: Address, slot: U256, value: U256) {
        self.0
            .entry(address)
            .or_default()
            .insert(B256::from(slot), B256::from(value));
    }

    /// Size of the storage map.
    pub fn num_slots(&self) -> usize {
        self.0.values().map(|slots| slots.len()).sum()
    }
}

/// The expected storage values for a bundle of user operations
#[derive(Clone, Debug, Default)]
pub struct BundleExpectedStorage {
    /// The inner expected storage values for the bundle
    pub inner: ExpectedStorage,
    /// The number of times each storage slot was seen in the bundle.
    counts: BTreeMap<Address, BTreeMap<B256, usize>>,
}

impl BundleExpectedStorage {
    /// Add the expected storage from a UO into this bundle's expected storage.
    pub fn add(&mut self, to_add: &ExpectedStorage) -> anyhow::Result<()> {
        let mut new_inner = self.inner.clone(); // no side effects on failure
        let mut new_counts = self.counts.clone();

        for (&address, other_values_by_slot) in &to_add.0 {
            let values_by_slot = new_inner.0.entry(address).or_default();
            for (&slot, &value) in other_values_by_slot {
                match values_by_slot.entry(slot) {
                    btree_map::Entry::Occupied(mut entry) => {
                        if *entry.get() != value {
                            bail!(
                                "a storage slot was read with a different value from multiple ops. Address: {address:?}, slot: {slot}, first value seen: {value}, second value seen: {}",
                                entry.get(),
                            );
                        }
                        entry.insert(value);
                    }
                    btree_map::Entry::Vacant(entry) => {
                        entry.insert(value);
                    }
                }
                *new_counts
                    .entry(address)
                    .or_default()
                    .entry(slot)
                    .or_default() += 1;
            }
        }

        self.inner = new_inner;
        self.counts = new_counts;

        Ok(())
    }

    /// Remove the expected storage from a UO from this bundle's expected storage.
    pub fn remove(&mut self, to_remove: &ExpectedStorage) {
        for (&address, other_values_by_slot) in &to_remove.0 {
            let values_by_slot = self.inner.0.entry(address).or_default();
            for slot in other_values_by_slot.keys() {
                let count = self
                    .counts
                    .entry(address)
                    .or_default()
                    .entry(*slot)
                    .or_default();
                *count -= 1;
                if *count == 0 {
                    values_by_slot.remove(slot);
                }
            }
            if values_by_slot.is_empty() {
                self.inner.0.remove(&address);
            }
        }
    }
}

use std::fmt::{Display, Formatter};

/// An error that occurs when a user operation violates a spec rule.
#[derive(Debug, thiserror::Error)]
pub enum ViolationError<T> {
    /// A list of known simulation violations
    Violations(Vec<T>),

    /// Other error that occurs during simulation
    Other(#[from] anyhow::Error),
}

impl<T> Clone for ViolationError<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        match self {
            ViolationError::Violations(violations) => {
                ViolationError::Violations(violations.clone())
            }
            ViolationError::Other(error) => {
                ViolationError::Other(anyhow::anyhow!(error.to_string()))
            }
        }
    }
}

impl<T> From<Vec<T>> for ViolationError<T> {
    fn from(violations: Vec<T>) -> Self {
        Self::Violations(violations)
    }
}

impl<T: Display> Display for ViolationError<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ViolationError::Violations(violations) => {
                if violations.len() == 1 {
                    Display::fmt(&violations[0], f)
                } else {
                    f.write_str("multiple violations: ")?;
                    for violation in violations {
                        Display::fmt(violation, f)?;
                        f.write_str("; ")?;
                    }
                    Ok(())
                }
            }
            ViolationError::Other(error) => Display::fmt(error, f),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expected_storage() {
        let address0 = Address::random();
        let address1 = Address::random();

        let mut expected_storage = ExpectedStorage::default();
        expected_storage.insert(address0, U256::from(1), U256::from(2));
        expected_storage.insert(address0, U256::from(2), U256::from(3));
        expected_storage.insert(address1, U256::from(1), U256::from(4));
        assert_eq!(expected_storage.num_slots(), 3);
        assert_eq!(expected_storage.0.len(), 2);
        assert_eq!(expected_storage.0[&address0].len(), 2);
        assert_eq!(*expected_storage.0[&address0][&b256(1)], b256(2));
        assert_eq!(*expected_storage.0[&address0][&b256(2)], b256(3));
        assert_eq!(expected_storage.0[&address1].len(), 1);
        assert_eq!(*expected_storage.0[&address1][&b256(1)], b256(4));
    }

    #[test]
    fn test_bundle_expected_storage() {
        let address0 = Address::random();
        let address1 = Address::random();

        let mut bundle_expected_storage = BundleExpectedStorage::default();

        let mut expected_storage0 = ExpectedStorage::default();
        expected_storage0.insert(address0, U256::from(1), U256::from(2));
        expected_storage0.insert(address0, U256::from(2), U256::from(3));
        expected_storage0.insert(address1, U256::from(1), U256::from(4));

        let mut expected_storage1 = ExpectedStorage::default();
        expected_storage1.insert(address0, U256::from(3), U256::from(5));
        expected_storage1.insert(address0, U256::from(4), U256::from(6));
        expected_storage1.insert(address1, U256::from(2), U256::from(7));

        bundle_expected_storage.add(&expected_storage0).unwrap();
        assert_eq!(bundle_expected_storage.inner.num_slots(), 3);

        bundle_expected_storage.add(&expected_storage1).unwrap();
        assert_eq!(bundle_expected_storage.inner.num_slots(), 6);
    }

    #[test]
    fn test_bundle_expected_storage_conflict() {
        let address0 = Address::random();
        let address1 = Address::random();

        let mut bundle_expected_storage = BundleExpectedStorage::default();

        let mut expected_storage0 = ExpectedStorage::default();
        expected_storage0.insert(address0, U256::from(1), U256::from(2));
        expected_storage0.insert(address0, U256::from(2), U256::from(3));
        expected_storage0.insert(address1, U256::from(1), U256::from(4));

        let mut expected_storage1 = ExpectedStorage::default();
        expected_storage1.insert(address0, U256::from(1), U256::from(5));

        bundle_expected_storage.add(&expected_storage0).unwrap();
        bundle_expected_storage.add(&expected_storage1).unwrap_err();
    }

    #[test]
    fn test_bundle_expected_storage_remove() {
        let address0 = Address::random();
        let address1 = Address::random();

        let mut bundle_expected_storage = BundleExpectedStorage::default();

        let mut expected_storage0 = ExpectedStorage::default();
        expected_storage0.insert(address0, U256::from(1), U256::from(2));
        expected_storage0.insert(address0, U256::from(2), U256::from(3));
        expected_storage0.insert(address1, U256::from(1), U256::from(4));

        bundle_expected_storage.add(&expected_storage0).unwrap();
        bundle_expected_storage.remove(&expected_storage0);
        assert_eq!(bundle_expected_storage.inner.num_slots(), 0);

        bundle_expected_storage.add(&expected_storage0).unwrap(); // add it back twice
        bundle_expected_storage.add(&expected_storage0).unwrap();
        bundle_expected_storage.remove(&expected_storage0);
        assert_eq!(bundle_expected_storage.inner.num_slots(), 3);

        // add a different value
        let mut expected_storage1 = ExpectedStorage::default();
        expected_storage1.insert(address0, U256::from(3), U256::from(2));
        bundle_expected_storage.add(&expected_storage1).unwrap();
        bundle_expected_storage.remove(&expected_storage0);
        assert_eq!(bundle_expected_storage.inner.num_slots(), 1);
    }

    fn b256(value: u64) -> B256 {
        B256::from(U256::from(value))
    }
}
