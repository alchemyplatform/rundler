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

use anyhow::bail;
use ethers::types::{Address, H256, U256};
use serde::{Deserialize, Serialize};

/// The expected storage values for a user operation that must
/// be checked to determine if this operation is valid.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ExpectedStorage(pub BTreeMap<Address, BTreeMap<H256, H256>>);

impl ExpectedStorage {
    /// Merge this expected storage with another one, accounting for conflicts.
    pub fn merge(&mut self, other: &Self) -> anyhow::Result<()> {
        for (&address, other_values_by_slot) in &other.0 {
            let values_by_slot = self.0.entry(address).or_default();
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
            }
        }
        Ok(())
    }

    /// Insert a new storage slot value for a given address.
    pub fn insert(&mut self, address: Address, slot: U256, value: U256) {
        let buf: [u8; 32] = slot.into();
        let slot = H256::from_slice(&buf);

        let buf: [u8; 32] = value.into();
        let value = H256::from_slice(&buf);

        self.0.entry(address).or_default().insert(slot, value);
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
