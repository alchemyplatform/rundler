mod chain;
mod timestamp;
mod validation_results;
mod violations;

use std::collections::{btree_map, BTreeMap};

use anyhow::bail;
pub use chain::*;
use ethers::types::{Address, H256};
use serde::{Deserialize, Serialize};
pub use timestamp::*;
pub use validation_results::*;
pub use violations::*;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ExpectedStorage(BTreeMap<Address, BTreeMap<H256, H256>>);

impl ExpectedStorage {
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
}
