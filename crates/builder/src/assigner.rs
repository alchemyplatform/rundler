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
    collections::{hash_map::Entry, HashMap, HashSet},
    sync::{Arc, Mutex},
};

use alloy_primitives::{Address, B256};
use rundler_types::{
    pool::{Pool, PoolOperation},
    UserOperation,
};

#[derive(Clone)]
pub(crate) struct Assigner {
    pool: Arc<dyn Pool>,
    uo_sender_assignments: Arc<Mutex<HashMap<Address, (Address, u64)>>>,
    max_pool_ops_per_request: u64,
    max_bundle_size: u64,
}

impl Assigner {
    pub(crate) fn new(
        pool: Arc<dyn Pool>,
        max_pool_ops_per_request: u64,
        max_bundle_size: u64,
    ) -> Self {
        Self {
            pool,
            uo_sender_assignments: Arc::new(Mutex::new(HashMap::new())),
            max_pool_ops_per_request,
            max_bundle_size,
        }
    }

    pub(crate) async fn get_operations(
        &self,
        builder_address: Address,
        entry_point: Address,
        filter_id: Option<String>,
    ) -> anyhow::Result<Vec<PoolOperation>> {
        let ops = self
            .pool
            .get_ops_summaries(entry_point, self.max_pool_ops_per_request, filter_id)
            .await?;
        let mut return_ops_summaries = Vec::new();

        {
            let mut assignments = self.uo_sender_assignments.lock().unwrap();
            for op in ops {
                let entry = assignments.entry(op.sender).or_insert((builder_address, 0));

                if entry.0 != builder_address {
                    tracing::debug!(
                        "op {:?} sender {:?} already assigned to another builder, skipping",
                        op.hash,
                        op.sender
                    );
                    continue;
                }

                entry.1 += 1;
                return_ops_summaries.push(op);
                if return_ops_summaries.len() >= self.max_bundle_size as usize {
                    break;
                }
            }
        }

        if return_ops_summaries.is_empty() {
            return Ok(vec![]);
        }

        let return_ops = self
            .pool
            .get_ops_by_hashes(
                entry_point,
                return_ops_summaries.iter().map(|op| op.hash).collect(),
            )
            .await?;

        // Pool may have removed ops in the meantime, so we need to check if the returned ops are
        // the same as the ones we requested. If not, we decrement the assignments for the sender.
        if return_ops.len() != return_ops_summaries.len() {
            tracing::debug!("some operations were not returned from the pool, skipping them");
            let mut assignments = self.uo_sender_assignments.lock().unwrap();
            let returned_hashes: HashSet<B256> = return_ops.iter().map(|op| op.uo.hash()).collect();
            for op in return_ops_summaries {
                if !returned_hashes.contains(&op.hash) {
                    Self::decrement_assignments(&mut assignments, op.sender);
                }
            }
        }

        Ok(return_ops)
    }

    pub(crate) fn return_operations(&self, _builder_address: Address, ops: Vec<PoolOperation>) {
        let mut assignments = self.uo_sender_assignments.lock().unwrap();
        for op in ops {
            Self::decrement_assignments(&mut assignments, op.uo.sender());
        }
    }

    pub(crate) fn release_all_operations(&self, builder_address: Address) {
        self.uo_sender_assignments
            .lock()
            .unwrap()
            .remove(&builder_address);
    }

    fn decrement_assignments(assignments: &mut HashMap<Address, (Address, u64)>, sender: Address) {
        match assignments.entry(sender) {
            Entry::Occupied(mut entry) => {
                let count = &mut entry.get_mut().1;
                *count -= 1;
                if *count == 0 {
                    entry.remove();
                }
            }
            Entry::Vacant(_) => {}
        }
    }
}
