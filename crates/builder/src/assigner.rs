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
    collections::{hash_map::Entry, HashMap},
    sync::{Arc, RwLock},
};

use alloy_primitives::Address;
use rundler_types::{
    pool::{Pool, PoolOperation},
    UserOperation,
};

#[derive(Clone)]
pub(crate) struct Assigner {
    pool: Arc<dyn Pool>,
    uo_sender_assignments: Arc<RwLock<HashMap<Address, (Address, u64)>>>,
}

impl Assigner {
    pub(crate) fn new(pool: Arc<dyn Pool>) -> Self {
        Self {
            pool,
            uo_sender_assignments: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub(crate) async fn get_operations(
        &self,
        builder_address: Address,
        entry_point: Address,
        filter_id: Option<String>,
    ) -> anyhow::Result<Vec<PoolOperation>> {
        let ops = self.pool.get_ops(entry_point, 1024, 0, filter_id).await?;
        let mut return_ops = Vec::new();

        // filter out ops that are already assigned to another builder
        // and assign the rest to the current builder
        for op in ops {
            if let Some((sender, _)) = self
                .uo_sender_assignments
                .read()
                .unwrap()
                .get(&op.uo.sender())
            {
                if *sender != builder_address {
                    tracing::info!(
                        "op {:?} sender {:?} already assigned to another builder, skipping",
                        op.uo.hash(),
                        op.uo.sender()
                    );
                    continue;
                }
            }
            return_ops.push(op);
        }

        {
            let mut write = self.uo_sender_assignments.write().unwrap();
            for op in &return_ops {
                let entry = write.entry(op.uo.sender()).or_insert((builder_address, 0));
                entry.1 += 1;
            }
        }

        Ok(return_ops)
    }

    pub(crate) fn return_operations(&self, _builder_address: Address, ops: Vec<PoolOperation>) {
        let mut write = self.uo_sender_assignments.write().unwrap();
        for op in ops {
            match write.entry(op.uo.sender()) {
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

    pub(crate) fn release_all_operations(&self, builder_address: Address) {
        self.uo_sender_assignments
            .write()
            .unwrap()
            .remove(&builder_address);
    }
}
