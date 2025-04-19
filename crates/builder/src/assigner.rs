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
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

use alloy_primitives::Address;
use metrics::Gauge;
use metrics_derive::Metrics;
use rundler_types::pool::{Pool, PoolOperation};

// The Assigner is responsible for assigning operations to builder addresses.
//
// It is used to ensure that no two builders attempt to include operations from the same sender in bundles simultaneously.
#[derive(Clone)]
pub(crate) struct Assigner {
    pool: Arc<dyn Pool>,
    state: Arc<Mutex<State>>,
    max_pool_ops_per_request: u64,
    max_bundle_size: u64,
    metrics: GlobalMetrics,
}

#[derive(Default)]
struct State {
    uo_sender_to_builder_state: HashMap<Address, (Address, LockState)>,
    builder_to_uo_senders: HashMap<Address, HashSet<Address>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockState {
    // The sender is assigned to the builder, but has not yet been confirmed.
    // The builder has yet to include the sender in a bundle.
    Assigned,
    // The sender is confirmed to the builder. The builder has included the sender in a bundle.
    Confirmed,
}

impl Assigner {
    pub(crate) fn new(
        pool: Arc<dyn Pool>,
        max_pool_ops_per_request: u64,
        max_bundle_size: u64,
    ) -> Self {
        Self {
            pool,
            state: Arc::new(Mutex::new(State::default())),
            max_pool_ops_per_request,
            max_bundle_size,
            metrics: GlobalMetrics::default(),
        }
    }

    // This method retrieves operations from the pool for the given entry point and filter id.
    //
    // From here, any senders that are not already assigned to another builder are assigned to the current builder.
    // These senders enter the "assigned" state and cannot be assigned to another builder until the current builder drops or confirms them.
    //
    // This method is called to receive operations from the pool for a builder prior to forming a bundle.
    pub(crate) async fn assign_operations(
        &self,
        builder_address: Address,
        entry_point: Address,
        filter_id: Option<String>,
    ) -> anyhow::Result<Vec<PoolOperation>> {
        let per_builder_metrics =
            PerBuilderMetrics::new_with_labels(&[("builder_address", builder_address.to_string())]);
        let ops = self
            .pool
            .get_ops_summaries(entry_point, self.max_pool_ops_per_request, filter_id)
            .await?;
        let mut return_ops_summaries = Vec::new();

        {
            let mut state = self.state.lock().unwrap();
            for op in ops {
                let entry = state
                    .uo_sender_to_builder_state
                    .entry(op.sender)
                    .or_insert_with(|| {
                        tracing::debug!(
                            "op {:?} sender {:?} assigned to builder {:?}",
                            op.hash,
                            op.sender,
                            builder_address
                        );
                        per_builder_metrics.senders_assigned.increment(1);
                        (builder_address, LockState::Assigned)
                    });

                if entry.0 != builder_address {
                    tracing::debug!(
                        "op {:?} sender {:?} already assigned to another builder {:?}, skipping",
                        op.hash,
                        op.sender,
                        entry.0
                    );
                    continue;
                }

                state
                    .builder_to_uo_senders
                    .entry(builder_address)
                    .or_insert_with(|| {
                        self.metrics.active_builders.increment(1);
                        HashSet::new()
                    })
                    .insert(op.sender);

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

        Ok(return_ops)
    }

    // This method confirms the locks for the confirmed senders and drops the locks for the senders that are not confirmed.
    // If a sender is assigned to the builder, is in the "assigned" state, and is not confirmed, it will be dropped.
    // If a sender is assigned to the builder, and is in the "confirmed" state, it will be kept regardless of whether it is in the confirmed_senders list or not.
    //
    // This method is typically called when the builder is done forming and sending a bundle. Confirmed senders are the senders that were included in the bundle.
    //
    // PANICS:
    // - If the confirmed_sender is not found in the state, the builder must have been assigned this sender via the assign_operations method.
    // - If the confirmed_sender is assigned to another builder, the builder must have been assigned this sender via the assign_operations method.
    // - If the builder_address is not found in the state, the builder must have been assigned via the assign_operations method.
    // - If the builder is assigned a sender that is not found in the uo_sender_to_builder_state map, this is an internal error.
    pub(crate) fn confirm_senders_drop_unused<'a>(
        &self,
        builder_address: Address,
        confirmed_senders: impl IntoIterator<Item = &'a Address>,
    ) {
        let mut state = self.state.lock().unwrap();
        let per_builder_metrics =
            PerBuilderMetrics::new_with_labels(&[("builder_address", builder_address.to_string())]);

        // Confirm all of the senders in state
        for confirmed_sender in confirmed_senders.into_iter() {
            let entry = state
                .uo_sender_to_builder_state
                .get_mut(confirmed_sender)
                .expect("BUG: confirmed_sender not found in state, lock contract broken");

            if entry.0 != builder_address {
                panic!("BUG: confirmed_sender {:?} is assigned to another builder expected: {:?} found: {:?}, lock contract broken", confirmed_sender, builder_address, entry.0);
            }

            // Confirm the sender to the builder
            if entry.1 == LockState::Assigned {
                tracing::debug!(
                    "confirmed_sender {:?} confirmed to builder {:?}",
                    confirmed_sender,
                    builder_address
                );
                per_builder_metrics.senders_confirmed.increment(1);
                per_builder_metrics.senders_assigned.decrement(1);
                entry.1 = LockState::Confirmed;
            }
        }

        // Drop locks for all senders that are still in the assigned state
        let builder_senders = state
            .builder_to_uo_senders
            .get(&builder_address)
            .expect("BUG: builder_address not found in state, lock contract broken");

        let mut to_remove = Vec::new();

        for sender in builder_senders.iter() {
            let entry = state
                .uo_sender_to_builder_state
                .get(sender)
                .expect("BUG: sender not found in state, lock contract broken");
            if entry.1 != LockState::Confirmed {
                to_remove.push(*sender);
            }
        }

        for sender in to_remove {
            state.uo_sender_to_builder_state.remove(&sender);
            let builder_senders = state
                .builder_to_uo_senders
                .get_mut(&builder_address)
                .unwrap();
            builder_senders.remove(&sender);
            tracing::debug!(
                "sender {:?} removed from builder {:?}",
                sender,
                builder_address
            );
            per_builder_metrics.senders_assigned.decrement(1);

            if builder_senders.is_empty() {
                self.metrics.active_builders.decrement(1);
                state.builder_to_uo_senders.remove(&builder_address);
            }
        }
    }

    // This method releases all of the senders assigned to the builder.
    // This is typically done when the builder is done forming a bundle and is ready to start forming the next bundle.
    pub(crate) fn release_all(&self, builder_address: Address) {
        let mut state = self.state.lock().unwrap();
        let Some(builder_senders) = state.builder_to_uo_senders.remove(&builder_address) else {
            return;
        };
        let per_builder_metrics =
            PerBuilderMetrics::new_with_labels(&[("builder_address", builder_address.to_string())]);

        for sender in builder_senders {
            if let Some((_, state)) = state.uo_sender_to_builder_state.remove(&sender) {
                tracing::debug!(
                    "sender {:?} removed from builder {:?}",
                    sender,
                    builder_address
                );
                match state {
                    LockState::Assigned => {
                        per_builder_metrics.senders_assigned.decrement(1);
                    }
                    LockState::Confirmed => {
                        per_builder_metrics.senders_confirmed.decrement(1);
                    }
                }
            }
        }

        self.metrics.active_builders.decrement(1);
    }
}

#[derive(Metrics, Clone)]
#[metrics(scope = "builder_assigner")]
struct GlobalMetrics {
    #[metric(describe = "the number of active builders.")]
    active_builders: Gauge,
}

#[derive(Metrics)]
#[metrics(scope = "builder_assigner")]
struct PerBuilderMetrics {
    #[metric(describe = "the count of senders assigned to a builder.")]
    senders_assigned: Gauge,
    #[metric(describe = "the count of senders confirmed to a builder.")]
    senders_confirmed: Gauge,
}

#[cfg(test)]
mod tests {
    use alloy_primitives::B256;
    use rundler_types::{
        chain::ChainSpec,
        pool::MockPool,
        v0_6::{UserOperationBuilder, UserOperationRequiredFields},
        EntityInfos, UserOperation, UserOperationPermissions, ValidTimeRange,
    };

    use super::*;

    fn create_test_ops(senders: &[Address]) -> Vec<PoolOperation> {
        senders
            .iter()
            .map(|sender| {
                let uo = UserOperationBuilder::new(
                    &ChainSpec::default(),
                    UserOperationRequiredFields {
                        sender: *sender,
                        ..Default::default()
                    },
                )
                .build()
                .into();
                PoolOperation {
                    uo,
                    expected_code_hash: B256::ZERO,
                    entry_point: Address::ZERO,
                    sim_block_hash: B256::ZERO,
                    sim_block_number: 0,
                    account_is_staked: false,
                    valid_time_range: ValidTimeRange::default(),
                    entity_infos: EntityInfos::default(),
                    aggregator: None,
                    da_gas_data: Default::default(),
                    filter_id: None,
                    perms: UserOperationPermissions::default(),
                }
            })
            .collect()
    }

    fn mock_pool_get_ops(mock_pool: &mut MockPool, ops: Vec<PoolOperation>) {
        let ops_cloned = ops.clone();
        mock_pool
            .expect_get_ops_summaries()
            .returning(move |_, _, _| {
                Ok(ops_cloned.iter().map(|op| op.into()).collect::<Vec<_>>())
            });
        mock_pool
            .expect_get_ops_by_hashes()
            .returning(move |_, hashes| {
                Ok(ops
                    .iter()
                    .filter(|op| hashes.contains(&op.uo.hash()))
                    .cloned()
                    .collect::<Vec<_>>())
            });
    }

    #[tokio::test]
    async fn test_no_operations() {
        let mut mock_pool = MockPool::new();
        mock_pool_get_ops(&mut mock_pool, vec![]);
        let assigner = Assigner::new(Arc::new(mock_pool), 10, 10);

        // First assignment should succeed
        let assigned_ops = assigner
            .assign_operations(address(0), address(0), None)
            .await
            .unwrap();
        assert_eq!(assigned_ops.len(), 0); // TestPool returns empty by default
    }

    #[tokio::test]
    async fn test_assign_operations() {
        let mut mock_pool = MockPool::new();
        let ops = create_test_ops(&[address(1), address(2)]);
        mock_pool_get_ops(&mut mock_pool, ops.clone());

        let assigner = Assigner::new(Arc::new(mock_pool), 10, 10);
        let assigned_ops = assigner
            .assign_operations(address(0), address(0), None)
            .await
            .unwrap();
        assert_eq!(assigned_ops.len(), 2);
        assert_eq!(assigned_ops[0].uo.sender(), address(1));
        assert_eq!(assigned_ops[1].uo.sender(), address(2));
    }

    #[tokio::test]
    async fn test_assign_twice() {
        let mut mock_pool = MockPool::new();
        let ops = create_test_ops(&[address(1), address(2)]);
        mock_pool_get_ops(&mut mock_pool, ops.clone());

        let assigner = Assigner::new(Arc::new(mock_pool), 10, 10);
        let _ = assigner
            .assign_operations(address(0), address(0), None)
            .await
            .unwrap();

        // Same builder address should assign again
        let assigned_ops = assigner
            .assign_operations(address(0), address(0), None)
            .await
            .unwrap();
        assert_eq!(assigned_ops.len(), 2);
        // Different builder address should not assign
        let assigned_ops = assigner
            .assign_operations(address(1), address(0), None)
            .await
            .unwrap();
        assert_eq!(assigned_ops.len(), 0);
    }

    #[tokio::test]
    async fn test_assign_after_drop() {
        let mut mock_pool = MockPool::new();
        let ops = create_test_ops(&[address(1), address(2)]);
        mock_pool_get_ops(&mut mock_pool, ops.clone());

        let assigner = Assigner::new(Arc::new(mock_pool), 10, 10);
        let _ = assigner
            .assign_operations(address(0), address(0), None)
            .await
            .unwrap();

        // Same builder address should assign again
        assigner.confirm_senders_drop_unused(address(0), &[address(1)]);

        // Different builder should be able go receive address(2)
        let assigned_ops = assigner
            .assign_operations(address(1), address(0), None)
            .await
            .unwrap();
        assert_eq!(assigned_ops.len(), 1);
        assert_eq!(assigned_ops[0].uo.sender(), address(2));
    }

    #[tokio::test]
    async fn test_assign_after_release() {
        let mut mock_pool = MockPool::new();
        let ops = create_test_ops(&[address(1), address(2)]);
        mock_pool_get_ops(&mut mock_pool, ops.clone());

        let assigner = Assigner::new(Arc::new(mock_pool), 10, 10);
        let _ = assigner
            .assign_operations(address(0), address(0), None)
            .await
            .unwrap();

        // Same builder address should assign again
        assigner.release_all(address(0));

        let assigned_ops = assigner
            .assign_operations(address(1), address(0), None)
            .await
            .unwrap();
        assert_eq!(assigned_ops.len(), 2);
        assert_eq!(assigned_ops[0].uo.sender(), address(1));
        assert_eq!(assigned_ops[1].uo.sender(), address(2));
    }

    #[tokio::test]
    async fn test_cannot_drop_confirmed_senders() {
        let mut mock_pool = MockPool::new();
        let ops = create_test_ops(&[address(1), address(2)]);
        mock_pool_get_ops(&mut mock_pool, ops.clone());

        let assigner = Assigner::new(Arc::new(mock_pool), 10, 10);
        let _ = assigner
            .assign_operations(address(0), address(0), None)
            .await
            .unwrap();

        // confirm address(1)
        assigner.confirm_senders_drop_unused(address(0), &[address(1)]);
        // this should not drop lock on address(1)
        assigner.confirm_senders_drop_unused(address(0), &[]);

        // Different builder should be able go receive address(2)
        let assigned_ops = assigner
            .assign_operations(address(1), address(0), None)
            .await
            .unwrap();
        assert_eq!(assigned_ops.len(), 1);
        assert_eq!(assigned_ops[0].uo.sender(), address(2));
    }

    #[tokio::test]
    #[should_panic]
    async fn test_try_confirm_unknown_sender() {
        let mut mock_pool = MockPool::new();
        let ops = create_test_ops(&[address(1), address(2)]);
        mock_pool_get_ops(&mut mock_pool, ops.clone());

        let assigner = Assigner::new(Arc::new(mock_pool), 10, 10);
        assigner.confirm_senders_drop_unused(address(0), &[address(3)]);
    }

    #[tokio::test]
    #[should_panic]
    async fn test_try_confirm_sender_not_assigned() {
        let mock_pool = MockPool::new();
        let assigner = Assigner::new(Arc::new(mock_pool), 10, 10);
        assigner.confirm_senders_drop_unused(address(1), &[address(1)]);
    }

    #[tokio::test]
    #[should_panic]
    async fn test_try_confirm_sender_assigned_to_other_builder() {
        let mut mock_pool = MockPool::new();
        let ops = create_test_ops(&[address(1), address(2)]);
        mock_pool_get_ops(&mut mock_pool, ops.clone());

        let assigner = Assigner::new(Arc::new(mock_pool), 10, 10);
        let _ = assigner
            .assign_operations(address(0), address(0), None)
            .await
            .unwrap();

        assigner.confirm_senders_drop_unused(address(1), &[address(1)]);
    }

    fn address(i: u64) -> Address {
        Address::from([i as u8; 20])
    }
}
