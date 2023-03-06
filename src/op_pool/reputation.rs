use ethers::types::{Address, H256};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::interval;
use tracing::error;

use crate::common::{
    contracts::entry_point::EntryPointEvents,
    protos::op_pool::{Reputation, ReputationStatus},
};

use super::events::NewBlockEvent;

pub trait ReputationManager: Send + Sync {
    /// Callback for new block events
    fn on_new_block(&self, new_block: &NewBlockEvent);

    /// Called by mempool before returning operations to bundler
    fn status(&self, address: Address) -> ReputationStatus;

    /// Called by mempool when an operation is added to the pool
    fn add_seen<'a>(&self, addresses: impl IntoIterator<Item = &'a Address>);

    /// Called by debug API
    fn dump_reputation(&self) -> Vec<Reputation>;

    /// Called by debug API
    fn set_reputation(&self, address: Address, ops_seen: u64, ops_included: u64);
}

#[derive(Debug)]
pub struct HourlyMovingAverageReputationManager {
    reputation: RwLock<AddressReputation>,
}

impl HourlyMovingAverageReputationManager {
    pub fn new(params: ReputationParams) -> Self {
        Self {
            reputation: RwLock::new(AddressReputation::new(params)),
        }
    }

    // run the reputation hourly update job
    pub async fn run(&self) {
        let mut tick = interval(Duration::from_secs(60 * 60));
        loop {
            tick.tick().await;
            self.reputation.write().hourly_update();
        }
    }
}

impl ReputationManager for HourlyMovingAverageReputationManager {
    fn on_new_block(&self, new_block: &NewBlockEvent) {
        let mut reputation = self.reputation.write();
        for event in &new_block.events {
            match &event.contract_event {
                EntryPointEvents::UserOperationEventFilter(uo_event) => {
                    let paymaster = if uo_event.paymaster.is_zero() {
                        None
                    } else {
                        Some(uo_event.paymaster)
                    };

                    reputation.add_included_op(
                        uo_event.sender,
                        paymaster,
                        uo_event.user_op_hash.into(),
                    );
                }
                EntryPointEvents::AccountDeployedFilter(ad_event) => {
                    reputation.add_included(ad_event.factory);
                }
                EntryPointEvents::SignatureAggregatorChangedFilter(sa_event) => {
                    let aggregator = if sa_event.aggregator.is_zero() {
                        None
                    } else {
                        Some(sa_event.aggregator)
                    };

                    reputation.set_aggregator(aggregator, event.txn_hash);
                }
                _ => {}
            }
        }
    }

    fn status(&self, address: Address) -> ReputationStatus {
        self.reputation.read().status(address)
    }

    fn add_seen<'a>(&self, addresses: impl IntoIterator<Item = &'a Address>) {
        let mut reputation = self.reputation.write();
        for address in addresses {
            reputation.add_seen(*address);
        }
    }

    fn dump_reputation(&self) -> Vec<Reputation> {
        let reputation = self.reputation.read();
        reputation
            .counts
            .iter()
            .map(|(address, count)| Reputation {
                address: address.as_bytes().to_vec(),
                status: reputation.status(*address).into(),
                ops_seen: count.ops_seen,
                ops_included: count.ops_included,
            })
            .collect()
    }

    fn set_reputation(&self, address: Address, ops_seen: u64, ops_included: u64) {
        self.reputation
            .write()
            .set_reputation(address, ops_seen, ops_included)
    }
}

#[derive(Debug, Clone)]
pub struct ReputationParams {
    min_inclusion_rate_denominator: u64,
    throttling_slack: u64,
    ban_slack: u64,
}

impl ReputationParams {
    pub fn bundler_default() -> Self {
        Self {
            min_inclusion_rate_denominator: 10,
            throttling_slack: 10,
            ban_slack: 50,
        }
    }

    #[allow(dead_code)]
    pub fn client_default() -> Self {
        Self {
            min_inclusion_rate_denominator: 100,
            throttling_slack: 10,
            ban_slack: 50,
        }
    }
}

#[derive(Debug)]
struct AddressReputation {
    counts: HashMap<Address, AddressCount>,
    params: ReputationParams,
    aggregator: Option<Address>,
    aggregator_txn_hash: H256,
}

impl AddressReputation {
    pub fn new(params: ReputationParams) -> Self {
        Self {
            counts: HashMap::new(),
            params,
            aggregator: None,
            aggregator_txn_hash: H256::zero(),
        }
    }

    pub fn status(&self, address: Address) -> ReputationStatus {
        let count = match self.counts.get(&address) {
            Some(count) => count,
            None => return ReputationStatus::Ok,
        };

        let min_expected_included = count.ops_seen / self.params.min_inclusion_rate_denominator;
        if min_expected_included <= count.ops_included + self.params.throttling_slack {
            ReputationStatus::Ok
        } else if min_expected_included <= count.ops_included + self.params.ban_slack {
            ReputationStatus::Throttled
        } else {
            ReputationStatus::Banned
        }
    }

    pub fn add_seen(&mut self, address: Address) {
        let count = self.counts.entry(address).or_default();
        count.ops_seen += 1;
    }

    pub fn add_included(&mut self, address: Address) {
        let count = self.counts.entry(address).or_default();
        count.ops_included += 1;
    }

    pub fn add_included_op(&mut self, sender: Address, paymaster: Option<Address>, txn_hash: H256) {
        self.add_included(sender);

        if let Some(paymaster) = paymaster {
            self.add_included(paymaster);
        }

        if self.aggregator_txn_hash == txn_hash {
            if let Some(aggregator) = self.aggregator {
                self.add_included(aggregator);
            } else {
                error!("aggregator txn hash {txn_hash:?} is equal but aggregator is not set");
            }
        }
    }

    pub fn set_reputation(&mut self, address: Address, ops_seen: u64, ops_included: u64) {
        let count = self.counts.entry(address).or_default();
        count.ops_seen = ops_seen;
        count.ops_included = ops_included;
    }

    pub fn set_aggregator(&mut self, aggregator: Option<Address>, txn_hash: H256) {
        self.aggregator = aggregator;
        self.aggregator_txn_hash = txn_hash;
    }

    pub fn hourly_update(&mut self) {
        for count in self.counts.values_mut() {
            count.ops_seen -= count.ops_seen / 24;
            count.ops_included -= count.ops_included / 24;
        }
        self.counts
            .retain(|_, count| count.ops_seen > 0 || count.ops_included > 0);
    }
}

#[derive(Debug, Default, Clone)]
struct AddressCount {
    ops_seen: u64,
    ops_included: u64,
}
