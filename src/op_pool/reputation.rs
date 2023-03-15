use ethers::types::{Address, H256};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::interval;

use crate::common::protos::op_pool::{Reputation, ReputationStatus};

/// Reputation manager trait
///
/// Interior mutability pattern used as ReputationManagers may
/// need to be thread-safe.
pub trait ReputationManager: Send + Sync {
    /// Called by mempool before returning operations to bundler
    fn status(&self, address: Address) -> ReputationStatus;

    /// Called by mempool when an operation is added to the pool
    fn add_seen<'a>(&self, addresses: impl IntoIterator<Item = &'a Address>);

    /// Called by the mempool when an operation is removed from the pool
    fn add_included<'a>(&self, addresses: impl IntoIterator<Item = &'a Address>);

    /// Called by the mempool during a block event when the aggregator changes
    /// Must be called before `add_included` for an operation that uses the aggregator
    fn set_aggregator(&self, aggregator: Option<Address>, txn_hash: H256);

    /// Called by the mempool during a block event to check if
    /// there is an aggregator set for the current txn_hash
    fn get_aggregator(&self, txn_hash: H256) -> Option<Address>;

    /// Called by debug API
    fn dump_reputation(&self) -> Vec<Reputation>;

    /// Called by debug API
    fn set_reputation(&self, address: Address, ops_seen: u64, ops_included: u64);
}

#[derive(Debug)]
pub struct HourlyMovingAverageReputation {
    reputation: RwLock<AddressReputation>,
}

impl HourlyMovingAverageReputation {
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

impl ReputationManager for HourlyMovingAverageReputation {
    fn status(&self, address: Address) -> ReputationStatus {
        self.reputation.read().status(address)
    }

    fn add_seen<'a>(&self, addresses: impl IntoIterator<Item = &'a Address>) {
        let mut reputation = self.reputation.write();
        for address in addresses {
            reputation.add_seen(*address);
        }
    }

    fn add_included<'a>(&self, addresses: impl IntoIterator<Item = &'a Address>) {
        let mut reputation = self.reputation.write();
        for address in addresses {
            reputation.add_included(*address);
        }
    }

    fn set_aggregator(&self, aggregator: Option<Address>, txn_hash: H256) {
        self.reputation.write().set_aggregator(aggregator, txn_hash);
    }

    fn get_aggregator(&self, txn_hash: H256) -> Option<Address> {
        self.reputation.read().get_aggregator(txn_hash)
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

    pub fn set_aggregator(&mut self, aggregator: Option<Address>, txn_hash: H256) {
        self.aggregator = aggregator;
        self.aggregator_txn_hash = txn_hash;
    }

    pub fn get_aggregator(&self, txn_hash: H256) -> Option<Address> {
        if txn_hash != self.aggregator_txn_hash {
            None
        } else {
            self.aggregator
        }
    }

    pub fn set_reputation(&mut self, address: Address, ops_seen: u64, ops_included: u64) {
        let count = self.counts.entry(address).or_default();
        count.ops_seen = ops_seen;
        count.ops_included = ops_included;
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
