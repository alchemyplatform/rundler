#![allow(dead_code)] // TODO(danc): remove this once done
#![allow(unused_variables)]

use ethers::types::{Address, H256};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::interval;
use tokio_stream::wrappers::IntervalStream;
use tokio_stream::StreamExt;
use tracing::error;

use crate::common::protos::op_pool::{Reputation, ReputationStatus};

use crate::op_pool::events::{
    AccountDeployedEvent, SignagureAggregatorChangedEvent, UserOperationEvent,
};

pub struct ReputationManager {
    reputation: RwLock<AddressReputation>,
}

// TODO:
// - Event listener integration
// - Mempool integration
impl ReputationManager {
    pub fn new(params: ReputationParams) -> Self {
        Self {
            reputation: RwLock::new(AddressReputation::new(params)),
        }
    }

    // run the reputation hourly update job
    pub async fn run(&self) {
        let mut tick = IntervalStream::new(interval(Duration::from_secs(60 * 60)));
        while tick.next().await.is_some() {
            self.reputation.write().hourly_update();
        }
        error!("Reputation manager update stream stopped");
    }

    // Called by mempool before returning operations to bundler
    pub fn status(&self, address: Address) -> ReputationStatus {
        self.reputation.read().status(address)
    }

    // Called by debug API
    pub fn dump_reputation(&self) -> Vec<Reputation> {
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

    // Called by debug API
    pub fn set_reputation(&self, reputation: Reputation) {
        self.reputation.write().set_reputation(reputation)
    }

    // Called by mempool when an operation is added to the pool
    pub fn add_seen(&self, addresses: impl IntoIterator<Item = Address>) {
        let mut reputation = self.reputation.write();
        for address in addresses {
            reputation.add_seen(address);
        }
    }

    // Called by event listener
    pub fn on_user_operation(&self, event: UserOperationEvent) {
        self.reputation
            .write()
            .add_included_op(event.sender, event.paymaster, event.txn_hash);
    }

    // Called by event listener
    pub fn on_signature_aggregator_changed(&self, event: SignagureAggregatorChangedEvent) {
        self.reputation
            .write()
            .set_aggregator(event.aggregator, event.tx_hash);
    }

    // Called by event listener
    pub fn on_account_deployed(&self, event: AccountDeployedEvent) {
        self.reputation.write().add_included(event.factory);
    }
}

#[derive(Debug, Clone)]
pub struct ReputationParams {
    min_inclusion_rate_denominator: u64,
    throttling_slack: u64,
    ban_slack: u64,
}

impl ReputationParams {
    fn bundler_default() -> Self {
        Self {
            min_inclusion_rate_denominator: 10,
            throttling_slack: 10,
            ban_slack: 50,
        }
    }

    fn client_default() -> Self {
        Self {
            min_inclusion_rate_denominator: 100,
            throttling_slack: 10,
            ban_slack: 50,
        }
    }
}

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

    pub fn set_reputation(&mut self, reputation: Reputation) {
        let address = Address::from_slice(&reputation.address);
        let count = self.counts.entry(address).or_default();
        count.ops_seen = reputation.ops_seen;
        count.ops_included = reputation.ops_included;
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
