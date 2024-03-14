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
    time::Duration,
};

use ethers::types::Address;
use parking_lot::RwLock;
use rundler_types::pool::{Reputation, ReputationStatus};
use tokio::time::interval;

#[derive(Debug, Clone, Copy)]
pub(crate) struct ReputationParams {
    bundle_invalidation_ops_seen_staked_penalty: u64,
    bundle_invalidation_ops_seen_unstaked_penalty: u64,
    same_unstaked_entity_mempool_count: u64,
    min_inclusion_rate_denominator: u64,
    inclusion_rate_factor: u64,
    throttling_slack: u64,
    ban_slack: u64,
    tracking_enabled: bool,
    decay_interval_secs: u64,
    decay_factor: u64,
}

impl Default for ReputationParams {
    fn default() -> Self {
        Self {
            bundle_invalidation_ops_seen_staked_penalty: 10_000,
            bundle_invalidation_ops_seen_unstaked_penalty: 1_000,
            same_unstaked_entity_mempool_count: 10,
            min_inclusion_rate_denominator: 10,
            inclusion_rate_factor: 10,
            throttling_slack: 10,
            ban_slack: 50,
            tracking_enabled: true,
            decay_interval_secs: 3600,
            decay_factor: 24,
        }
    }
}

impl ReputationParams {
    pub(crate) fn new(tracking_enabled: bool) -> Self {
        Self {
            tracking_enabled,
            ..Default::default()
        }
    }

    #[allow(dead_code)]
    pub(crate) fn bundler_default() -> Self {
        Self::default()
    }

    #[allow(dead_code)]
    pub(crate) fn client_default() -> Self {
        Self {
            min_inclusion_rate_denominator: 100,
            ..Self::default()
        }
    }

    #[cfg(test)]
    pub(crate) fn test_parameters(ban_slack: u64, throttling_slack: u64) -> Self {
        Self {
            ban_slack,
            throttling_slack,
            ..Self::default()
        }
    }
}

pub(crate) struct AddressReputation {
    state: RwLock<AddressReputationInner>,
}

impl AddressReputation {
    pub(crate) fn new(
        params: ReputationParams,
        blocklist: HashSet<Address>,
        allowlist: HashSet<Address>,
    ) -> AddressReputation {
        Self {
            state: RwLock::new(
                AddressReputationInner::new(params)
                    .with_blocklist(blocklist)
                    .with_allowlist(allowlist),
            ),
        }
    }

    pub(crate) async fn run(&self) {
        let mut tick = interval(Duration::from_secs(
            self.state.read().params.decay_interval_secs,
        ));
        loop {
            tick.tick().await;
            self.state.write().update();
        }
    }

    pub(crate) fn status(&self, address: Address) -> ReputationStatus {
        self.state.read().status(address)
    }

    pub(crate) fn add_seen(&self, address: Address) {
        self.state.write().add_seen(address);
    }

    pub(crate) fn handle_urep_030_penalty(&self, address: Address) {
        self.state.write().handle_urep_030_penalty(address);
    }

    pub(crate) fn handle_srep_050_penalty(&self, address: Address) {
        self.state.write().handle_srep_050_penalty(address);
    }

    pub(crate) fn dump_reputation(&self) -> Vec<Reputation> {
        self.state.read().dump_reputation()
    }

    pub(crate) fn add_included(&self, address: Address) {
        self.state.write().add_included(address);
    }

    pub(crate) fn remove_included(&self, address: Address) {
        self.state.write().remove_included(address);
    }

    pub(crate) fn set_reputation(&self, address: Address, ops_seen: u64, ops_included: u64) {
        self.state
            .write()
            .set_reputation(address, ops_seen, ops_included);
    }

    pub(crate) fn get_ops_allowed(&self, address: Address) -> u64 {
        self.state.read().get_ops_allowed(address)
    }

    pub(crate) fn clear(&self) {
        self.state.write().clear();
    }

    pub(crate) fn set_tracking(&self, tracking_enabled: bool) {
        self.state.write().set_tracking(tracking_enabled);
    }
}

#[derive(Debug)]
struct AddressReputationInner {
    // Addresses that are always banned
    blocklist: HashSet<Address>,
    // Addresses that are always exempt from throttling and banning
    allowlist: HashSet<Address>,
    counts: HashMap<Address, AddressCount>,
    params: ReputationParams,
}

impl AddressReputationInner {
    fn new(params: ReputationParams) -> AddressReputationInner {
        AddressReputationInner {
            blocklist: HashSet::new(),
            allowlist: HashSet::new(),
            counts: HashMap::new(),
            params,
        }
    }

    fn with_blocklist(self, blocklist: HashSet<Address>) -> AddressReputationInner {
        AddressReputationInner { blocklist, ..self }
    }

    fn with_allowlist(self, allowlist: HashSet<Address>) -> AddressReputationInner {
        AddressReputationInner { allowlist, ..self }
    }

    fn status(&self, address: Address) -> ReputationStatus {
        if self.blocklist.contains(&address) {
            return ReputationStatus::Banned;
        } else if self.allowlist.contains(&address) {
            return ReputationStatus::Ok;
        }

        if !self.params.tracking_enabled {
            return ReputationStatus::Ok;
        }

        let count = match self.counts.get(&address) {
            Some(count) => count,
            None => return ReputationStatus::Ok,
        };

        let min_expected_included = count.ops_seen / self.params.min_inclusion_rate_denominator;
        if min_expected_included <= (count.ops_included + self.params.throttling_slack) {
            ReputationStatus::Ok
        } else if min_expected_included <= (count.ops_included + self.params.ban_slack) {
            ReputationStatus::Throttled
        } else {
            ReputationStatus::Banned
        }
    }

    fn add_seen(&mut self, address: Address) {
        let count = self.counts.entry(address).or_default();
        count.ops_seen += 1;
    }

    fn handle_urep_030_penalty(&mut self, address: Address) {
        let count = self.counts.entry(address).or_default();
        count.ops_seen += self.params.bundle_invalidation_ops_seen_unstaked_penalty;
    }

    fn handle_srep_050_penalty(&mut self, address: Address) {
        let count = self.counts.entry(address).or_default();
        // According to the spec we set ops_seen here instead of incrementing it
        count.ops_seen = self.params.bundle_invalidation_ops_seen_staked_penalty;
    }

    fn dump_reputation(&self) -> Vec<Reputation> {
        self.counts
            .iter()
            .map(|(address, count)| Reputation {
                address: *address,
                ops_seen: count.ops_seen,
                ops_included: count.ops_included,
            })
            .collect()
    }

    fn add_included(&mut self, address: Address) {
        let count = self.counts.entry(address).or_default();
        count.ops_included += 1;
    }

    fn remove_included(&mut self, address: Address) {
        let count = self.counts.entry(address).or_default();
        count.ops_included = count.ops_included.saturating_sub(1)
    }

    fn set_reputation(&mut self, address: Address, ops_seen: u64, ops_included: u64) {
        let count = self.counts.entry(address).or_default();
        count.ops_seen = ops_seen;
        count.ops_included = ops_included;
    }

    fn get_ops_allowed(&self, address: Address) -> u64 {
        let (seen, included) = self
            .counts
            .get(&address)
            .map_or((0, 0), |c| (c.ops_seen, c.ops_included));

        let inclusion_based_count = if seen == 0 {
            // make sure we aren't dividing by 0
            0
        } else {
            self.params.inclusion_rate_factor * included / seen + std::cmp::min(included, 10_000)
        };

        // return ops allowed, as defined by UREP-020
        self.params.same_unstaked_entity_mempool_count + inclusion_based_count
    }

    fn update(&mut self) {
        for count in self.counts.values_mut() {
            count.ops_seen -= count.ops_seen / self.params.decay_factor;
            count.ops_included -= count.ops_included / self.params.decay_factor;
        }
        self.counts
            .retain(|_, count| count.ops_seen > 0 || count.ops_included > 0);
    }

    fn clear(&mut self) {
        self.counts.clear();
    }

    fn set_tracking(&mut self, tracking_enabled: bool) {
        self.params.tracking_enabled = tracking_enabled;
    }
}

#[derive(Debug, Default, Clone)]
struct AddressCount {
    ops_seen: u64,
    ops_included: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test AddressReputation

    #[test]
    fn seen_included() {
        let addr = Address::random();
        let mut reputation = AddressReputationInner::new(ReputationParams::bundler_default());

        for _ in 0..1000 {
            reputation.add_seen(addr);
            reputation.add_included(addr);
        }
        let counts = reputation.counts.get(&addr).unwrap();
        assert_eq!(counts.ops_seen, 1000);
        assert_eq!(counts.ops_included, 1000);
    }

    #[test]
    fn set_rep() {
        let addr = Address::random();
        let mut reputation = AddressReputationInner::new(ReputationParams::bundler_default());

        reputation.set_reputation(addr, 1000, 1000);
        let counts = reputation.counts.get(&addr).unwrap();
        assert_eq!(counts.ops_seen, 1000);
        assert_eq!(counts.ops_included, 1000);
    }

    #[test]
    fn reputation_ok() {
        let addr = Address::random();
        let mut reputation = AddressReputationInner::new(ReputationParams::bundler_default());
        reputation.add_seen(addr);
        assert_eq!(reputation.status(addr), ReputationStatus::Ok);
    }

    #[test]
    fn reputation_throttled() {
        let addr = Address::random();
        let params = ReputationParams::bundler_default();
        let mut reputation = AddressReputationInner::new(params);

        let ops_seen = 1000;
        let ops_included =
            ops_seen / params.min_inclusion_rate_denominator - params.throttling_slack - 1;
        reputation.set_reputation(addr, ops_seen, ops_included);
        assert_eq!(reputation.status(addr), ReputationStatus::Throttled);
    }

    #[test]
    fn reputation_throttled_edge() {
        let addr = Address::random();
        let params = ReputationParams::bundler_default();
        let mut reputation = AddressReputationInner::new(params);

        let ops_seen = 1000;
        let ops_included =
            ops_seen / params.min_inclusion_rate_denominator - params.throttling_slack;
        reputation.set_reputation(addr, ops_seen, ops_included);
        assert_eq!(reputation.status(addr), ReputationStatus::Ok);
    }

    #[test]
    fn reputation_banned() {
        let addr = Address::random();
        let params = ReputationParams::bundler_default();
        let mut reputation = AddressReputationInner::new(params);

        let ops_seen = 1000;
        let ops_included = ops_seen / params.min_inclusion_rate_denominator - params.ban_slack - 1;
        reputation.set_reputation(addr, ops_seen, ops_included);
        assert_eq!(reputation.status(addr), ReputationStatus::Banned);
    }

    #[test]
    fn reputation_banned_tracking_disabled() {
        let addr = Address::random();
        let params = ReputationParams::new(false);
        let mut reputation = AddressReputationInner::new(params);

        let ops_seen = 1000;
        let ops_included = ops_seen / params.min_inclusion_rate_denominator - params.ban_slack - 1;
        reputation.set_reputation(addr, ops_seen, ops_included);
        assert_eq!(reputation.status(addr), ReputationStatus::Ok);
    }

    #[test]
    fn hourly_update() {
        let addr = Address::random();
        let mut reputation = AddressReputationInner::new(ReputationParams::bundler_default());

        for _ in 0..1000 {
            reputation.add_seen(addr);
            reputation.add_included(addr);
        }

        reputation.update();
        let counts = reputation.counts.get(&addr).unwrap();
        assert_eq!(
            counts.ops_seen,
            1000 - 1000 / reputation.params.decay_factor
        );
        assert_eq!(
            counts.ops_included,
            1000 - 1000 / reputation.params.decay_factor
        );
    }

    #[test]
    fn test_blocklist() {
        let addr = Address::random();
        let reputation = AddressReputationInner::new(ReputationParams::bundler_default())
            .with_blocklist(HashSet::from([addr]));

        assert_eq!(reputation.status(addr), ReputationStatus::Banned);
        assert_eq!(reputation.status(Address::random()), ReputationStatus::Ok);
    }

    #[test]
    fn test_allowlist() {
        let addr = Address::random();
        let mut reputation = AddressReputationInner::new(ReputationParams::bundler_default())
            .with_allowlist(HashSet::from([addr]));
        reputation.set_reputation(addr, 1000000, 0);

        assert_eq!(reputation.status(addr), ReputationStatus::Ok);
    }

    // Test HourlyMovingAverageReputation

    #[test]
    fn manager_seen_included() {
        let mut manager = AddressReputationInner::new(ReputationParams::bundler_default());
        let addrs = [Address::random(), Address::random(), Address::random()];

        for _ in 0..10 {
            for addr in addrs {
                manager.add_seen(addr);
                manager.add_included(addr);
            }
        }

        for addr in &addrs {
            assert_eq!(manager.status(*addr), ReputationStatus::Ok);

            let counts = manager.counts.get(addr).unwrap();
            assert_eq!(counts.ops_seen, 10);
            assert_eq!(counts.ops_included, 10);
        }
    }

    #[test]
    fn manager_set_dump_reputation() {
        let mut manager = AddressReputationInner::new(ReputationParams::bundler_default());
        let addrs = [Address::random(), Address::random(), Address::random()];

        for addr in &addrs {
            manager.set_reputation(*addr, 1000, 1000);
        }

        let reps = manager.dump_reputation();
        for rep in reps {
            assert_eq!(rep.ops_seen, 1000);
            assert_eq!(rep.ops_included, 1000);
            assert!(addrs.contains(&rep.address));
        }
    }
}
