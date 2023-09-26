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
#[cfg(test)]
use mockall::automock;
use parking_lot::RwLock;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use tokio::time::interval;

/// Reputation status for an entity
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ReputationStatus {
    /// Entity is not throttled or banned
    Ok,
    /// Entity is throttled
    Throttled,
    /// Entity is banned
    Banned,
}

impl Serialize for ReputationStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            ReputationStatus::Ok => serializer.serialize_str("ok"),
            ReputationStatus::Throttled => serializer.serialize_str("throttled"),
            ReputationStatus::Banned => serializer.serialize_str("banned"),
        }
    }
}

impl<'de> Deserialize<'de> for ReputationStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "ok" => Ok(ReputationStatus::Ok),
            "throttled" => Ok(ReputationStatus::Throttled),
            "banned" => Ok(ReputationStatus::Banned),
            _ => Err(de::Error::custom(format!("Invalid reputation status {s}"))),
        }
    }
}

/// The reputation of an entity
#[derive(Debug, Clone)]
pub struct Reputation {
    /// The entity's address
    pub address: Address,
    /// The entity's reputation status
    pub status: ReputationStatus,
    /// Number of ops seen in the current interval
    pub ops_seen: u64,
    /// Number of ops included in the current interval
    pub ops_included: u64,
}

/// Reputation manager trait
///
/// Interior mutability pattern used as ReputationManagers may
/// need to be thread-safe.
#[cfg_attr(test, automock)]
pub(crate) trait ReputationManager: Send + Sync + 'static {
    /// Called by mempool before returning operations to bundler
    fn status(&self, address: Address) -> ReputationStatus;

    /// Called by mempool when an operation that requires stake is added to the
    /// pool
    fn add_seen(&self, address: Address);

    /// Called by the mempool when an operation that requires stake is removed
    /// from the pool
    fn add_included(&self, address: Address);

    /// Called by the mempool when a previously mined operation that requires
    /// stake is returned to the pool.
    fn remove_included(&self, address: Address);

    /// Called by debug API
    fn dump_reputation(&self) -> Vec<Reputation>;

    /// Called by debug API
    fn set_reputation(&self, address: Address, ops_seen: u64, ops_included: u64);
}

#[derive(Debug)]
pub(crate) struct HourlyMovingAverageReputation {
    reputation: RwLock<AddressReputation>,
}

impl HourlyMovingAverageReputation {
    pub(crate) fn new(
        params: ReputationParams,
        blocklist: Option<HashSet<Address>>,
        allowlist: Option<HashSet<Address>>,
    ) -> Self {
        let rep = AddressReputation::new(params)
            .with_blocklist(blocklist.unwrap_or_default())
            .with_allowlist(allowlist.unwrap_or_default());

        Self {
            reputation: RwLock::new(rep),
        }
    }

    // run the reputation hourly update job
    pub(crate) async fn run(&self) {
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

    fn add_seen(&self, address: Address) {
        self.reputation.write().add_seen(address);
    }

    fn add_included(&self, address: Address) {
        self.reputation.write().add_included(address);
    }

    fn remove_included(&self, address: Address) {
        self.reputation.write().remove_included(address);
    }

    fn dump_reputation(&self) -> Vec<Reputation> {
        let reputation = self.reputation.read();
        reputation
            .counts
            .iter()
            .map(|(address, count)| Reputation {
                address: *address,
                status: reputation.status(*address),
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

#[derive(Debug, Clone, Copy)]
pub(crate) struct ReputationParams {
    min_inclusion_rate_denominator: u64,
    throttling_slack: u64,
    ban_slack: u64,
}

impl ReputationParams {
    pub(crate) fn bundler_default() -> Self {
        Self {
            min_inclusion_rate_denominator: 10,
            throttling_slack: 10,
            ban_slack: 50,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn client_default() -> Self {
        Self {
            min_inclusion_rate_denominator: 100,
            throttling_slack: 10,
            ban_slack: 50,
        }
    }
}

#[derive(Debug)]
struct AddressReputation {
    // Addresses that are always banned
    blocklist: HashSet<Address>,
    // Addresses that are always exempt from throttling and banning
    allowlist: HashSet<Address>,
    counts: HashMap<Address, AddressCount>,
    params: ReputationParams,
}

impl AddressReputation {
    fn new(params: ReputationParams) -> Self {
        Self {
            blocklist: HashSet::new(),
            allowlist: HashSet::new(),
            counts: HashMap::new(),
            params,
        }
    }

    fn with_blocklist(self, blocklist: HashSet<Address>) -> Self {
        Self { blocklist, ..self }
    }

    fn with_allowlist(self, allowlist: HashSet<Address>) -> Self {
        Self { allowlist, ..self }
    }

    fn status(&self, address: Address) -> ReputationStatus {
        if self.blocklist.contains(&address) {
            return ReputationStatus::Banned;
        } else if self.allowlist.contains(&address) {
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

    fn hourly_update(&mut self) {
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

#[cfg(test)]
mod tests {
    use super::*;

    // Test AddressReputation

    #[test]
    fn seen_included() {
        let addr = Address::random();
        let mut reputation = AddressReputation::new(ReputationParams::bundler_default());

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
        let mut reputation = AddressReputation::new(ReputationParams::bundler_default());

        reputation.set_reputation(addr, 1000, 1000);
        let counts = reputation.counts.get(&addr).unwrap();
        assert_eq!(counts.ops_seen, 1000);
        assert_eq!(counts.ops_included, 1000);
    }

    #[test]
    fn reputation_ok() {
        let addr = Address::random();
        let mut reputation = AddressReputation::new(ReputationParams::bundler_default());
        reputation.add_seen(addr);
        assert_eq!(reputation.status(addr), ReputationStatus::Ok);
    }

    #[test]
    fn reputation_throttled() {
        let addr = Address::random();
        let params = ReputationParams::bundler_default();
        let mut reputation = AddressReputation::new(params);

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
        let mut reputation = AddressReputation::new(params);

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
        let mut reputation = AddressReputation::new(params);

        let ops_seen = 1000;
        let ops_included = ops_seen / params.min_inclusion_rate_denominator - params.ban_slack - 1;
        reputation.set_reputation(addr, ops_seen, ops_included);
        assert_eq!(reputation.status(addr), ReputationStatus::Banned);
    }

    #[test]
    fn hourly_update() {
        let addr = Address::random();
        let mut reputation = AddressReputation::new(ReputationParams::bundler_default());

        for _ in 0..1000 {
            reputation.add_seen(addr);
            reputation.add_included(addr);
        }

        reputation.hourly_update();
        let counts = reputation.counts.get(&addr).unwrap();
        assert_eq!(counts.ops_seen, 1000 - 1000 / 24);
        assert_eq!(counts.ops_included, 1000 - 1000 / 24);
    }

    #[test]
    fn test_blocklist() {
        let addr = Address::random();
        let reputation = AddressReputation::new(ReputationParams::bundler_default())
            .with_blocklist(HashSet::from([addr]));

        assert_eq!(reputation.status(addr), ReputationStatus::Banned);
        assert_eq!(reputation.status(Address::random()), ReputationStatus::Ok);
    }

    #[test]
    fn test_allowlist() {
        let addr = Address::random();
        let mut reputation = AddressReputation::new(ReputationParams::bundler_default())
            .with_allowlist(HashSet::from([addr]));
        reputation.set_reputation(addr, 1000000, 0);

        assert_eq!(reputation.status(addr), ReputationStatus::Ok);
    }

    // Test HourlyMovingAverageReputation

    #[test]
    fn manager_seen_included() {
        let manager =
            HourlyMovingAverageReputation::new(ReputationParams::bundler_default(), None, None);
        let addrs = [Address::random(), Address::random(), Address::random()];

        for _ in 0..10 {
            for addr in addrs {
                manager.add_seen(addr);
                manager.add_included(addr);
            }
        }

        for addr in &addrs {
            assert_eq!(manager.status(*addr), ReputationStatus::Ok);

            let rep = manager.reputation.read();
            let counts = rep.counts.get(addr).unwrap();
            assert_eq!(counts.ops_seen, 10);
            assert_eq!(counts.ops_included, 10);
        }
    }

    #[test]
    fn manager_set_dump_reputation() {
        let manager =
            HourlyMovingAverageReputation::new(ReputationParams::bundler_default(), None, None);
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
