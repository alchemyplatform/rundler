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

// from reth github: https://github.com/paradigmxyz/reth/blob/main/crates/transaction-pool/src/pool/size.rs
//! Tracks a size value.
use std::collections::HashMap;

use anyhow::Context;
use ethers::{abi::Address, types::U256};
use parking_lot::RwLock;
use rundler_provider::EntryPoint;
use rundler_types::{
    pool::{MempoolError, PaymasterMetadata, PoolOperation, StakeStatus},
    StakeInfo, UserOperation, UserOperationId, UserOperationVariant,
};
use rundler_utils::cache::LruMap;

use super::MempoolResult;
use crate::chain::MinedOp;

/// Keeps track of current and pending paymaster balances
#[derive(Debug)]
pub(crate) struct PaymasterTracker<E> {
    entry_point: E,
    state: RwLock<PaymasterTrackerInner>,
    config: PaymasterConfig,
}

#[derive(Debug)]
pub(crate) struct PaymasterConfig {
    min_stake_value: u128,
    min_unstake_delay: u32,
    tracker_enabled: bool,
    cache_length: u32,
}

impl PaymasterConfig {
    pub(crate) fn new(
        min_stake_value: u128,
        min_unstake_delay: u32,
        tracker_enabled: bool,
        cache_length: u32,
    ) -> Self {
        Self {
            min_stake_value,
            min_unstake_delay,
            tracker_enabled,
            cache_length,
        }
    }
}

impl<E> PaymasterTracker<E>
where
    E: EntryPoint,
{
    pub(crate) fn new(entry_point: E, config: PaymasterConfig) -> Self {
        Self {
            entry_point,
            state: RwLock::new(PaymasterTrackerInner::new(
                config.tracker_enabled,
                config.cache_length,
            )),
            config,
        }
    }

    pub(crate) async fn get_stake_status(&self, address: Address) -> MempoolResult<StakeStatus> {
        let deposit_info = self.entry_point.get_deposit_info(address).await?;

        let is_staked = deposit_info.stake.ge(&self.config.min_stake_value)
            && deposit_info
                .unstake_delay_sec
                .ge(&self.config.min_unstake_delay);

        let stake_status = StakeStatus {
            stake_info: StakeInfo {
                stake: deposit_info.stake.into(),
                unstake_delay_sec: deposit_info.unstake_delay_sec.into(),
            },
            is_staked,
        };

        Ok(stake_status)
    }

    pub(crate) async fn paymaster_balance(
        &self,
        paymaster: Address,
    ) -> MempoolResult<PaymasterMetadata> {
        if self.state.read().paymaster_exists(paymaster) {
            let meta = self
                .state
                .read()
                .paymaster_metadata(paymaster)
                .context("Paymaster balance should not be empty if address exists in pool")?;

            return Ok(meta);
        }

        let balance = self
            .entry_point
            .balance_of(paymaster, None)
            .await
            .context("Paymaster balance should not be empty if address exists in pool")?;

        let paymaster_meta = PaymasterMetadata {
            address: paymaster,
            pending_balance: balance,
            confirmed_balance: balance,
        };

        // Save paymaster balance after first lookup
        self.state
            .write()
            .add_new_paymaster(paymaster, balance, 0.into());

        Ok(paymaster_meta)
    }

    pub(crate) async fn check_operation_cost(
        &self,
        op: &UserOperationVariant,
    ) -> MempoolResult<()> {
        if let Some(paymaster) = op.paymaster() {
            let balance = self.paymaster_balance(paymaster).await?;
            self.state.read().check_operation_cost(op, &balance)?
        }

        Ok(())
    }

    pub(crate) fn clear(&self) {
        self.state.write().clear();
    }

    pub(crate) fn dump_paymaster_metadata(&self) -> Vec<PaymasterMetadata> {
        self.state.read().dump_paymaster_metadata()
    }

    pub(crate) fn set_tracking(&self, tracking_enabled: bool) {
        self.state.write().set_tracking(tracking_enabled);
    }

    pub(crate) async fn reset_confirmed_balances_for(
        &self,
        addresses: &[Address],
    ) -> MempoolResult<()> {
        let balances = self.entry_point.get_balances(addresses.to_vec()).await?;

        self.state
            .write()
            .set_confimed_balances(addresses, &balances);

        Ok(())
    }

    pub(crate) async fn reset_confirmed_balances(&self) -> MempoolResult<()> {
        let paymaster_addresses = self.paymaster_addresses();

        let balances = self
            .entry_point
            .get_balances(paymaster_addresses.clone())
            .await?;

        self.state
            .write()
            .set_confimed_balances(&paymaster_addresses, &balances);

        Ok(())
    }

    pub(crate) fn update_paymaster_balance_from_mined_op(&self, mined_op: &MinedOp) {
        self.state
            .write()
            .update_paymaster_balance_from_mined_op(mined_op);
    }

    pub(crate) fn remove_operation(&self, id: &UserOperationId) {
        self.state.write().remove_operation(id);
    }

    pub(crate) fn paymaster_addresses(&self) -> Vec<Address> {
        self.state.read().paymaster_addresses()
    }

    pub(crate) fn unmine_actual_cost(&self, paymaster: &Address, actual_cost: U256) {
        self.state
            .write()
            .unmine_actual_cost(paymaster, actual_cost);
    }

    pub(crate) async fn add_or_update_balance(&self, po: &PoolOperation) -> MempoolResult<()> {
        if let Some(paymaster) = po.uo.paymaster() {
            let paymaster_metadata = self.paymaster_balance(paymaster).await?;
            return self
                .state
                .write()
                .add_or_update_balance(po, &paymaster_metadata);
        }

        Ok(())
    }
}

// Keeps track of current and pending paymaster balances
#[derive(Debug)]
struct PaymasterTrackerInner {
    // map for userop based on id
    user_op_fees: HashMap<UserOperationId, UserOpFees>,
    // map for paymaster balance status
    paymaster_balances: LruMap<Address, PaymasterBalance>,
    // boolean for operation of tracker
    tracker_enabled: bool,
}

impl PaymasterTrackerInner {
    fn new(tracker_enabled: bool, cache_size: u32) -> Self {
        Self {
            user_op_fees: HashMap::new(),
            tracker_enabled,
            paymaster_balances: LruMap::new(cache_size),
        }
    }

    fn paymaster_exists(&self, paymaster: Address) -> bool {
        self.paymaster_balances.peek(&paymaster).is_some()
    }

    fn set_tracking(&mut self, tracking_enabled: bool) {
        self.tracker_enabled = tracking_enabled;
    }

    fn check_operation_cost(
        &self,
        op: &UserOperationVariant,
        paymaster_metadata: &PaymasterMetadata,
    ) -> MempoolResult<()> {
        let max_op_cost = op.max_gas_cost();

        if let Some(prev) = self.user_op_fees.get(&op.id()) {
            let reset_balance = paymaster_metadata
                .pending_balance
                .saturating_add(prev.max_op_cost);

            if reset_balance.lt(&max_op_cost) {
                return Err(MempoolError::PaymasterBalanceTooLow(
                    max_op_cost,
                    reset_balance,
                ));
            }
        } else if paymaster_metadata.pending_balance.lt(&max_op_cost) {
            return Err(MempoolError::PaymasterBalanceTooLow(
                max_op_cost,
                paymaster_metadata.pending_balance,
            ));
        }

        Ok(())
    }

    fn clear(&mut self) {
        self.user_op_fees.clear();
        self.paymaster_balances.clear();
    }

    fn set_confimed_balances(&mut self, addresses: &[Address], balances: &[U256]) {
        for (i, address) in addresses.iter().enumerate() {
            if let Some(paymaster_balance) = self.paymaster_balances.get(address) {
                paymaster_balance.confirmed = balances[i];
            }
        }
    }

    fn update_paymaster_balance_from_mined_op(&mut self, mined_op: &MinedOp) {
        let id = mined_op.id();

        if let Some(op_fee) = self.user_op_fees.get(&id) {
            if let Some(paymaster_balance) = self.paymaster_balances.get(&op_fee.paymaster) {
                paymaster_balance.confirmed = paymaster_balance
                    .confirmed
                    .saturating_sub(mined_op.actual_gas_cost);

                paymaster_balance.pending =
                    paymaster_balance.pending.saturating_sub(op_fee.max_op_cost);
            }

            self.user_op_fees.remove(&id);
        }
    }

    fn remove_operation(&mut self, id: &UserOperationId) {
        if let Some(op_fee) = self.user_op_fees.get(id) {
            if let Some(paymaster_balance) = self.paymaster_balances.get(&op_fee.paymaster) {
                paymaster_balance.pending =
                    paymaster_balance.pending.saturating_sub(op_fee.max_op_cost);
            }

            self.user_op_fees.remove(id);
        }
    }

    fn paymaster_addresses(&self) -> Vec<Address> {
        let keys: Vec<Address> = self.paymaster_balances.iter().map(|(k, _)| *k).collect();

        keys
    }

    fn paymaster_metadata(&self, paymaster: Address) -> Option<PaymasterMetadata> {
        if let Some(paymaster_balance) = self.paymaster_balances.peek(&paymaster) {
            return Some(PaymasterMetadata {
                pending_balance: paymaster_balance.pending_balance(),
                confirmed_balance: paymaster_balance.confirmed,
                address: paymaster,
            });
        }

        None
    }

    fn dump_paymaster_metadata(&self) -> Vec<PaymasterMetadata> {
        self.paymaster_balances
            .iter()
            .map(|(address, balance)| PaymasterMetadata {
                pending_balance: balance.pending_balance(),
                confirmed_balance: balance.confirmed,
                address: *address,
            })
            .collect()
    }

    fn unmine_actual_cost(&mut self, paymaster: &Address, actual_cost: U256) {
        if let Some(paymaster_balance) = self.paymaster_balances.get(paymaster) {
            paymaster_balance.confirmed = paymaster_balance.confirmed.saturating_add(actual_cost);
        }
    }

    fn add_or_update_balance(
        &mut self,
        po: &PoolOperation,
        paymaster_metadata: &PaymasterMetadata,
    ) -> MempoolResult<()> {
        let id = po.uo.id();
        let max_op_cost = po.uo.max_gas_cost();

        // Only return an error if tracking is enabled
        if paymaster_metadata.pending_balance.lt(&max_op_cost) && self.tracker_enabled {
            return Err(MempoolError::PaymasterBalanceTooLow(
                max_op_cost,
                paymaster_metadata.pending_balance,
            ));
        }

        if self.is_user_op_replacement(&id) {
            self.replace_existing_user_op(&id, paymaster_metadata, max_op_cost)?;
        } else {
            self.add_new_user_op(&id, paymaster_metadata, max_op_cost);
        }

        Ok(())
    }

    fn is_user_op_replacement(&self, id: &UserOperationId) -> bool {
        self.user_op_fees.contains_key(id)
    }

    fn decrement_previous_paymaster_balance(
        &mut self,
        paymaster: &Address,
        previous_max_op_cost: U256,
    ) {
        if let Some(pb) = self.paymaster_balances.get(paymaster) {
            pb.pending = pb.pending.saturating_sub(previous_max_op_cost);
        };
    }

    fn replace_existing_user_op(
        &mut self,
        id: &UserOperationId,
        paymaster_metadata: &PaymasterMetadata,
        max_op_cost: U256,
    ) -> MempoolResult<()> {
        let existing_user_op = self
            .user_op_fees
            .get_mut(id)
            .context("User op must exist to replace values ")?;

        let prev_max_op_cost = existing_user_op.max_op_cost;
        let prev_paymaster = existing_user_op.paymaster;

        *existing_user_op = UserOpFees::new(paymaster_metadata.address, max_op_cost);

        if let Some(paymaster_balance) = self.paymaster_balances.get(&paymaster_metadata.address) {
            // check to see if paymaster has changed
            if prev_paymaster.ne(&paymaster_metadata.address) {
                paymaster_balance.pending = paymaster_balance.pending.saturating_add(max_op_cost);

                //remove previous limit from data
                self.decrement_previous_paymaster_balance(&prev_paymaster, prev_max_op_cost);
            } else {
                paymaster_balance.pending = paymaster_balance
                    .pending
                    .saturating_sub(prev_max_op_cost)
                    .saturating_add(max_op_cost);
            }
        } else {
            // check to see if paymaster has changed
            if prev_paymaster.ne(&paymaster_metadata.address) {
                //remove previous limit from data
                self.decrement_previous_paymaster_balance(&prev_paymaster, prev_max_op_cost);
            }

            self.add_new_paymaster(
                paymaster_metadata.address,
                paymaster_metadata.confirmed_balance,
                max_op_cost,
            );
        }

        Ok(())
    }

    fn add_new_user_op(
        &mut self,
        id: &UserOperationId,
        paymaster_metadata: &PaymasterMetadata,
        max_op_cost: U256,
    ) {
        self.user_op_fees.insert(
            *id,
            UserOpFees::new(paymaster_metadata.address, max_op_cost),
        );

        if let Some(paymaster_balance) = self.paymaster_balances.get(&paymaster_metadata.address) {
            paymaster_balance.pending = paymaster_balance.pending.saturating_add(max_op_cost);
        } else {
            self.add_new_paymaster(
                paymaster_metadata.address,
                paymaster_metadata.confirmed_balance,
                max_op_cost,
            );
        }
    }

    fn add_new_paymaster(
        &mut self,
        address: Address,
        confirmed_balance: U256,
        inital_pending_balance: U256,
    ) {
        self.paymaster_balances.insert(
            address,
            PaymasterBalance::new(confirmed_balance, inital_pending_balance),
        );
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct UserOpFees {
    paymaster: Address,
    max_op_cost: U256,
}

impl UserOpFees {
    fn new(paymaster: Address, max_op_cost: U256) -> Self {
        Self {
            paymaster,
            max_op_cost,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct PaymasterBalance {
    pending: U256,
    confirmed: U256,
}

impl PaymasterBalance {
    fn new(confirmed: U256, pending: U256) -> Self {
        Self { confirmed, pending }
    }

    pub(crate) fn pending_balance(&self) -> U256 {
        self.confirmed.saturating_sub(self.pending)
    }
}

#[cfg(test)]
mod tests {
    use ethers::types::{Address, H256, U256};
    use rundler_provider::{DepositInfo, MockEntryPointV0_6};
    use rundler_types::{
        pool::{PaymasterMetadata, PoolOperation},
        v0_6::UserOperation,
        EntityInfos, UserOperation as UserOperationTrait, UserOperationId, ValidTimeRange,
    };

    use super::*;
    use crate::mempool::paymaster::PaymasterTracker;

    fn demo_pool_op(uo: UserOperation) -> PoolOperation {
        PoolOperation {
            uo: uo.into(),
            entry_point: Address::random(),
            aggregator: None,
            valid_time_range: ValidTimeRange::all_time(),
            expected_code_hash: H256::random(),
            sim_block_hash: H256::random(),
            account_is_staked: true,
            entity_infos: EntityInfos::default(),
            sim_block_number: 0,
        }
    }

    #[tokio::test]
    async fn new_uo_unused_paymaster() {
        let paymaster_tracker = new_paymaster_tracker();

        let paymaster = Address::random();
        let sender = Address::random();
        let uo = UserOperation {
            sender,
            call_gas_limit: 10.into(),
            pre_verification_gas: 10.into(),
            paymaster_and_data: paymaster.as_bytes().to_vec().into(),
            verification_gas_limit: 10.into(),
            max_fee_per_gas: 1.into(),
            ..Default::default()
        };

        let uo_max_cost = uo.clone().max_gas_cost();

        let po = demo_pool_op(uo);

        let res = paymaster_tracker.add_or_update_balance(&po).await;
        assert!(res.is_ok());
        let balance = paymaster_tracker
            .paymaster_balance(paymaster)
            .await
            .unwrap();

        assert_eq!(balance.confirmed_balance, 1000.into(),);

        assert_eq!(
            balance.pending_balance,
            balance.confirmed_balance.saturating_sub(uo_max_cost),
        );
    }

    #[tokio::test]
    async fn new_uo_not_enough_balance() {
        let paymaster_tracker = new_paymaster_tracker();

        let paymaster = Address::random();
        let sender = Address::random();
        let paymaster_balance = U256::from(5);
        let confirmed_balance = U256::from(5);

        paymaster_tracker.add_new_paymaster(paymaster, confirmed_balance, paymaster_balance);

        let uo = UserOperation {
            sender,
            call_gas_limit: 10.into(),
            paymaster_and_data: paymaster.as_bytes().to_vec().into(),
            pre_verification_gas: 10.into(),
            verification_gas_limit: 10.into(),
            max_fee_per_gas: 1.into(),
            ..Default::default()
        };

        let po = demo_pool_op(uo);

        let res = paymaster_tracker.add_or_update_balance(&po).await;

        assert!(res.is_err());
    }

    #[tokio::test]
    async fn new_uo_not_enough_balance_tracking_disabled() {
        let paymaster_tracker = new_paymaster_tracker();
        paymaster_tracker.set_tracking(false);

        let paymaster = Address::random();
        let sender = Address::random();
        let pending_op_cost = U256::from(5);
        let confirmed_balance = U256::from(5);
        let uo = UserOperation {
            sender,
            call_gas_limit: 10.into(),
            pre_verification_gas: 10.into(),
            verification_gas_limit: 10.into(),
            max_fee_per_gas: 1.into(),
            ..Default::default()
        };

        let po = demo_pool_op(uo);

        paymaster_tracker.add_new_paymaster(paymaster, confirmed_balance, pending_op_cost);

        let res = paymaster_tracker.add_or_update_balance(&po).await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn new_uo_not_enough_balance_existing_paymaster() {
        let paymaster_tracker = new_paymaster_tracker();

        let paymaster = Address::random();
        let sender = Address::random();
        let paymaster_balance = U256::from(100);
        let pending_paymaster_balance = U256::from(10);

        paymaster_tracker.add_new_paymaster(
            paymaster,
            paymaster_balance,
            pending_paymaster_balance,
        );

        let uo = UserOperation {
            sender,
            call_gas_limit: 100.into(),
            paymaster_and_data: paymaster.as_bytes().to_vec().into(),
            pre_verification_gas: 100.into(),
            verification_gas_limit: 100.into(),
            max_fee_per_gas: 1.into(),
            ..Default::default()
        };

        let po = demo_pool_op(uo);

        let res = paymaster_tracker.add_or_update_balance(&po).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_reset_balances() {
        let paymaster_tracker = new_paymaster_tracker();

        let paymaster_0 = Address::random();
        let paymaster_0_confimed = 1000.into();

        paymaster_tracker.add_new_paymaster(paymaster_0, paymaster_0_confimed, 0.into());

        let balance_0 = paymaster_tracker
            .paymaster_balance(paymaster_0)
            .await
            .unwrap();

        assert_eq!(balance_0.confirmed_balance, 1000.into());

        let _ = paymaster_tracker.reset_confirmed_balances().await;

        let balance_0 = paymaster_tracker
            .paymaster_balance(paymaster_0)
            .await
            .unwrap();

        assert_eq!(balance_0.confirmed_balance, 50.into());
    }

    #[tokio::test]
    async fn test_reset_balances_for() {
        let paymaster_tracker = new_paymaster_tracker();

        let paymaster_0 = Address::random();
        let paymaster_0_confimed = 1000.into();

        paymaster_tracker.add_new_paymaster(paymaster_0, paymaster_0_confimed, 0.into());

        let balance_0 = paymaster_tracker
            .paymaster_balance(paymaster_0)
            .await
            .unwrap();

        assert_eq!(balance_0.confirmed_balance, 1000.into());

        let _ = paymaster_tracker
            .reset_confirmed_balances_for(&[paymaster_0])
            .await;

        let balance_0 = paymaster_tracker
            .paymaster_balance(paymaster_0)
            .await
            .unwrap();

        assert_eq!(balance_0.confirmed_balance, 50.into());
    }

    #[tokio::test]
    async fn new_uo_existing_paymaster_valid_balance() {
        let paymaster_tracker = new_paymaster_tracker();
        let paymaster = Address::random();
        let paymaster_balance = U256::from(100000000);
        let pending_paymaster_balance = U256::from(10);

        paymaster_tracker.add_new_paymaster(
            paymaster,
            paymaster_balance,
            pending_paymaster_balance,
        );

        let sender = Address::random();
        let uo = UserOperation {
            sender,
            call_gas_limit: 10.into(),
            pre_verification_gas: 10.into(),
            verification_gas_limit: 10.into(),
            paymaster_and_data: paymaster.as_bytes().to_vec().into(),
            max_fee_per_gas: 1.into(),
            ..Default::default()
        };

        let uo_max_cost = uo.clone().max_gas_cost();

        let po = demo_pool_op(uo);
        let res = paymaster_tracker.add_or_update_balance(&po).await;

        assert!(res.is_ok());

        let remaining = paymaster_tracker
            .paymaster_balance(paymaster)
            .await
            .unwrap();

        assert_eq!(remaining.confirmed_balance, paymaster_balance);
        assert_eq!(
            remaining.pending_balance,
            paymaster_balance
                .saturating_sub(pending_paymaster_balance)
                .saturating_sub(uo_max_cost),
        );
    }

    #[tokio::test]
    async fn replacement_uo_new_paymaster() {
        let paymaster_tracker = new_paymaster_tracker();
        let paymaster_0 = Address::random();
        let paymaster_1 = Address::random();

        let paymaster_balance_0 = U256::from(100000000);
        let paymaster_balance_1 = U256::from(200000000);

        let sender = Address::random();
        let uo = UserOperation {
            sender,
            call_gas_limit: 10.into(),
            pre_verification_gas: 10.into(),
            paymaster_and_data: paymaster_0.as_bytes().to_vec().into(),
            verification_gas_limit: 10.into(),
            max_fee_per_gas: 1.into(),
            ..Default::default()
        };

        let mut uo_1 = uo.clone();
        uo_1.max_fee_per_gas = 2.into();
        uo_1.paymaster_and_data = paymaster_1.as_bytes().to_vec().into();

        let max_op_cost_0 = uo.max_gas_cost();
        let max_op_cost_1 = uo_1.max_gas_cost();

        paymaster_tracker.add_new_paymaster(paymaster_0, paymaster_balance_0, 0.into());
        paymaster_tracker.add_new_paymaster(paymaster_1, paymaster_balance_1, 0.into());

        let po_0 = demo_pool_op(uo);

        // Update first paymaster balance with first uo
        paymaster_tracker
            .add_or_update_balance(&po_0)
            .await
            .unwrap();

        assert_eq!(
            paymaster_tracker
                .paymaster_balance(paymaster_0)
                .await
                .unwrap(),
            PaymasterMetadata {
                address: paymaster_0,
                confirmed_balance: paymaster_balance_0,
                pending_balance: paymaster_balance_0.saturating_sub(max_op_cost_0),
            }
        );

        let po_1 = demo_pool_op(uo_1);
        // send same uo with updated fees and new paymaster
        paymaster_tracker
            .add_or_update_balance(&po_1)
            .await
            .unwrap();

        // check previous paymaster goes back to normal balance
        assert_eq!(
            paymaster_tracker
                .paymaster_balance(paymaster_0)
                .await
                .unwrap(),
            PaymasterMetadata {
                address: paymaster_0,
                confirmed_balance: paymaster_balance_0,
                pending_balance: paymaster_balance_0,
            }
        );

        // check that new paymaster has been updated correctly
        assert_eq!(
            paymaster_tracker
                .paymaster_balance(paymaster_1)
                .await
                .unwrap(),
            PaymasterMetadata {
                address: paymaster_1,
                confirmed_balance: paymaster_balance_1,
                pending_balance: paymaster_balance_1.saturating_sub(max_op_cost_1),
            }
        );
    }

    #[tokio::test]
    async fn replacement_uo_same_paymaster() {
        let paymaster_tracker = new_paymaster_tracker();
        let sender = Address::random();
        let paymaster = Address::random();
        let paymaster_balance = U256::from(100000000);
        let pending_paymaster_balance = U256::from(30);
        let nonce = U256::from(1);

        let existing_id = UserOperationId { sender, nonce };

        // add paymaster
        paymaster_tracker.add_new_paymaster(
            paymaster,
            paymaster_balance,
            pending_paymaster_balance,
        );

        let meta = paymaster_tracker
            .paymaster_balance(paymaster)
            .await
            .unwrap();

        paymaster_tracker.add_new_user_op(&existing_id, &meta, 30.into());

        // replacement_uo
        let uo = UserOperation {
            sender,
            nonce,
            call_gas_limit: 100.into(),
            pre_verification_gas: 100.into(),
            verification_gas_limit: 100.into(),
            paymaster_and_data: paymaster.as_bytes().to_vec().into(),
            max_fee_per_gas: 1.into(),
            ..Default::default()
        };

        let max_op_cost = uo.clone().max_gas_cost();

        let po = demo_pool_op(uo);

        let res = paymaster_tracker.add_or_update_balance(&po).await;
        assert!(res.is_ok());
        assert_eq!(
            paymaster_tracker
                .paymaster_balance(paymaster)
                .await
                .unwrap()
                .confirmed_balance,
            paymaster_balance,
        );
        assert_eq!(
            paymaster_tracker
                .paymaster_balance(paymaster)
                .await
                .unwrap()
                .pending_balance,
            paymaster_balance
                .saturating_sub(pending_paymaster_balance)
                .saturating_sub(max_op_cost),
        );
    }

    #[tokio::test]
    async fn test_stake_status_staked() {
        let tracker = new_paymaster_tracker();

        let status = tracker.get_stake_status(Address::random()).await.unwrap();

        assert!(status.is_staked);
    }

    #[test]
    fn test_inner_cache_full() {
        let mut inner = PaymasterTrackerInner::new(true, 2);

        let paymaster_0 = Address::random();
        let paymaster_1 = Address::random();
        let paymaster_2 = Address::random();

        let confirmed_balance = U256::from(1000);
        let pending_balance = U256::from(100);

        inner.add_new_paymaster(paymaster_0, confirmed_balance, pending_balance);
        inner.add_new_paymaster(paymaster_1, confirmed_balance, pending_balance);
        inner.add_new_paymaster(paymaster_2, confirmed_balance, pending_balance);

        assert_eq!(inner.paymaster_balances.len(), 2);
        assert!(!inner.paymaster_exists(paymaster_0));
        assert!(inner.paymaster_exists(paymaster_1));
        assert!(inner.paymaster_exists(paymaster_2));
    }

    fn new_paymaster_tracker() -> PaymasterTracker<MockEntryPointV0_6> {
        let mut entrypoint = MockEntryPointV0_6::new();

        entrypoint.expect_get_deposit_info().returning(|_| {
            Ok(DepositInfo {
                deposit: 1000.into(),
                staked: true,
                stake: 10000,
                unstake_delay_sec: 100,
                withdraw_time: 10,
            })
        });

        entrypoint
            .expect_get_balances()
            .returning(|_| Ok(vec![50.into()]));

        entrypoint
            .expect_balance_of()
            .returning(|_, _| Ok(U256::from(1000)));

        let config = PaymasterConfig::new(1001, 99, true, u32::MAX);

        PaymasterTracker::new(entrypoint, config)
    }

    impl PaymasterTracker<MockEntryPointV0_6> {
        fn add_new_user_op(
            &self,
            id: &UserOperationId,
            paymaster_metadata: &PaymasterMetadata,
            max_op_cost: U256,
        ) {
            self.state
                .write()
                .add_new_user_op(id, paymaster_metadata, max_op_cost)
        }

        fn add_new_paymaster(
            &self,
            address: Address,
            confirmed_balance: U256,
            inital_pending_balance: U256,
        ) {
            self.state.write().add_new_paymaster(
                address,
                confirmed_balance,
                inital_pending_balance,
            );
        }
    }
}
