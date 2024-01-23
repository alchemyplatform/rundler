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
use rundler_types::UserOperationId;

use super::{error::MempoolResult, PaymasterMetadata};
use crate::{chain::MinedOp, MempoolError, PoolOperation};

/// Keeps track of current and pending paymaster balances
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct PaymasterTracker {
    /// map for userop based on id
    user_op_fees: HashMap<UserOperationId, UserOpFees>,
    /// map for paymaster balance status
    paymaster_balances: HashMap<Address, PaymasterBalance>,
}

impl PaymasterTracker {
    pub(crate) fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    pub(crate) fn paymaster_exists(&self, paymaster: Address) -> bool {
        self.paymaster_balances.contains_key(&paymaster)
    }

    pub(crate) fn clear(&mut self) {
        self.user_op_fees.clear();
        self.paymaster_balances.clear();
    }

    pub(crate) fn set_confimed_balances(&mut self, addresses: &[Address], balances: &[U256]) {
        for (i, address) in addresses.iter().enumerate() {
            if let Some(paymaster_balance) = self.paymaster_balances.get_mut(address) {
                paymaster_balance.confirmed = balances[i];
            }
        }
    }

    //TODO track if paymaster has become stale and can be removed from the pool
    pub(crate) fn update_paymaster_balance_from_mined_op(&mut self, mined_op: &MinedOp) {
        let id = mined_op.id();

        if let Some(op_fee) = self.user_op_fees.get(&id) {
            if let Some(paymaster_balance) = self.paymaster_balances.get_mut(&op_fee.paymaster) {
                paymaster_balance.confirmed = paymaster_balance
                    .confirmed
                    .saturating_sub(mined_op.actual_gas_cost);

                paymaster_balance.pending =
                    paymaster_balance.pending.saturating_sub(op_fee.max_op_cost);
            }

            self.user_op_fees.remove(&id);
        }
    }

    pub(crate) fn remove_operation(&mut self, id: &UserOperationId) {
        if let Some(op_fee) = self.user_op_fees.get(id) {
            if let Some(paymaster_balance) = self.paymaster_balances.get_mut(&op_fee.paymaster) {
                paymaster_balance.pending =
                    paymaster_balance.pending.saturating_sub(op_fee.max_op_cost);
            }

            self.user_op_fees.remove(id);
        }
    }

    pub(crate) fn paymaster_addresses(&self) -> Vec<Address> {
        let keys: Vec<Address> = self.paymaster_balances.keys().cloned().collect();

        keys
    }

    pub(crate) fn update_paymaster_balance_after_deposit_reorg(
        &mut self,
        paymaster: Address,
        deposit_amount: U256,
    ) {
        if let Some(paymaster_balance) = self.paymaster_balances.get_mut(&paymaster) {
            paymaster_balance.confirmed =
                paymaster_balance.confirmed.saturating_sub(deposit_amount);
        }
    }

    pub(crate) fn update_paymaster_balance_from_deposit(
        &mut self,
        paymaster: Address,
        deposit_amount: U256,
    ) {
        if let Some(paymaster_balance) = self.paymaster_balances.get_mut(&paymaster) {
            paymaster_balance.confirmed =
                paymaster_balance.confirmed.saturating_add(deposit_amount);
        }
    }

    pub(crate) fn paymaster_metadata(&self, paymaster: Address) -> Option<PaymasterMetadata> {
        if let Some(paymaster_balance) = self.paymaster_balances.get(&paymaster) {
            return Some(PaymasterMetadata {
                pending_balance: paymaster_balance.pending_balance(),
                confirmed_balance: paymaster_balance.confirmed,
                address: paymaster,
            });
        }

        None
    }

    pub(crate) fn unmine_actual_cost(&mut self, paymaster: &Address, actual_cost: U256) {
        if let Some(paymaster_balance) = self.paymaster_balances.get_mut(paymaster) {
            paymaster_balance.confirmed = paymaster_balance.confirmed.saturating_add(actual_cost);
        }
    }

    pub(crate) fn add_or_update_balance(
        &mut self,
        po: &PoolOperation,
        paymaster_metadata: &PaymasterMetadata,
    ) -> MempoolResult<()> {
        let id = po.uo.id();
        let max_op_cost = po.uo.max_op_cost();

        if self.paymaster_exists(paymaster_metadata.address) {
            return self.update_paymaster_balance(&id, paymaster_metadata.address, max_op_cost);
        }

        self.add_paymaster_balance(&id, paymaster_metadata, max_op_cost)
    }

    fn add_paymaster_balance(
        &mut self,
        id: &UserOperationId,
        paymaster_metadata: &PaymasterMetadata,
        max_op_cost: U256,
    ) -> MempoolResult<()> {
        if paymaster_metadata.pending_balance.lt(&max_op_cost) {
            return Err(MempoolError::PaymasterBalanceTooLow(
                max_op_cost,
                paymaster_metadata.pending_balance,
            ));
        }

        self.paymaster_balances.insert(
            paymaster_metadata.address,
            PaymasterBalance::new(paymaster_metadata.pending_balance, max_op_cost),
        );

        self.user_op_fees.insert(
            *id,
            UserOpFees::new(paymaster_metadata.address, max_op_cost),
        );

        Ok(())
    }

    fn update_paymaster_balance(
        &mut self,
        id: &UserOperationId,
        paymaster: Address,
        max_op_cost: U256,
    ) -> MempoolResult<()> {
        let paymaster_balance = self
            .paymaster_balances
            .get_mut(&paymaster)
            .context("Paymaster must be valid to update")?;

        // check there is enough balance
        if !paymaster_balance.validate_user_op_cost(max_op_cost) {
            return Err(MempoolError::PaymasterBalanceTooLow(
                max_op_cost,
                paymaster_balance.pending_balance(),
            ));
        }

        // if user op already exists and is being replaced
        if let Some(replacement) = self.user_op_fees.get_mut(id) {
            let prev_limit = replacement.max_op_cost;
            let prev_paymaster = replacement.paymaster;

            *replacement = UserOpFees::new(paymaster, max_op_cost);
            // check to see if paymaster has changed
            if prev_paymaster.ne(&paymaster) {
                paymaster_balance.pending = paymaster_balance.pending.saturating_add(max_op_cost);

                //remove previous limit from data
                let prev_paymaster_balance = self
                    .paymaster_balances
                    .get_mut(&prev_paymaster)
                    .context("Previous paymaster must be valid to update")?;

                prev_paymaster_balance.pending.saturating_sub(prev_limit);
            } else {
                paymaster_balance.pending = paymaster_balance
                    .pending
                    .saturating_sub(prev_limit)
                    .saturating_add(max_op_cost);
            }
        } else {
            // add new user op
            self.user_op_fees
                .insert(*id, UserOpFees::new(paymaster, max_op_cost));

            paymaster_balance.pending = paymaster_balance.pending.saturating_add(max_op_cost);
        }

        Ok(())
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

    /// check that new user op cost is within an acceptable range
    fn validate_user_op_cost(&self, max_op_cost: U256) -> bool {
        let temp_pending = self.pending.saturating_add(max_op_cost);
        self.confirmed
            .saturating_sub(temp_pending)
            .gt(&U256::zero())
    }
}

#[cfg(test)]
mod tests {
    use ethers::types::{Address, H256, U256};
    use rundler_sim::EntityInfos;
    use rundler_types::{UserOperation, UserOperationId, ValidTimeRange};

    use crate::{
        mempool::{
            paymaster::{PaymasterBalance, PaymasterTracker, UserOpFees},
            PaymasterMetadata,
        },
        PoolOperation,
    };

    fn demo_pool_op(uo: UserOperation) -> PoolOperation {
        PoolOperation {
            uo,
            entry_point: Address::random(),
            aggregator: None,
            valid_time_range: ValidTimeRange::all_time(),
            expected_code_hash: H256::random(),
            sim_block_hash: H256::random(),
            entities_needing_stake: vec![],
            account_is_staked: true,
            entity_infos: EntityInfos::default(),
            sim_block_number: 0,
        }
    }

    #[test]
    fn new_uo_unused_paymaster() {
        let mut paymaster_tracker = PaymasterTracker::new();

        let paymaster = Address::random();
        let sender = Address::random();
        let paymaster_balance = U256::from(100000000);
        let confirmed_balance = U256::from(100000000);
        let uo = UserOperation {
            sender,
            call_gas_limit: 10.into(),
            pre_verification_gas: 10.into(),
            verification_gas_limit: 10.into(),
            max_fee_per_gas: 1.into(),
            ..Default::default()
        };

        let uo_max_cost = uo.clone().max_op_cost();
        let paymaster_meta = PaymasterMetadata {
            address: paymaster,
            pending_balance: paymaster_balance,
            confirmed_balance,
        };

        let po = demo_pool_op(uo);

        let res = paymaster_tracker.add_or_update_balance(&po, &paymaster_meta);
        assert!(res.is_ok());
        assert_eq!(
            paymaster_tracker
                .paymaster_balances
                .get(&paymaster)
                .unwrap()
                .confirmed,
            paymaster_balance,
        );
        assert_eq!(
            paymaster_tracker
                .paymaster_balances
                .get(&paymaster)
                .unwrap()
                .pending,
            uo_max_cost,
        );
    }

    #[test]
    fn new_uo_not_enough_balance() {
        let mut paymaster_tracker = PaymasterTracker::new();

        let paymaster = Address::random();
        let sender = Address::random();
        let paymaster_balance = U256::from(5);
        let confirmed_balance = U256::from(5);
        let uo = UserOperation {
            sender,
            call_gas_limit: 10.into(),
            pre_verification_gas: 10.into(),
            verification_gas_limit: 10.into(),
            max_fee_per_gas: 1.into(),
            ..Default::default()
        };

        let paymaster_meta = PaymasterMetadata {
            address: paymaster,
            pending_balance: paymaster_balance,
            confirmed_balance,
        };

        let po = demo_pool_op(uo);

        let res = paymaster_tracker.add_or_update_balance(&po, &paymaster_meta);
        assert!(res.is_err());
    }

    #[test]
    fn new_uo_not_enough_balance_existing_paymaster() {
        let mut paymaster_tracker = PaymasterTracker::new();

        let paymaster = Address::random();
        let sender = Address::random();
        let paymaster_balance = U256::from(100);
        let pending_paymaster_balance = U256::from(10);

        paymaster_tracker.paymaster_balances.insert(
            paymaster,
            PaymasterBalance {
                pending: pending_paymaster_balance,
                confirmed: paymaster_balance,
            },
        );

        let uo = UserOperation {
            sender,
            call_gas_limit: 100.into(),
            pre_verification_gas: 100.into(),
            verification_gas_limit: 100.into(),
            max_fee_per_gas: 1.into(),
            ..Default::default()
        };

        let paymaster_meta = PaymasterMetadata {
            address: paymaster,
            pending_balance: paymaster_balance,
            confirmed_balance: paymaster_balance,
        };

        let po = demo_pool_op(uo);

        let res = paymaster_tracker.add_or_update_balance(&po, &paymaster_meta);
        assert!(res.is_err());
    }

    #[test]
    fn new_uo_existing_paymaster_valid_balance() {
        let mut paymaster_tracker = PaymasterTracker::new();
        let paymaster = Address::random();
        let paymaster_balance = U256::from(100000000);
        let pending_paymaster_balance = U256::from(10);

        paymaster_tracker.paymaster_balances.insert(
            paymaster,
            PaymasterBalance {
                pending: pending_paymaster_balance,
                confirmed: paymaster_balance,
            },
        );

        let sender = Address::random();
        let uo = UserOperation {
            sender,
            call_gas_limit: 10.into(),
            pre_verification_gas: 10.into(),
            verification_gas_limit: 10.into(),
            max_fee_per_gas: 1.into(),
            ..Default::default()
        };

        let uo_max_cost = uo.clone().max_op_cost();

        let paymaster_meta = PaymasterMetadata {
            address: paymaster,
            pending_balance: paymaster_balance,
            confirmed_balance: paymaster_balance,
        };

        let po = demo_pool_op(uo);
        let res = paymaster_tracker.add_or_update_balance(&po, &paymaster_meta);

        assert!(res.is_ok());
        assert_eq!(
            paymaster_tracker
                .paymaster_balances
                .get(&paymaster)
                .unwrap()
                .confirmed,
            paymaster_balance,
        );
        assert_eq!(
            paymaster_tracker
                .paymaster_balances
                .get(&paymaster)
                .unwrap()
                .pending,
            pending_paymaster_balance.saturating_add(uo_max_cost),
        );
        assert_eq!(
            paymaster_tracker
                .paymaster_balances
                .get(&paymaster)
                .unwrap()
                .pending_balance(),
            paymaster_balance.saturating_sub(uo_max_cost.saturating_add(pending_paymaster_balance)),
        );
    }

    #[test]
    fn replacement_uo_same_paymaster() {
        let mut paymaster_tracker = PaymasterTracker::new();
        let sender = Address::random();
        let paymaster = Address::random();
        let paymaster_balance = U256::from(100000000);
        let pending_paymaster_balance = U256::from(30);
        let nonce = U256::from(1);

        let existing_id = UserOperationId { sender, nonce };

        paymaster_tracker.paymaster_balances.insert(
            paymaster,
            PaymasterBalance {
                pending: pending_paymaster_balance,
                confirmed: paymaster_balance,
            },
        );

        // existing fee
        paymaster_tracker.user_op_fees.insert(
            existing_id,
            UserOpFees {
                paymaster,
                max_op_cost: 30.into(),
            },
        );

        // replacement_uo
        let uo = UserOperation {
            sender,
            nonce,
            call_gas_limit: 100.into(),
            pre_verification_gas: 100.into(),
            verification_gas_limit: 100.into(),
            max_fee_per_gas: 1.into(),
            ..Default::default()
        };

        let paymaster_meta = PaymasterMetadata {
            address: paymaster,
            pending_balance: paymaster_balance,
            confirmed_balance: paymaster_balance,
        };

        let max_op_cost = uo.clone().max_op_cost();

        let po = demo_pool_op(uo);

        let res = paymaster_tracker.add_or_update_balance(&po, &paymaster_meta);
        assert!(res.is_ok());
        assert_eq!(
            paymaster_tracker
                .paymaster_balances
                .get(&paymaster)
                .unwrap()
                .confirmed,
            paymaster_balance,
        );
        assert_eq!(
            paymaster_tracker
                .paymaster_balances
                .get(&paymaster)
                .unwrap()
                .pending,
            max_op_cost,
        );
        assert_eq!(
            paymaster_tracker
                .paymaster_balances
                .get(&paymaster)
                .unwrap()
                .pending_balance(),
            paymaster_balance.saturating_sub(max_op_cost),
        );
    }
}
