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

//! E1: fixtures. Idempotent: every run calls [`ensure`], which deploys whatever is missing,
//! so experiments survive a devnet reset.

use alloy_network::TransactionBuilder;
use alloy_primitives::{Address, B256, Bytes, U256, address, keccak256, utils::parse_ether};
use alloy_provider::Provider;
use alloy_rpc_types_eth::TransactionRequest;
use alloy_sol_types::{SolCall, SolValue};
use serde::Serialize;

use crate::{
    contracts::{
        IStakeManagerLite, ProbeAccount, ProbeFactory, ProbePaymaster, Scratch,
        entry_point_v0_7_init_code,
    },
    harness::Harness,
};

/// Canonical EntryPoint v0.7 address.
pub const CANONICAL_ENTRY_POINT_V0_7: Address =
    address!("0000000071727De22E5E9d8BAf0edAc6f37da032");

/// Paymaster deposit is topped up to this amount whenever it falls below half of it.
const PAYMASTER_DEPOSIT_ETH: &str = "0.05";

#[derive(Debug, Clone, Serialize)]
pub struct Fixtures {
    pub entry_point: Address,
    /// True if the canonical EntryPoint was used, false if the harness deployed its own
    /// (gas-equivalent) build because the canonical address has no code on this chain.
    pub entry_point_canonical: bool,
    pub entry_point_code_size: usize,
    pub entry_point_code_hash: B256,
    pub factory: Address,
    pub paymaster: Address,
    pub paymaster_deposit: U256,
    pub scratch: Address,
}

impl Fixtures {
    /// Init code hash of `ProbeAccount` for this EntryPoint, as `ProbeFactory` deploys it.
    pub fn account_init_code_hash(&self) -> B256 {
        keccak256(with_args(&ProbeAccount::BYTECODE, self.entry_point))
    }

    /// Counterfactual address of the `ProbeAccount` with this salt.
    pub fn account_address(&self, salt: U256) -> Address {
        self.factory
            .create2(B256::from(salt), self.account_init_code_hash())
    }

    /// `factoryData` that deploys the account with this salt.
    pub fn factory_data(salt: U256) -> Bytes {
        ProbeFactory::createAccountCall { salt }.abi_encode().into()
    }
}

pub async fn ensure(harness: &Harness) -> anyhow::Result<Fixtures> {
    let canonical_code = harness
        .provider
        .get_code_at(CANONICAL_ENTRY_POINT_V0_7)
        .await?;
    let (entry_point, entry_point_canonical) = if canonical_code.is_empty() {
        let ep = harness
            .ensure_create2(B256::ZERO, &entry_point_v0_7_init_code())
            .await?;
        (ep, false)
    } else {
        (CANONICAL_ENTRY_POINT_V0_7, true)
    };
    let ep_code = harness.provider.get_code_at(entry_point).await?;

    let factory = harness
        .ensure_create2(B256::ZERO, &with_args(&ProbeFactory::BYTECODE, entry_point))
        .await?;
    let paymaster = ensure_paymaster(harness, entry_point, B256::ZERO).await?;
    let scratch = harness
        .ensure_create2(B256::ZERO, &Scratch::BYTECODE)
        .await?;

    let target = parse_ether(PAYMASTER_DEPOSIT_ETH)?;
    let mut paymaster_deposit = deposit_of(harness, entry_point, paymaster).await?;
    if paymaster_deposit < target / U256::from(2) {
        deposit_to(harness, entry_point, paymaster, target - paymaster_deposit).await?;
        paymaster_deposit = deposit_of(harness, entry_point, paymaster).await?;
    }

    Ok(Fixtures {
        entry_point,
        entry_point_canonical,
        entry_point_code_size: ep_code.len(),
        entry_point_code_hash: keccak256(&ep_code),
        factory,
        paymaster,
        paymaster_deposit,
        scratch,
    })
}

/// A `ProbePaymaster` for this EntryPoint at the given salt, without any deposit. Salt zero
/// is the fixture paymaster; other salts give independent paymasters whose deposit an
/// experiment controls exactly.
pub async fn ensure_paymaster(
    harness: &Harness,
    entry_point: Address,
    salt: B256,
) -> anyhow::Result<Address> {
    harness
        .ensure_create2(salt, &with_args(&ProbePaymaster::BYTECODE, entry_point))
        .await
}

/// Deposits `amount` for `account` in the EntryPoint.
pub async fn deposit_to(
    harness: &Harness,
    entry_point: Address,
    account: Address,
    amount: U256,
) -> anyhow::Result<()> {
    let outcome = harness
        .send(
            TransactionRequest::default()
                .with_to(entry_point)
                .with_value(amount)
                .with_input(IStakeManagerLite::depositToCall { account }.abi_encode()),
        )
        .await?;
    anyhow::ensure!(outcome.success, "depositTo reverted: {}", outcome.tx_hash);
    Ok(())
}

pub async fn deposit_of(
    harness: &Harness,
    entry_point: Address,
    account: Address,
) -> anyhow::Result<U256> {
    let ret = harness
        .provider
        .call(
            TransactionRequest::default()
                .with_to(entry_point)
                .with_input(IStakeManagerLite::balanceOfCall { account }.abi_encode()),
        )
        .await?;
    Ok(IStakeManagerLite::balanceOfCall::abi_decode_returns(&ret)?)
}

/// Creation code followed by the ABI-encoded constructor argument.
fn with_args(bytecode: &Bytes, arg: Address) -> Bytes {
    let mut code = bytecode.to_vec();
    code.extend_from_slice(&arg.abi_encode());
    code.into()
}
