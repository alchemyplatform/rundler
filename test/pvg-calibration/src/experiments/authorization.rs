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

//! E4: EIP-7702 authorizations (EntryPoint v0.7).
//!
//! An op whose sender is an EOA delegating to a `ProbeAccount` carries its authorization in
//! the bundle transaction's authorization list. The authorization is charged as intrinsic gas,
//! so it is unmetered and PVG has to cover it. Rundler adds a flat `PER_EMPTY_ACCOUNT_COST`
//! (`authorization_gas_limit`) for any op with an authorization.
//!
//! Each case is measured against a baseline bundle of the same size whose senders are
//! already delegated and carry no authorization. The difference is the unmetered cost of the
//! authorizations alone. The cases vary what the authority looks like: empty (the account
//! does not exist), non-empty but undelegated, already delegated to the same delegate, or
//! to a different one. This is what the "account exists" refund depends on.

use alloy_eips::eip7702::{Authorization, SignedAuthorization};
use alloy_network::{TransactionBuilder, TransactionBuilder7702};
use alloy_primitives::{Address, U256};
use alloy_provider::Provider;
use alloy_rpc_types_eth::TransactionRequest;
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use anyhow::ensure;
use serde::Serialize;

use crate::{
    bundle::{BeneficiaryKind, BundleRun, BundleRunner, OpSpec, Payer},
    fixtures::Fixtures,
};

/// ProbeFactory salts of the two delegate implementations.
const DELEGATE_SALTS: [u64; 2] = [1, 2];

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum Authority {
    /// New key, never used: nonce 0, no balance, no code. The account does not exist.
    Empty,
    /// New key with a balance but no code: exists, not delegated.
    Funded,
    /// Already delegated to the same delegate the authorization names.
    RedelegateSame,
    /// Already delegated to the other delegate.
    RedelegateOther,
}

#[derive(Debug, Serialize)]
struct CaseResult {
    name: String,
    authority: Authority,
    authorizations: usize,
    /// Unmetered gas minus the same-size baseline without authorizations.
    extra_unmetered_gas: i128,
    extra_per_authorization: f64,
    /// What rundler adds per authorization (`authorization_gas_limit`).
    predicted_per_authorization: u128,
    /// `predicted_per_authorization - extra_per_authorization`. Negative: undercharged.
    per_authorization_error: f64,
    run: BundleRun,
}

#[derive(Debug, Serialize)]
pub struct Report {
    experiment: &'static str,
    fixtures: Fixtures,
    delegates: [Address; 2],
    baselines: Vec<BundleRun>,
    cases: Vec<CaseResult>,
}

struct Authorizer<'a> {
    runner: &'a BundleRunner<'a>,
    chain_id: u64,
}

impl Authorizer<'_> {
    fn sign(
        &self,
        signer: &PrivateKeySigner,
        delegate: Address,
        nonce: u64,
    ) -> anyhow::Result<SignedAuthorization> {
        let auth = Authorization {
            chain_id: U256::from(self.chain_id),
            address: delegate,
            nonce,
        };
        let signature = signer.sign_hash_sync(&auth.signature_hash())?;
        Ok(auth.into_signed(signature))
    }

    /// A new EOA delegated to `delegate` by a plain type-4 transaction from the harness.
    async fn delegated_eoa(&self, delegate: Address) -> anyhow::Result<PrivateKeySigner> {
        let signer = PrivateKeySigner::random();
        let auth = self.sign(&signer, delegate, 0)?;
        let outcome = self
            .runner
            .harness
            .send(
                TransactionRequest::default()
                    .with_to(signer.address())
                    .with_authorization_list(vec![auth]),
            )
            .await?;
        ensure!(
            outcome.success,
            "delegation tx reverted: {}",
            outcome.tx_hash
        );
        let code = self
            .runner
            .harness
            .provider
            .get_code_at(signer.address())
            .await?;
        ensure!(
            code.len() == 23 && code[..3] == [0xef, 0x01, 0x00] && code[3..] == delegate[..],
            "{} is not delegated to {delegate}",
            signer.address()
        );
        Ok(signer)
    }

    async fn authority_nonce(&self, address: Address) -> anyhow::Result<u64> {
        Ok(self
            .runner
            .harness
            .provider
            .get_transaction_count(address)
            .await?)
    }

    /// An op from a new authority of the given kind, with its authorization attached.
    async fn op(&self, authority: Authority, delegates: [Address; 2]) -> anyhow::Result<OpSpec> {
        let (signer, target) = match authority {
            Authority::Empty => (PrivateKeySigner::random(), delegates[0]),
            Authority::Funded => {
                let signer = PrivateKeySigner::random();
                let outcome = self
                    .runner
                    .harness
                    .send(
                        TransactionRequest::default()
                            .with_to(signer.address())
                            .with_value(U256::from(1)),
                    )
                    .await?;
                ensure!(outcome.success, "funding tx reverted");
                (signer, delegates[0])
            }
            Authority::RedelegateSame => (self.delegated_eoa(delegates[0]).await?, delegates[0]),
            Authority::RedelegateOther => (self.delegated_eoa(delegates[0]).await?, delegates[1]),
        };
        let nonce = self.authority_nonce(signer.address()).await?;
        let mut spec = OpSpec::typical(Payer::Paymaster, false).with_sender(signer.address(), 0);
        spec.authorization = Some(self.sign(&signer, target, nonce)?);
        Ok(spec)
    }
}

pub async fn run(runner: &BundleRunner<'_>, chain_id: u64) -> anyhow::Result<Report> {
    let fixtures = runner.fixtures;
    let salts: Vec<U256> = DELEGATE_SALTS.iter().map(|s| U256::from(*s)).collect();
    runner
        .setup_probes(salts.clone(), true, U256::ZERO, U256::ZERO)
        .await?;
    let delegates = [
        fixtures.account_address(salts[0]),
        fixtures.account_address(salts[1]),
    ];
    let authorizer = Authorizer { runner, chain_id };

    // Baselines: already-delegated senders, no authorization in the bundle.
    let mut baselines = Vec::new();
    for n in [1usize, 2] {
        let mut specs = Vec::new();
        for _ in 0..n {
            let signer = authorizer.delegated_eoa(delegates[0]).await?;
            specs.push(OpSpec::typical(Payer::Paymaster, false).with_sender(signer.address(), 0));
        }
        baselines.push(
            runner
                .run(
                    "7702/baseline-delegated-no-auth",
                    &specs,
                    BeneficiaryKind::Bundler,
                )
                .await?,
        );
    }

    let mut cases = Vec::new();
    let plan = [
        (Authority::Empty, 1),
        (Authority::Funded, 1),
        (Authority::RedelegateSame, 1),
        (Authority::RedelegateOther, 1),
        (Authority::Empty, 2),
        (Authority::Funded, 2),
    ];
    for (authority, n) in plan {
        let mut specs = Vec::new();
        for _ in 0..n {
            specs.push(authorizer.op(authority, delegates).await?);
        }
        let name = format!("7702/{authority:?}");
        let run = runner
            .run(name.clone(), &specs, BeneficiaryKind::Bundler)
            .await?;
        let baseline = &baselines[n - 1];
        let extra = run.unmetered_gas - baseline.unmetered_gas;
        let per_auth = extra as f64 / n as f64;
        let predicted = run.ops[0].predicted_authorization_gas;
        cases.push(CaseResult {
            name,
            authority,
            authorizations: n,
            extra_unmetered_gas: extra,
            extra_per_authorization: per_auth,
            predicted_per_authorization: predicted,
            per_authorization_error: predicted as f64 - per_auth,
            run,
        });
    }

    for case in &cases {
        eprintln!(
            "  {:<22} auths={} extra/auth={:>8.0} rundler/auth={:>6} error={:>8.0}",
            format!("{:?}", case.authority),
            case.authorizations,
            case.extra_per_authorization,
            case.predicted_per_authorization,
            case.per_authorization_error,
        );
    }

    Ok(Report {
        experiment: "e4-7702-authorization",
        fixtures: fixtures.clone(),
        delegates,
        baselines,
        cases,
    })
}
