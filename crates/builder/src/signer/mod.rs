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

mod aws;
mod local;

use alloy_consensus::{SignableTransaction, TxEnvelope, TypedTransaction};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, B256};
use alloy_signer::{Signature, Signer as _};
use anyhow::{bail, Context};
pub(crate) use aws::*;
pub(crate) use local::*;
use metrics::Gauge;
use metrics_derive::Metrics;
use num_traits::cast::ToPrimitive;
use rundler_provider::{EvmProvider, TransactionRequest};

#[async_trait::async_trait]
pub(crate) trait Signer: Send + Sync {
    fn address(&self) -> Address;

    fn chain_id(&self) -> u64;

    async fn sign_hash(&self, hash: &B256) -> anyhow::Result<Signature>;

    async fn fill_and_sign(&self, mut tx: TransactionRequest) -> anyhow::Result<(Bytes, u64)> {
        tx = tx.from(self.address());

        let nonce = tx
            .nonce
            .context("nonce should be set when transaction is filled")?;

        let TypedTransaction::Eip1559(mut tx_1559) = tx
            .build_typed_tx()
            .expect("should build eip1559 transaction")
        else {
            bail!("transaction is not eip1559");
        };

        tx_1559.set_chain_id(self.chain_id());
        let tx_hash = tx_1559.signature_hash();

        let signature = self
            .sign_hash(&tx_hash)
            .await
            .context("should sign transaction before sending")?;

        let signed: TxEnvelope = tx_1559.into_signed(signature).into();

        let mut encoded = vec![];
        signed.encode_2718(&mut encoded);

        Ok((encoded.into(), nonce))
    }
}

#[derive(Metrics)]
#[metrics(scope = "bundle_builder")]
struct BuilderMetric {
    #[metric(describe = "the balance of bundler builder.")]
    account_balance: Gauge,
}

pub(crate) async fn monitor_account_balance<P: EvmProvider>(addr: Address, provider: P) {
    loop {
        match provider.get_balance(addr, None).await {
            Ok(balance) => {
                let eth_balance = balance.to_f64().unwrap_or_default() / 1e18;
                tracing::info!("account {addr:?} balance: {}", eth_balance);
                let metric = BuilderMetric::new_with_labels(&[("addr", format!("{addr:?}"))]);
                metric.account_balance.set(eth_balance);
            }
            Err(err) => {
                tracing::error!("Get account {addr:?} balance error {err:?}");
            }
        };
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    }
}

/// A `Signer` which is backed by either a local signer or a KMS signer.
#[derive(Debug)]
pub(crate) enum BundlerSigner {
    Local(LocalSigner),
    Kms(KmsSigner),
}

#[async_trait::async_trait]
impl Signer for BundlerSigner {
    fn address(&self) -> Address {
        match self {
            Self::Local(l) => l.signer.address(),
            Self::Kms(k) => k.signer.address(),
        }
    }

    fn chain_id(&self) -> u64 {
        match self {
            Self::Local(l) => l
                .signer
                .chain_id()
                .expect("local signer should have chain id"),
            Self::Kms(k) => k
                .signer
                .chain_id()
                .expect("kms signer should have chain id"),
        }
    }

    async fn sign_hash(&self, hash: &B256) -> anyhow::Result<Signature> {
        match self {
            Self::Local(l) => l
                .signer
                .sign_hash(hash)
                .await
                .context("local signer failed"),
            Self::Kms(k) => k.signer.sign_hash(hash).await.context("kms signer failed"),
        }
    }
}
