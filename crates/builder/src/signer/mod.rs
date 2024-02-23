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
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
pub(crate) use aws::*;
use ethers::{
    abi::Address,
    providers::Middleware,
    types::{
        transaction::{eip2718::TypedTransaction, eip712::Eip712},
        Signature,
    },
};
use ethers_signers::{AwsSignerError, LocalWallet, Signer, WalletError};
use rundler_utils::handle::SpawnGuard;

/// A local signer handle
#[derive(Debug)]
pub(crate) struct LocalSigner {
    signer: LocalWallet,
    _monitor_abort_handle: SpawnGuard,
}

impl LocalSigner {
    pub(crate) async fn connect<M: Middleware + 'static>(
        provider: Arc<M>,
        chain_id: u64,
        private_key: String,
    ) -> anyhow::Result<Self> {
        let signer = private_key
            .parse::<LocalWallet>()
            .context("should create signer")?;
        let _monitor_abort_handle = SpawnGuard::spawn_with_guard(
            super::signer::monitor_account_balance(signer.address(), Arc::clone(&provider)),
        );

        Ok(Self {
            signer: signer.with_chain_id(chain_id),
            _monitor_abort_handle,
        })
    }
}

pub(crate) async fn monitor_account_balance<M: Middleware>(addr: Address, provider: Arc<M>) {
    loop {
        match provider.get_balance(addr, None).await {
            Ok(balance) => {
                // Divide balance by a large number first to prevent overflow when
                // converting to u64. This keeps six decimal places.
                let eth_balance = (balance / 10_u64.pow(12)).as_u64() as f64 / 1e6;
                tracing::info!("account {addr:?} balance: {}", eth_balance);
                metrics::gauge!("bundle_builder_account_balance", "addr" => format!("{addr:?}"))
                    .set(eth_balance);
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

#[derive(Debug, thiserror::Error)]
pub(crate) enum BundlerSignerError {
    #[error(transparent)]
    Local(#[from] WalletError),
    #[error(transparent)]
    Kms(#[from] AwsSignerError),
}

#[async_trait]
impl Signer for BundlerSigner {
    type Error = BundlerSignerError;

    async fn sign_message<S: Send + Sync + AsRef<[u8]>>(
        &self,
        message: S,
    ) -> Result<Signature, Self::Error> {
        let out = match self {
            BundlerSigner::Local(s) => s.signer.sign_message(message).await?,
            BundlerSigner::Kms(s) => s.signer.sign_message(message).await?,
        };
        Ok(out)
    }

    async fn sign_transaction(&self, message: &TypedTransaction) -> Result<Signature, Self::Error> {
        let out = match self {
            BundlerSigner::Local(s) => s.signer.sign_transaction(message).await?,
            BundlerSigner::Kms(s) => s.signer.sign_transaction(message).await?,
        };
        Ok(out)
    }

    async fn sign_typed_data<T: Eip712 + Send + Sync>(
        &self,
        payload: &T,
    ) -> Result<Signature, Self::Error> {
        let out = match self {
            BundlerSigner::Local(s) => s.signer.sign_typed_data(payload).await?,
            BundlerSigner::Kms(s) => s.signer.sign_typed_data(payload).await?,
        };
        Ok(out)
    }

    fn address(&self) -> Address {
        match self {
            BundlerSigner::Local(s) => s.signer.address(),
            BundlerSigner::Kms(s) => s.signer.address(),
        }
    }

    fn chain_id(&self) -> u64 {
        match self {
            BundlerSigner::Local(s) => s.signer.chain_id(),
            BundlerSigner::Kms(s) => s.signer.chain_id(),
        }
    }

    fn with_chain_id<T: Into<u64>>(self, chain_id: T) -> Self {
        match self {
            BundlerSigner::Local(mut s) => {
                s.signer = s.signer.with_chain_id(chain_id);
                BundlerSigner::Local(s)
            }
            BundlerSigner::Kms(mut s) => {
                s.signer = s.signer.with_chain_id(chain_id);
                BundlerSigner::Kms(s)
            }
        }
    }
}
