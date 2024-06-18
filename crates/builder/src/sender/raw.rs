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

use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use ethers::{
    middleware::SignerMiddleware,
    providers::{JsonRpcClient, Middleware, PendingTransaction, Provider},
    types::{transaction::eip2718::TypedTransaction, Address, TransactionReceipt, H256, U256},
};
use ethers_signers::Signer;
use rundler_sim::ExpectedStorage;
use rundler_types::GasFees;

use super::{CancelTxInfo, Result};
use crate::sender::{
    create_hard_cancel_tx, fill_and_sign, SentTxInfo, TransactionSender, TxStatus,
};

#[derive(Debug)]
pub(crate) struct RawTransactionSender<C, S>
where
    C: JsonRpcClient + 'static,
    S: Signer + 'static,
{
    // The `SignerMiddleware` specifically needs to wrap a `Provider`, and not
    // just any `Middleware`, because `.request()` is only on `Provider` and not
    // on `Middleware`.
    provider: SignerMiddleware<Arc<Provider<C>>, S>,
}

#[async_trait]
impl<C, S> TransactionSender for RawTransactionSender<C, S>
where
    C: JsonRpcClient + 'static,
    S: Signer + 'static,
{
    async fn send_transaction(
        &self,
        tx: TypedTransaction,
        _expected_storage: &ExpectedStorage,
    ) -> Result<SentTxInfo> {
        let (raw_tx, nonce) = fill_and_sign(&self.provider, tx).await?;

        let tx_hash = self
            .provider
            .provider()
            .request("eth_sendRawTransaction", (raw_tx,))
            .await?;
        Ok(SentTxInfo { nonce, tx_hash })
    }

    async fn cancel_transaction(
        &self,
        _tx_hash: H256,
        nonce: U256,
        to: Address,
        gas_fees: GasFees,
    ) -> Result<CancelTxInfo> {
        let tx = create_hard_cancel_tx(self.provider.address(), to, nonce, gas_fees);

        let (raw_tx, _) = fill_and_sign(&self.provider, tx).await?;

        let tx_hash = self
            .provider
            .provider()
            .request("eth_sendRawTransaction", (raw_tx,))
            .await?;

        Ok(CancelTxInfo {
            tx_hash,
            soft_cancelled: false,
        })
    }

    async fn get_transaction_status(&self, tx_hash: H256) -> Result<TxStatus> {
        let tx = self
            .provider
            .get_transaction(tx_hash)
            .await
            .context("provider should return transaction status")?;
        Ok(match tx {
            None => TxStatus::Dropped,
            Some(tx) => match tx.block_number {
                None => TxStatus::Pending,
                Some(block_number) => TxStatus::Mined {
                    block_number: block_number.as_u64(),
                },
            },
        })
    }

    async fn wait_until_mined(&self, tx_hash: H256) -> Result<Option<TransactionReceipt>> {
        Ok(PendingTransaction::new(tx_hash, self.provider.inner())
            .await
            .context("should wait for transaction to be mined or dropped")?)
    }

    fn address(&self) -> Address {
        self.provider.address()
    }
}

impl<C, S> RawTransactionSender<C, S>
where
    C: JsonRpcClient + 'static,
    S: Signer + 'static,
{
    pub(crate) fn new(provider: Arc<Provider<C>>, signer: S) -> Self {
        Self {
            provider: SignerMiddleware::new(provider, signer),
        }
    }
}
