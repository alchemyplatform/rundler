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

use alloy_primitives::{Address, B256};
use async_trait::async_trait;
use rundler_provider::{EvmProvider, TransactionRequest};
use rundler_sim::ExpectedStorage;
use rundler_types::GasFees;
use serde_json::json;

use super::{CancelTxInfo, Result};
use crate::{
    sender::{create_hard_cancel_tx, SentTxInfo, TransactionSender},
    signer::Signer,
};

#[derive(Debug)]
pub(crate) struct RawTransactionSender<P, S> {
    submit_provider: P,
    signer: S,
    use_conditional_rpc: bool,
}

#[async_trait]
impl<P, S> TransactionSender for RawTransactionSender<P, S>
where
    P: EvmProvider,
    S: Signer,
{
    async fn send_transaction(
        &self,
        tx: TransactionRequest,
        expected_storage: &ExpectedStorage,
    ) -> Result<SentTxInfo> {
        let (raw_tx, nonce) = self.signer.fill_and_sign(tx).await?;

        let tx_hash = if self.use_conditional_rpc {
            self.submit_provider
                .request(
                    "eth_sendRawTransactionConditional",
                    (raw_tx, json!({ "knownAccounts": expected_storage })),
                )
                .await?
        } else {
            self.submit_provider
                .request("eth_sendRawTransaction", (raw_tx,))
                .await?
        };

        Ok(SentTxInfo { nonce, tx_hash })
    }

    async fn cancel_transaction(
        &self,
        _tx_hash: B256,
        nonce: u64,
        gas_fees: GasFees,
    ) -> Result<CancelTxInfo> {
        let tx = create_hard_cancel_tx(self.signer.address(), nonce, gas_fees);

        let (raw_tx, _) = self.signer.fill_and_sign(tx).await?;

        let tx_hash = self
            .submit_provider
            .request("eth_sendRawTransaction", (raw_tx,))
            .await?;

        Ok(CancelTxInfo {
            tx_hash,
            soft_cancelled: false,
        })
    }

    fn address(&self) -> Address {
        self.signer.address()
    }
}

impl<P, S> RawTransactionSender<P, S> {
    pub(crate) fn new(submit_provider: P, signer: S, use_conditional_rpc: bool) -> Self {
        Self {
            submit_provider,
            signer,
            use_conditional_rpc,
        }
    }
}
