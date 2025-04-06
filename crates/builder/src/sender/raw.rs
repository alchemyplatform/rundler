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

use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{ChainId, B256};
use anyhow::Context;
use async_trait::async_trait;
use rundler_provider::{EvmProvider, TransactionRequest};
use rundler_signer::SignerLease;
use rundler_types::{ExpectedStorage, GasFees};
use serde_json::json;

use super::{CancelTxInfo, Result};
use crate::sender::{create_hard_cancel_tx, TransactionSender};

#[derive(Debug)]
pub(crate) struct RawTransactionSender<P> {
    submit_provider: P,
    chain_id: ChainId,
    use_conditional_rpc: bool,
}

#[async_trait]
impl<P> TransactionSender for RawTransactionSender<P>
where
    P: EvmProvider,
{
    async fn send_transaction(
        &self,
        tx: TransactionRequest,
        expected_storage: &ExpectedStorage,
        signer: &SignerLease,
    ) -> Result<B256> {
        let raw_tx = signer
            .sign_tx_raw(tx)
            .await
            .context("failed to sign transaction")?;

        let tx_hash = if self.use_conditional_rpc {
            self.submit_provider
                .request(
                    "eth_sendRawTransactionConditional",
                    (raw_tx, json!({ "knownAccounts": expected_storage })),
                )
                .await?
        } else {
            self.submit_provider.send_raw_transaction(raw_tx).await?
        };

        Ok(tx_hash)
    }

    async fn cancel_transaction(
        &self,
        _tx_hash: B256,
        nonce: u64,
        gas_fees: GasFees,
        signer: &SignerLease,
    ) -> Result<CancelTxInfo> {
        let tx = create_hard_cancel_tx(self.chain_id, signer.address(), nonce, gas_fees);

        let tx_envelope = signer
            .sign_tx(tx)
            .await
            .context("failed to sign transaction")?;
        let mut raw_tx = vec![];
        tx_envelope.encode_2718(&mut raw_tx);

        let tx_hash = self
            .submit_provider
            .send_raw_transaction(raw_tx.into())
            .await?;

        Ok(CancelTxInfo {
            tx_hash,
            soft_cancelled: false,
        })
    }
}

impl<P> RawTransactionSender<P> {
    pub(crate) fn new(submit_provider: P, use_conditional_rpc: bool, chain_id: ChainId) -> Self {
        Self {
            submit_provider,
            chain_id,
            use_conditional_rpc,
        }
    }
}
