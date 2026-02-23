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

use alloy_primitives::B256;
use anyhow::Context;
use async_trait::async_trait;
use rundler_provider::{EvmProvider, TransactionRequest};
use rundler_signer::SignerLease;
use rundler_types::{ExpectedStorage, GasFees};

use super::{CancelTxInfo, Result};
use crate::sender::{TransactionSender, create_hard_cancel_tx};

#[derive(Debug)]
pub(crate) struct PolygonPrivateSender<P> {
    submit_provider: P,
}

#[async_trait]
impl<P> TransactionSender for PolygonPrivateSender<P>
where
    P: EvmProvider,
{
    async fn send_transaction(
        &self,
        tx: TransactionRequest,
        _expected_storage: &ExpectedStorage,
        signer: &SignerLease,
    ) -> Result<B256> {
        let raw_tx = signer
            .sign_tx_raw(tx)
            .await
            .context("failed to sign transaction")?;

        let tx_hash = self
            .submit_provider
            .request("eth_sendRawTransactionPrivate", raw_tx)
            .await?;

        Ok(tx_hash)
    }

    async fn cancel_transaction(
        &self,
        _tx_hash: B256,
        nonce: u64,
        gas_fees: GasFees,
        signer: &SignerLease,
    ) -> Result<CancelTxInfo> {
        let tx = create_hard_cancel_tx(signer.address(), nonce, gas_fees);

        let raw_tx = signer
            .sign_tx_raw(tx)
            .await
            .context("failed to sign transaction")?;

        let tx_hash = self.submit_provider.send_raw_transaction(raw_tx).await?;

        Ok(CancelTxInfo {
            tx_hash,
            soft_cancelled: false,
        })
    }
}

impl<P> PolygonPrivateSender<P> {
    pub(crate) fn new(submit_provider: P) -> PolygonPrivateSender<P> {
        PolygonPrivateSender { submit_provider }
    }
}
