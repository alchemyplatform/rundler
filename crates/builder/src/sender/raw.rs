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
use rundler_provider::{EvmProvider, ProviderError, TransactionRequest};
use rundler_signer::SignerLease;
use rundler_types::{ExpectedStorage, GasFees};
use serde_json::json;

use super::{CancelTxInfo, Result};
use crate::sender::{TransactionSender, TxSenderError, create_hard_cancel_tx};

#[derive(Debug)]
pub(crate) struct RawTransactionSender<P> {
    submit_provider: P,
    use_conditional_rpc: bool,
    internal_rpc_error_is_terminal: bool,
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

        let result = if self.use_conditional_rpc {
            self.submit_provider
                .request(
                    "eth_sendRawTransactionConditional",
                    (raw_tx, json!({ "knownAccounts": expected_storage })),
                )
                .await
        } else {
            self.submit_provider.send_raw_transaction(raw_tx).await
        };

        result.map_err(|e| self.map_provider_error(e))
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

        let tx_hash = self
            .submit_provider
            .send_raw_transaction(raw_tx)
            .await
            .map_err(|e| self.map_provider_error(e))?;

        Ok(CancelTxInfo {
            tx_hash,
            soft_cancelled: false,
        })
    }
}

impl<P> RawTransactionSender<P> {
    pub(crate) fn new(
        submit_provider: P,
        use_conditional_rpc: bool,
        internal_rpc_error_is_terminal: bool,
    ) -> Self {
        Self {
            submit_provider,
            use_conditional_rpc,
            internal_rpc_error_is_terminal,
        }
    }

    fn map_provider_error(&self, error: ProviderError) -> TxSenderError {
        let error = TxSenderError::from(error);
        if self.internal_rpc_error_is_terminal {
            error.promote_terminal_internal_error()
        } else {
            error
        }
    }
}

#[cfg(test)]
mod tests {
    use rundler_provider::MockEvmProvider;

    use super::*;
    use crate::sender::rpc_error_response;

    #[test]
    fn promotes_internal_error_only_when_flagged() {
        let flagged = RawTransactionSender::new(MockEvmProvider::new(), false, true);
        assert!(matches!(
            flagged.map_provider_error(rpc_error_response(-32000, "internal error")),
            TxSenderError::TerminalRpcError { .. }
        ));

        let unflagged = RawTransactionSender::new(MockEvmProvider::new(), false, false);
        assert!(matches!(
            unflagged.map_provider_error(rpc_error_response(-32000, "internal error")),
            TxSenderError::UnrecognizedRpc { .. }
        ));
    }
}
