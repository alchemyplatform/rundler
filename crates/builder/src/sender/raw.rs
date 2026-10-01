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

use alloy_primitives::{B256, keccak256};
use anyhow::Context;
use async_trait::async_trait;
use rundler_provider::{EvmProvider, ProviderError, TransactionRequest};
use rundler_signer::SignerLease;
use rundler_types::{ExpectedStorage, GasFees, chain::ChainSpec};
use serde_json::json;

use super::{CancelTxInfo, Result};
use crate::sender::{TransactionSender, TxSenderError, create_hard_cancel_tx};

#[derive(Debug)]
pub(crate) struct RawTransactionSender<P> {
    submit_provider: P,
    use_conditional_rpc: bool,
    chain_spec: ChainSpec,
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
        let tx_hash = keccak256(&raw_tx);

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

        self.accept_already_known(result, tx_hash)
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
        let expected_tx_hash = keccak256(&raw_tx);

        let tx_hash = self
            .submit_provider
            .send_raw_transaction(raw_tx)
            .await
            .or_else(|error| {
                if error.is_already_known() {
                    Ok(expected_tx_hash)
                } else {
                    Err(error)
                }
            })
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
        chain_spec: ChainSpec,
    ) -> Self {
        Self {
            submit_provider,
            use_conditional_rpc,
            chain_spec,
        }
    }

    fn map_provider_error(&self, error: ProviderError) -> TxSenderError {
        TxSenderError::from(error).promote_terminal_error(&self.chain_spec)
    }

    fn accept_already_known(
        &self,
        result: std::result::Result<B256, ProviderError>,
        tx_hash: B256,
    ) -> Result<B256> {
        match result {
            Ok(hash) => Ok(hash),
            Err(error) if error.is_already_known() => Ok(tx_hash),
            Err(error) => Err(self.map_provider_error(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use rundler_provider::MockEvmProvider;

    use super::*;
    use crate::sender::rpc_error_response;

    fn chain_spec_with_internal_error_terminal(internal_rpc_error_is_terminal: bool) -> ChainSpec {
        ChainSpec {
            internal_rpc_error_is_terminal,
            ..Default::default()
        }
    }

    #[test]
    fn promotes_internal_error_only_when_flagged() {
        let flagged = RawTransactionSender::new(
            MockEvmProvider::new(),
            false,
            chain_spec_with_internal_error_terminal(true),
        );
        assert!(matches!(
            flagged.map_provider_error(rpc_error_response(-32000, "internal error")),
            TxSenderError::TerminalRpcError { .. }
        ));

        let unflagged = RawTransactionSender::new(
            MockEvmProvider::new(),
            false,
            chain_spec_with_internal_error_terminal(false),
        );
        assert!(matches!(
            unflagged.map_provider_error(rpc_error_response(-32000, "internal error")),
            TxSenderError::UnrecognizedRpc { .. }
        ));
    }

    #[test]
    fn promotes_chain_policy_rejection_regardless_of_flag() {
        for internal_rpc_error_is_terminal in [false, true] {
            let sender = RawTransactionSender::new(
                MockEvmProvider::new(),
                false,
                chain_spec_with_internal_error_terminal(internal_rpc_error_is_terminal),
            );
            assert!(matches!(
                sender.map_provider_error(rpc_error_response(
                    -32000,
                    "Transaction rejected by chain policy"
                )),
                TxSenderError::TerminalRpcError { .. }
            ));
        }
    }

    #[test]
    fn treats_already_known_as_success() {
        let sender = RawTransactionSender::new(MockEvmProvider::new(), false, ChainSpec::default());
        let expected_hash = B256::repeat_byte(0x42);

        let result = sender.accept_already_known(
            Err(rpc_error_response(-32000, "already known")),
            expected_hash,
        );

        assert_eq!(result.unwrap(), expected_hash);
    }
}
