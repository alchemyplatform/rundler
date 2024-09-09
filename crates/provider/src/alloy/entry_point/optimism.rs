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

use alloy_consensus::{transaction::SignableTransaction, TxEnvelope, TypedTransaction};
use alloy_primitives::{ruint::UintTryTo, Address, Bytes, Signature, U256};
use alloy_provider::Provider as AlloyProvider;
use alloy_rlp::Encodable;
use alloy_rpc_types_eth::TransactionRequest;
use alloy_sol_types::sol;
use alloy_transport::Transport;
use anyhow::Context;

use crate::ProviderResult;

// From https://github.com/ethereum-optimism/optimism/blob/f93f9f40adcd448168c6ea27820aeee5da65fcbd/packages/contracts-bedrock/src/L2/GasPriceOracle.sol#L54
sol! {
    #[sol(rpc)]
    interface GasPriceOracle {
        function getL1Fee(bytes memory _data) external view returns (uint256);
    }
}

pub(crate) async fn estimate_l1_gas<AP: AlloyProvider<T>, T: Transport + Clone>(
    provider: AP,
    oracle_address: Address,
    to_address: Address,
    data: Bytes,
    gas_price: u128,
) -> ProviderResult<u128> {
    let oracle = GasPriceOracle::GasPriceOracleInstance::new(oracle_address, provider);

    let tx = TransactionRequest::default()
        .from(Address::random())
        .to(to_address)
        .gas_limit(1_000_000)
        .max_priority_fee_per_gas(100_000_000)
        .max_fee_per_gas(100_000_000)
        .value(U256::from(0))
        .input(data.into())
        .nonce(100_000);
    let ty = match tx.build_typed_tx() {
        Ok(tx) => tx,
        Err(e) => {
            return Err(anyhow::anyhow!("failed to build typed transaction: {:?}", e).into());
        }
    };

    let mut tx_1559 = match ty {
        TypedTransaction::Eip1559(tx) => tx,
        _ => {
            return Err(anyhow::anyhow!("transaction is not eip1559").into());
        }
    };

    tx_1559.set_chain_id(100_000);
    // use a test signature just for gas estimation
    // NOTE: this is an unsupported alloy function, if its removed just hardcode any valid signature
    let tx_envelope: TxEnvelope = tx_1559.into_signed(Signature::test_signature()).into();
    let mut encoded = vec![];
    tx_envelope.encode(&mut encoded);

    let l1_fee: u128 = oracle
        .getL1Fee(Bytes::from(encoded))
        .call()
        .await?
        ._0
        .uint_try_to()
        .context("failed to convert L1 fee to u128")?;

    Ok(l1_fee.checked_div(gas_price).unwrap_or(u128::MAX))
}
