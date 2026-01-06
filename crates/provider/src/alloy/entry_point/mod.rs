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

use alloy_consensus::{TxEnvelope, TypedTransaction, transaction::SignableTransaction};
use alloy_primitives::{Address, Bytes, Signature, U256, address};
use alloy_provider::network::TransactionBuilder7702;
use alloy_rlp::Encodable;
use alloy_rpc_types_eth::TransactionRequest;
use rundler_types::authorization::Eip7702Auth;

pub(crate) mod v0_6;
pub(crate) mod v0_7;

fn max_bundle_transaction_data(
    to_address: Address,
    data: Bytes,
    gas_price: u128,
    au: Option<&Eip7702Auth>,
) -> Bytes {
    // Fill in max values for unknown or varying fields
    let gas_price_ceil = gas_price.next_power_of_two() - 1; // max out bits of gas price, assume same power of 2
    let gas_limit = 0xffffffff; // 4 bytes
    let nonce = 0xffffffff; // 4 bytes
    let chain_id = 0xffffffff; // 4 bytes

    let mut tx = TransactionRequest::default()
        .from(address!("ffffffffffffffffffffffffffffffffffffffff"))
        .to(to_address)
        .gas_limit(gas_limit)
        .max_priority_fee_per_gas(gas_price_ceil)
        .max_fee_per_gas(gas_price_ceil)
        .value(U256::ZERO)
        .input(data.into())
        .nonce(nonce);
    if let Some(auth) = au {
        tx = tx.with_authorization_list(vec![auth.clone().into_max_fill().into()])
    }

    // these conversions should not fail.
    let ty = tx.build_typed_tx().unwrap();

    match ty {
        TypedTransaction::Eip1559(mut tx) => {
            tx.set_chain_id(chain_id);
            let tx_envelope: TxEnvelope = tx
                .into_signed(Signature::new(U256::MAX, U256::MAX, false))
                .into();
            let mut encoded = vec![];
            tx_envelope.encode(&mut encoded);

            encoded.into()
        }
        TypedTransaction::Eip7702(mut tx) => {
            tx.set_chain_id(chain_id);
            let tx_envelope: TxEnvelope = tx
                .into_signed(Signature::new(U256::MAX, U256::MAX, false))
                .into();
            let mut encoded = vec![];
            tx_envelope.encode(&mut encoded);

            encoded.into()
        }
        _ => {
            panic!("transaction is neither EIP-1559 nor EIP-7702");
        }
    }
}
