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
use rundler_types::{authorization::Eip7702Auth, chain::ChainSpec, da::DAGasOracleType};

use crate::SimulationTransactionRequest;

pub(crate) mod v0_6;
pub(crate) mod v0_7;

/// Admission checks execution validity; DA affordability is checked separately.
/// Nitro can omit posting charges for both eth_call and debug_traceCall, so a
/// sponsored operation with zero PVG still has the full verification gas budget.
/// See OffchainLabs/go-ethereum internal/ethapi/transaction_args.go and
/// OffchainLabs/nitro arbos/tx_processor.go (GasChargingHook).
fn validation_simulation_request(
    mut tx: SimulationTransactionRequest,
    chain_spec: &ChainSpec,
    max_verification_gas: u64,
) -> SimulationTransactionRequest {
    if matches!(
        chain_spec.da_gas_oracle_type,
        DAGasOracleType::ArbitrumNitro | DAGasOracleType::CachedNitro
    ) {
        tx.gas = Some(max_verification_gas);
        tx.other.insert("skipL1Charging".to_string(), true.into());
    }
    tx
}

/// Returns true if an `eth_call` error means the node rejected the call before
/// execution because its fee caps were below the base fee.
fn is_base_fee_too_low(message: &str) -> bool {
    // Geth: https://github.com/ethereum/go-ethereum/blob/master/core/error.go `ErrFeeCapTooLow`
    // Reth: https://github.com/paradigmxyz/reth/blob/main/crates/rpc/rpc-eth-types/src/error/mod.rs
    let lowercase_message = message.to_lowercase();
    lowercase_message.contains("max fee per gas less than block base fee")
        || lowercase_message.contains("fee cap less than block base fee")
}

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

#[cfg(test)]
mod tests {
    use std::{thread, time::Duration};

    use alloy_primitives::{Address, Bytes, U256};
    use alloy_provider::RootProvider;
    use alloy_sol_types::SolError;
    use rundler_contracts::{
        v0_6::UserOperation as ContractUserOperation,
        v0_7::{IEntryPoint::FailedOp, PackedUserOperation},
    };
    use rundler_types::{EntryPointVersion, chain::ChainSpec, da::DAGasOracleType, v0_6, v0_7};
    use serde_json::{Value, json};
    use tiny_http::{Response, Server};

    use super::is_base_fee_too_low;
    use crate::{
        AlloyEntryPointV0_6, AlloyEntryPointV0_7, AlloyEvmProvider, AnyNetwork, EvmProvider,
        GethDebugTracingCallOptions, SimulationProvider, SimulationTransactionRequest,
        StateOverride, ZeroDAGasOracle,
    };

    const VERIFICATION_GAS: u64 = 5_000_000;

    #[tokio::test]
    async fn validation_rpc_preserves_nitro_option_and_revert_decoding() {
        let server = Server::http("127.0.0.1:0").unwrap();
        let url = format!("http://{}", server.server_addr()).parse().unwrap();
        let worker = thread::spawn(move || {
            for method in ["eth_call", "eth_call", "debug_traceCall"] {
                let mut request = server
                    .recv_timeout(Duration::from_secs(10))
                    .unwrap()
                    .unwrap();
                let body: Value = serde_json::from_reader(request.as_reader()).unwrap();
                assert_eq!(body["method"], method);
                assert_eq!(body["params"][0]["skipL1Charging"], true);
                assert_eq!(body["params"][0]["gas"], "0x4c4b40");
                assert_eq!(body["params"][1], "0x7b");
                let response = if method == "eth_call" {
                    let revert = FailedOp {
                        opIndex: U256::ZERO,
                        reason: "AA25 invalid account nonce".to_string(),
                    };
                    // FailedOp has the same ABI for both entry point versions.
                    let data = revert.abi_encode();
                    json!({"jsonrpc": "2.0", "id": body["id"], "error": {
                        "code": 3, "message": "execution reverted", "data": Bytes::from(data)
                    }})
                } else {
                    json!({"jsonrpc": "2.0", "id": body["id"], "result": {
                        "gas": 0, "failed": false, "returnValue": "", "structLogs": []
                    }})
                };
                request
                    .respond(Response::from_string(response.to_string()))
                    .unwrap();
            }
        });
        let chain_spec = ChainSpec {
            da_gas_oracle_type: DAGasOracleType::CachedNitro,
            da_pre_verification_gas: true,
            include_da_gas_in_gas_limit: true,
            ..ChainSpec::default()
        };
        let provider = RootProvider::<AnyNetwork>::new_http(url);
        let ep_v06 = AlloyEntryPointV0_6::new(
            chain_spec.clone(),
            VERIFICATION_GAS,
            10_000_000,
            10_000_000,
            5_000_000,
            provider.clone(),
            ZeroDAGasOracle,
        );
        let op_v06 = v0_6::UserOperationBuilder::from_contract(
            &chain_spec,
            ContractUserOperation::default(),
        )
        .unwrap()
        .build();
        let result = ep_v06
            .simulate_validation(op_v06, Some(123.into()))
            .await
            .unwrap();
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("AA25 invalid account nonce")
        );

        let ep_v07 = AlloyEntryPointV0_7::new(
            chain_spec.clone(),
            EntryPointVersion::V0_7,
            VERIFICATION_GAS,
            10_000_000,
            10_000_000,
            5_000_000,
            provider.clone(),
            ZeroDAGasOracle,
        );
        let op_v07 = v0_7::UserOperationBuilder::from_packed(
            PackedUserOperation::default(),
            &chain_spec,
            EntryPointVersion::V0_7,
            None,
        )
        .unwrap()
        .build();
        let result = ep_v07
            .simulate_validation(op_v07.clone(), Some(123.into()))
            .await
            .unwrap();
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("AA25 invalid account nonce")
        );
        let (tx, overrides) = ep_v07.get_tracer_simulate_validation_call(op_v07).unwrap();
        let trace_options = GethDebugTracingCallOptions {
            state_overrides: Some(overrides),
            ..GethDebugTracingCallOptions::default()
        };
        AlloyEvmProvider::new(provider)
            .debug_trace_call(tx, Some(123.into()), trace_options)
            .await
            .unwrap();
        worker.join().unwrap();
    }

    fn validation_requests(
        oracle_type: DAGasOracleType,
        pvg: u128,
    ) -> Vec<(SimulationTransactionRequest, StateOverride)> {
        let chain_spec = ChainSpec {
            da_gas_oracle_type: oracle_type,
            da_pre_verification_gas: true,
            include_da_gas_in_gas_limit: true,
            ..ChainSpec::default()
        };
        let provider =
            RootProvider::<AnyNetwork>::new_http("http://localhost:8545".parse().unwrap());
        let ep = AlloyEntryPointV0_6::new(
            chain_spec.clone(),
            VERIFICATION_GAS,
            10_000_000,
            10_000_000,
            5_000_000,
            provider.clone(),
            ZeroDAGasOracle,
        );
        let op = v0_6::UserOperationBuilder::new(
            &chain_spec,
            v0_6::UserOperationRequiredFields {
                sender: Address::ZERO,
                nonce: U256::ZERO,
                init_code: Bytes::new(),
                call_data: Bytes::from_static(&[1, 2, 3]),
                signature: Bytes::new(),
                paymaster_and_data: Bytes::new(),
                call_gas_limit: 100_000,
                verification_gas_limit: 100_000,
                pre_verification_gas: pvg,
                max_fee_per_gas: 0,
                max_priority_fee_per_gas: 0,
            },
        )
        .build();
        let mut calls = vec![ep.get_tracer_simulate_validation_call(op).unwrap()];
        for version in [
            EntryPointVersion::V0_7,
            EntryPointVersion::V0_8,
            EntryPointVersion::V0_9,
        ] {
            let ep = AlloyEntryPointV0_7::new(
                chain_spec.clone(),
                version,
                VERIFICATION_GAS,
                10_000_000,
                10_000_000,
                5_000_000,
                provider.clone(),
                ZeroDAGasOracle,
            );
            let op = v0_7::UserOperationBuilder::new(
                &chain_spec,
                version,
                v0_7::UserOperationRequiredFields {
                    sender: Address::ZERO,
                    nonce: U256::ZERO,
                    call_data: Bytes::from_static(&[1, 2, 3]),
                    signature: Bytes::new(),
                    call_gas_limit: 100_000,
                    verification_gas_limit: 100_000,
                    pre_verification_gas: pvg,
                    max_fee_per_gas: 0,
                    max_priority_fee_per_gas: 0,
                },
            )
            .build();
            calls.push(ep.get_tracer_simulate_validation_call(op).unwrap());
        }
        calls
    }

    #[test]
    fn nitro_validation_preserves_execution_budget_with_zero_or_large_pvg() {
        for pvg in [0, 10_000_000] {
            let ordinary = validation_requests(DAGasOracleType::None, pvg);
            for oracle_type in [DAGasOracleType::ArbitrumNitro, DAGasOracleType::CachedNitro] {
                for ((tx, overrides), (ordinary_tx, ordinary_overrides)) in
                    validation_requests(oracle_type, pvg)
                        .into_iter()
                        .zip(&ordinary)
                {
                    let json = serde_json::to_value(&tx).unwrap();
                    assert_eq!(json["skipL1Charging"], true);
                    assert_eq!(tx.gas, Some(VERIFICATION_GAS));
                    assert_eq!(tx.input, ordinary_tx.input);
                    assert_eq!(tx.to, ordinary_tx.to);
                    assert_eq!(tx.from, ordinary_tx.from);
                    assert_eq!(&overrides, ordinary_overrides);
                }
            }
        }
    }

    #[test]
    fn non_nitro_validation_keeps_existing_gas_allowance() {
        for oracle_type in [
            DAGasOracleType::None,
            DAGasOracleType::OptimismBedrock,
            DAGasOracleType::LocalBedrock,
        ] {
            for pvg in [0, 10_000_000] {
                for (tx, _) in validation_requests(oracle_type, pvg) {
                    let json = serde_json::to_value(&tx).unwrap();
                    assert!(json.get("skipL1Charging").is_none());
                    if pvg == 0 {
                        assert_eq!(tx.gas, Some(VERIFICATION_GAS));
                    } else {
                        assert!(tx.gas.unwrap() > VERIFICATION_GAS);
                    }
                }
            }
        }
    }

    #[test]
    fn classifies_base_fee_too_low() {
        // Geth/Reth, as returned by HyperEVM for a bundle validation call.
        assert!(is_base_fee_too_low(
            "max fee per gas less than block base fee"
        ));
        assert!(is_base_fee_too_low(
            "err: max fee per gas less than block base fee: address 0x1, maxFeePerGas: 1 baseFee: 2"
        ));
        assert!(is_base_fee_too_low("Fee cap less than block base fee"));
    }

    #[test]
    fn ignores_unrelated_errors() {
        assert!(!is_base_fee_too_low("execution reverted"));
        assert!(!is_base_fee_too_low("nonce too low"));
        assert!(!is_base_fee_too_low("insufficient funds for gas * price"));
        // A submission-time underpriced error is a different condition.
        assert!(!is_base_fee_too_low("transaction underpriced"));
    }
}
