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
use alloy_json_rpc::{ErrorPayload, RpcError};
use alloy_primitives::{address, Address, Bytes, Log, LogData, Signature, U256};
use alloy_provider::{ext::DebugApi, network::TransactionBuilder7702};
use alloy_rlp::Encodable;
use alloy_rpc_types_eth::{
    simulate::{SimBlock, SimulatePayload},
    BlockId, TransactionRequest,
};
use alloy_rpc_types_trace::geth::{
    CallConfig, GethDebugBuiltInTracerType, GethDebugTracerType, GethDebugTracingOptions, GethTrace,
};
use rundler_types::{authorization::Eip7702Auth, chain::ChainSpec};

use crate::{AlloyProvider, ProviderResult};

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
        tx = tx.with_authorization_list(vec![auth.max_fill().into()])
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

struct SimulateResult {
    gas_used: u128,
    success: bool,
    data: Bytes,
    logs: Vec<Log>,
}

async fn simulate_transaction<P: AlloyProvider>(
    provider: &P,
    chain_spec: &ChainSpec,
    tx: TransactionRequest,
    block_id: BlockId,
) -> ProviderResult<SimulateResult> {
    if chain_spec.rpc_eth_simulate_v1_enabled {
        simulate_with_simulate_v1(provider, tx, block_id).await
    } else if chain_spec.rpc_debug_trace_call_enabled {
        simulate_with_debug_trace_call(provider, tx, block_id).await
    } else {
        // TOD(revert): consider a fallback here to eth_call to just get the revert data
        simulate_with_eth_call(provider, tx, block_id).await
    }
}

async fn simulate_with_simulate_v1<P: AlloyProvider>(
    provider: &P,
    tx: TransactionRequest,
    block_id: BlockId,
) -> ProviderResult<SimulateResult> {
    let payload = SimulatePayload {
        block_state_calls: vec![SimBlock {
            block_overrides: None,
            state_overrides: None,
            calls: vec![tx],
        }],
        trace_transfers: false,
        validation: false,
        return_full_transactions: false,
    };

    let result = provider.simulate(&payload).block_id(block_id).await?;
    if result.len() != 1 {
        return Err(anyhow::anyhow!("expected 1 simulated block, got {}", result.len()).into());
    }
    if result[0].calls.len() != 1 {
        return Err(anyhow::anyhow!("expected 1 call, got {}", result[0].calls.len()).into());
    }
    let result_call = &result[0].calls[0];

    Ok(SimulateResult {
        gas_used: result_call.gas_used.into(),
        success: result_call.status,
        data: result_call.return_data.clone(),
        logs: result_call
            .logs
            .clone()
            .into_iter()
            .map(|log| log.inner)
            .collect(),
    })
}

async fn simulate_with_debug_trace_call<P: AlloyProvider>(
    provider: &P,
    tx: TransactionRequest,
    block_id: BlockId,
) -> ProviderResult<SimulateResult> {
    let trace_options = GethDebugTracingOptions::new_tracer(GethDebugTracerType::BuiltInTracer(
        GethDebugBuiltInTracerType::CallTracer,
    ))
    .with_call_config(CallConfig::default().with_log());

    let trace = provider
        .debug_trace_call(tx.into(), block_id, trace_options.into())
        .await?;

    let GethTrace::CallTracer(call_frame) = trace else {
        return Err(anyhow::anyhow!("expected call tracer, got {:?}", trace).into());
    };

    Ok(SimulateResult {
        gas_used: call_frame.gas_used.try_into().unwrap_or(u128::MAX),
        success: call_frame.error.is_none(),
        data: call_frame.output.unwrap_or_default(),
        logs: call_frame
            .logs
            .iter()
            .filter_map(|log| {
                let address = log.address?;
                let topics = log.clone().topics?;
                let data = log.clone().data?;
                let data = LogData::new(topics, data)?;
                Some(Log { address, data })
            })
            .collect(),
    })
}

async fn simulate_with_eth_call<P: AlloyProvider>(
    provider: &P,
    tx: TransactionRequest,
    block_id: BlockId,
) -> ProviderResult<SimulateResult> {
    match provider.call(tx.into()).block(block_id).await {
        Ok(data) => Ok(SimulateResult {
            gas_used: 0,
            success: false,
            data,
            logs: vec![],
        }),
        // TODO(revert): don't hardcode these
        Err(RpcError::ErrorResp(ErrorPayload {
            code: -32603,
            message,
            data,
        })) if message == "execution reverted" => Ok(SimulateResult {
            gas_used: 0,
            success: false,
            data: data
                .and_then(|data| data.to_string().parse::<Bytes>().ok())
                .unwrap_or_default(),
            logs: vec![],
        }),
        Err(e) => Err(e.into()),
    }
}
