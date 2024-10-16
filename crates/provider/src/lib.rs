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

#![warn(missing_docs, unreachable_pub)]
#![deny(unused_must_use, rust_2018_idioms)]
#![doc(test(
    no_crate_inject,
    attr(deny(warnings, rust_2018_idioms), allow(dead_code, unused_variables))
))]

//! Rundler providers
//! A provider is a type that provides access to blockchain data and functions

mod alloy;
pub use alloy::{
    entry_point::{
        v0_6::EntryPointProvider as AlloyEntryPointV0_6,
        v0_7::{
            decode_validation_revert as decode_v0_7_validation_revert,
            EntryPointProvider as AlloyEntryPointV0_7,
        },
    },
    evm::AlloyEvmProvider,
    new_alloy_da_gas_oracle, new_alloy_evm_provider, new_alloy_provider,
};

mod traits;
// re-export alloy RPC types
pub use alloy_json_rpc::{RpcParam, RpcReturn};
pub use alloy_rpc_types_eth::{
    state::{AccountOverride, StateOverride},
    Block, BlockHashOrNumber, BlockId, BlockNumberOrTag, FeeHistory, Filter, FilterBlockOption,
    Header as BlockHeader, Log, ReceiptEnvelope as TransactionReceiptEnvelope,
    ReceiptWithBloom as TransactionReceiptWithBloom, RpcBlockHash, Transaction, TransactionReceipt,
    TransactionRequest,
};
pub use alloy_rpc_types_trace::geth::{
    GethDebugBuiltInTracerType, GethDebugTracerType, GethDebugTracingCallOptions,
    GethDebugTracingOptions, GethTrace,
};
// re-export contract types
pub use rundler_contracts::utils::GetGasUsed::GasUsedResult;
#[cfg(any(test, feature = "test-utils"))]
pub use traits::test_utils::*;
pub use traits::*;
