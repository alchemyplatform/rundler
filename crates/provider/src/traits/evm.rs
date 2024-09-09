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

//! Trait for interacting with chain data and contracts.

use alloy_json_rpc::{RpcParam, RpcReturn};
use alloy_primitives::{Address, Bytes, TxHash, B256, U256};
use alloy_rpc_types_eth::{
    state::StateOverride, Block, BlockId, BlockNumberOrTag, FeeHistory, Filter, Log, Transaction,
    TransactionReceipt, TransactionRequest,
};
use alloy_rpc_types_trace::geth::{
    GethDebugTracingCallOptions, GethDebugTracingOptions, GethTrace,
};
#[cfg(feature = "test-utils")]
use mockall::automock;
use rundler_contracts::utils::GetGasUsed::GasUsedResult;

use super::error::ProviderResult;

/// A struct representing an EVM call
#[derive(Debug)]
pub struct EvmCall {
    /// The address to call
    pub to: Address,
    /// Call data
    pub data: Bytes,
    /// Call value
    pub value: U256,
    /// State overrides
    pub state_override: StateOverride,
}

/// Trait for interacting with chain data and contracts.
#[cfg_attr(feature = "test-utils", automock)]
#[async_trait::async_trait]
pub trait EvmProvider: Send + Sync {
    /// Make an arbitrary JSON RPC request to the provider
    async fn request<P, R>(&self, method: &'static str, params: P) -> ProviderResult<R>
    where
        P: RpcParam + 'static,
        R: RpcReturn;

    /// Get fee history given a number of blocks and reward percentiles
    async fn fee_history(
        &self,
        block_count: u64,
        block_number: BlockNumberOrTag,
        reward_percentiles: &[f64],
    ) -> ProviderResult<FeeHistory>;

    /// Simulate a transaction via an eth_call
    async fn call(
        &self,
        tx: &TransactionRequest,
        block: Option<BlockId>,
        state_overrides: &StateOverride,
    ) -> ProviderResult<Bytes>;

    /// Get the current block number
    async fn get_block_number(&self) -> ProviderResult<u64>;

    /// Get a block by its hash or number
    async fn get_block(&self, block_id: BlockId) -> ProviderResult<Option<Block>>;

    /// Get the balance of an address
    async fn get_balance(&self, address: Address, block: Option<BlockId>) -> ProviderResult<U256>;

    /// Get transaction by hash
    async fn get_transaction_by_hash(&self, tx: TxHash) -> ProviderResult<Option<Transaction>>;

    /// Get transaction receipt by hash
    async fn get_transaction_receipt(
        &self,
        tx: TxHash,
    ) -> ProviderResult<Option<TransactionReceipt>>;

    /// Debug trace a transaction
    async fn debug_trace_transaction(
        &self,
        tx_hash: TxHash,
        trace_options: GethDebugTracingOptions,
    ) -> ProviderResult<GethTrace>;

    /// Debug trace a call
    async fn debug_trace_call(
        &self,
        tx: TransactionRequest,
        block_id: Option<BlockId>,
        trace_options: GethDebugTracingCallOptions,
    ) -> ProviderResult<GethTrace>;

    /// Get the latest block hash and number
    async fn get_latest_block_hash_and_number(&self) -> ProviderResult<(B256, u64)>;

    /// Get the base fee per gas of the pending block
    async fn get_pending_base_fee(&self) -> ProviderResult<u128>;

    /// Get the max fee per gas as reported by the node's RPC
    async fn get_max_priority_fee(&self) -> ProviderResult<u128>;

    /// Get the code at an address
    async fn get_code(&self, address: Address, block: Option<BlockId>) -> ProviderResult<Bytes>;

    /// Get the nonce/transaction count of an address
    async fn get_transaction_count(&self, address: Address) -> ProviderResult<u64>;

    /// Get the logs matching a filter
    async fn get_logs(&self, filter: &Filter) -> ProviderResult<Vec<Log>>;

    /// Measures the gas used by a call to target with value and data.
    async fn get_gas_used(&self, call: EvmCall) -> ProviderResult<GasUsedResult>;

    /// Get the storage values at a given address and slots
    async fn batch_get_storage_at(
        &self,
        address: Address,
        slots: Vec<B256>,
    ) -> ProviderResult<Vec<B256>>;
}
