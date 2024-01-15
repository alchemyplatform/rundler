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

use std::{fmt::Debug, sync::Arc};

use ethers::types::{
    spoof, transaction::eip2718::TypedTransaction, Address, Block, BlockId, BlockNumber, Bytes,
    FeeHistory, Filter, GethDebugTracingCallOptions, GethDebugTracingOptions, GethTrace, Log,
    Transaction, TransactionReceipt, TxHash, H256, U256, U64,
};
#[cfg(feature = "test-utils")]
use mockall::automock;
use rundler_types::UserOperation;
use serde::{de::DeserializeOwned, Serialize};

use super::error::ProviderError;

/// Output of a successful signature aggregator simulation call
#[derive(Clone, Debug, Default)]
pub struct AggregatorSimOut {
    /// Address of the aggregator contract
    pub address: Address,
    /// Aggregated signature
    pub signature: Bytes,
}

/// Result of a signature aggregator call
#[derive(Debug)]
pub enum AggregatorOut {
    /// No aggregator used
    NotNeeded,
    /// Successful call
    SuccessWithInfo(AggregatorSimOut),
    /// Aggregator validation function reverted
    ValidationReverted,
}

/// Result of a provider method call
pub type ProviderResult<T> = Result<T, ProviderError>;

/// Trait for interacting with chain data and contracts.
#[cfg_attr(feature = "test-utils", automock)]
#[async_trait::async_trait]
pub trait Provider: Send + Sync + Debug + 'static {
    /// Make an arbitrary JSON RPC request to the provider
    async fn request<T, R>(&self, method: &str, params: T) -> ProviderResult<R>
    where
        T: Debug + Serialize + Send + Sync + 'static,
        R: Serialize + DeserializeOwned + Debug + Send + 'static;

    /// Get fee history given a number of blocks and reward percentiles
    async fn fee_history<T: Into<U256> + Serialize + Send + Sync + 'static>(
        &self,
        t: T,
        block_number: BlockNumber,
        reward_percentiles: &[f64],
    ) -> Result<FeeHistory, ProviderError>;

    /// Simulate a transaction via an eth_call
    async fn call(
        &self,
        tx: &TypedTransaction,
        block: Option<BlockId>,
        state_overrides: &spoof::State,
    ) -> ProviderResult<Bytes>;

    /// Get the current block number
    async fn get_block_number(&self) -> ProviderResult<u64>;

    /// Get a block by its hash or number
    async fn get_block<T: Into<BlockId> + Send + Sync + 'static>(
        &self,
        block_hash_or_number: T,
    ) -> ProviderResult<Option<Block<H256>>>;

    /// Get the balance of an address
    async fn get_balance(&self, address: Address, block: Option<BlockId>) -> ProviderResult<U256>;

    /// Get transaction by hash
    async fn get_transaction<T: Send + Sync + Into<TxHash> + 'static>(
        &self,
        tx: T,
    ) -> ProviderResult<Option<Transaction>>;

    /// Get transaction receipt by hash
    async fn get_transaction_receipt<T: Send + Sync + Into<TxHash> + 'static>(
        &self,
        transaction_hash: T,
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
        tx: TypedTransaction,
        block_id: Option<BlockId>,
        trace_options: GethDebugTracingCallOptions,
    ) -> ProviderResult<GethTrace>;

    /// Get the latest block hash and number
    async fn get_latest_block_hash_and_number(&self) -> ProviderResult<(H256, U64)>;

    /// Get the base fee per gas of the pending block
    async fn get_base_fee(&self) -> ProviderResult<U256>;

    /// Get the max fee per gas as reported by the node's RPC
    async fn get_max_priority_fee(&self) -> ProviderResult<U256>;

    /// Get the code at an address
    async fn get_code(&self, address: Address, block_hash: Option<H256>) -> ProviderResult<Bytes>;

    /// Get the nonce/transaction count of an address
    async fn get_transaction_count(&self, address: Address) -> ProviderResult<U256>;

    /// Get the logs matching a filter
    async fn get_logs(&self, filter: &Filter) -> ProviderResult<Vec<Log>>;

    /// Call an aggregator to aggregate signatures for a set of operations
    async fn aggregate_signatures(
        self: Arc<Self>,
        aggregator_address: Address,
        ops: Vec<UserOperation>,
    ) -> ProviderResult<Option<Bytes>>;

    /// Validate a user operation signature using an aggregator
    async fn validate_user_op_signature(
        self: Arc<Self>,
        aggregator_address: Address,
        user_op: UserOperation,
        gas_cap: u64,
    ) -> ProviderResult<AggregatorOut>;

    /// Calculate the L1 portion of the gas for a user operation on Arbitrum
    async fn calc_arbitrum_l1_gas(
        self: Arc<Self>,
        entry_point_address: Address,
        op: UserOperation,
    ) -> ProviderResult<U256>;

    /// Calculate the L1 portion of the gas for a user operation on optimism
    async fn calc_optimism_l1_gas(
        self: Arc<Self>,
        entry_point_address: Address,
        op: UserOperation,
        gas_price: U256,
    ) -> ProviderResult<U256>;
}
