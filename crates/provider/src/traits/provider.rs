//! Trait for interacting with chain data and contracts.

use std::{fmt::Debug, sync::Arc};

use ethers::{
    providers::ProviderError,
    types::{
        transaction::eip2718::TypedTransaction, Address, Block, BlockId, Bytes, Filter,
        GethDebugTracingCallOptions, GethDebugTracingOptions, GethTrace, Log, Transaction,
        TransactionReceipt, TxHash, H256, U256,
    },
};
#[cfg(feature = "test-utils")]
use mockall::automock;
use rundler_types::UserOperation;
use serde::{de::DeserializeOwned, Serialize};

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

/// Trait for interacting with chain data and contracts.
#[cfg_attr(feature = "test-utils", automock)]
#[async_trait::async_trait]
pub trait Provider: Send + Sync + 'static {
    /// Make an arbitrary JSON RPC request to the provider
    async fn request<T, R>(&self, method: &str, params: T) -> Result<R, ProviderError>
    where
        T: Debug + Serialize + Send + Sync + 'static,
        R: Serialize + DeserializeOwned + Debug + Send + 'static;

    /// Simulate a transaction via an eth_call
    async fn call(
        &self,
        tx: &TypedTransaction,
        block: Option<BlockId>,
    ) -> Result<Bytes, ProviderError>;

    /// Get the current block number
    async fn get_block_number(&self) -> anyhow::Result<u64>;

    /// Get a block by its hash or number
    async fn get_block<T: Into<BlockId> + Send + Sync + 'static>(
        &self,
        block_hash_or_number: T,
    ) -> anyhow::Result<Option<Block<H256>>>;

    /// Get the balance of an address
    async fn get_balance(&self, address: Address, block: Option<BlockId>) -> anyhow::Result<U256>;

    /// Get transaction by hash
    async fn get_transaction<T: Send + Sync + Into<TxHash> + 'static>(
        &self,
        tx: T,
    ) -> Result<Option<Transaction>, ProviderError>;

    /// Get transaction receipt by hash
    async fn get_transaction_receipt<T: Send + Sync + Into<TxHash> + 'static>(
        &self,
        transaction_hash: T,
    ) -> Result<Option<TransactionReceipt>, ProviderError>;

    /// Debug trace a transaction
    async fn debug_trace_transaction(
        &self,
        tx_hash: TxHash,
        trace_options: GethDebugTracingOptions,
    ) -> Result<GethTrace, ProviderError>;

    /// Debug trace a call
    async fn debug_trace_call(
        &self,
        tx: TypedTransaction,
        block_id: Option<BlockId>,
        trace_options: GethDebugTracingCallOptions,
    ) -> Result<GethTrace, ProviderError>;

    /// Get the latest block hash
    async fn get_latest_block_hash(&self) -> anyhow::Result<H256>;

    /// Get the base fee per gas of the pending block
    async fn get_base_fee(&self) -> anyhow::Result<U256>;

    /// Get the max fee per gas as reported by the node's RPC
    async fn get_max_priority_fee(&self) -> anyhow::Result<U256>;

    /// Get the code at an address
    async fn get_code(&self, address: Address, block_hash: Option<H256>) -> anyhow::Result<Bytes>;

    /// Get the nonce/transaction count of an address
    async fn get_transaction_count(&self, address: Address) -> anyhow::Result<U256>;

    /// Get the logs matching a filter
    async fn get_logs(&self, filter: &Filter) -> anyhow::Result<Vec<Log>>;

    /// Call an aggregator to aggregate signatures for a set of operations
    async fn aggregate_signatures(
        self: Arc<Self>,
        aggregator_address: Address,
        ops: Vec<UserOperation>,
    ) -> anyhow::Result<Option<Bytes>>;

    /// Validate a user operation signature using an aggregator
    async fn validate_user_op_signature(
        self: Arc<Self>,
        aggregator_address: Address,
        user_op: UserOperation,
        gas_cap: u64,
    ) -> anyhow::Result<AggregatorOut>;

    /// Calculate the L1 portion of the gas for a user operation on Arbitrum
    async fn calc_arbitrum_l1_gas(
        self: Arc<Self>,
        entry_point_address: Address,
        op: UserOperation,
    ) -> anyhow::Result<U256>;

    /// Calculate the L1 portion of the gas for a user operation on optimism
    async fn calc_optimism_l1_gas(
        self: Arc<Self>,
        entry_point_address: Address,
        op: UserOperation,
    ) -> anyhow::Result<U256>;
}
