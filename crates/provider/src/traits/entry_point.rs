use ethers::types::{spoof, transaction::eip2718::TypedTransaction, Address, Bytes, H256, U256};
#[cfg(feature = "test-utils")]
use mockall::automock;
use rundler_types::{
    contracts::{i_entry_point::ExecutionResult, shared_types::UserOpsPerAggregator},
    GasFees, UserOperation,
};

/// Result of an entry point handle ops call
#[derive(Clone, Debug)]
pub enum HandleOpsOut {
    /// Call succeeded
    Success,
    /// Call failed due to a failed operation at index `usize` with reason `String`
    FailedOp(usize, String),
    /// Call failed due to a signature validation failure
    SignatureValidationFailed(Address),
}

/// Trait for interacting with an entry point contract.
/// Implemented for the v0.6 version of the entry point contract.
/// [Contracts can be found here](https://github.com/eth-infinitism/account-abstraction/tree/v0.6.0).
#[cfg_attr(feature = "test-utils", automock)]
#[async_trait::async_trait]
pub trait EntryPoint: Send + Sync + 'static {
    /// Get the address of the entry point contract
    fn address(&self) -> Address;

    /// Call the entry point contract's `handleOps` function
    async fn call_handle_ops(
        &self,
        ops_per_aggregator: Vec<UserOpsPerAggregator>,
        beneficiary: Address,
        gas: U256,
    ) -> anyhow::Result<HandleOpsOut>;

    /// Get the balance of an address
    async fn balance_of(&self, address: Address) -> anyhow::Result<U256>;

    /// Get the deposit value of an address on the entry point contract
    async fn get_deposit(&self, address: Address, block_hash: H256) -> anyhow::Result<U256>;

    /// Call the entry point contract's `simulateValidation` function
    async fn simulate_validation(
        &self,
        user_op: UserOperation,
        max_validation_gas: u64,
    ) -> anyhow::Result<TypedTransaction>;

    /// Call the entry point contract's `simulateHandleOps` function
    /// with a spoofed state
    async fn call_spoofed_simulate_op(
        &self,
        op: UserOperation,
        target: Address,
        target_call_data: Bytes,
        block_hash: H256,
        gas: U256,
        spoofed_state: &spoof::State,
    ) -> anyhow::Result<Result<ExecutionResult, String>>;

    /// Construct the transaction to send a bundle of operations to the entry point contract
    fn get_send_bundle_transaction(
        &self,
        ops_per_aggregator: Vec<UserOpsPerAggregator>,
        beneficiary: Address,
        gas: U256,
        gas_fees: GasFees,
    ) -> TypedTransaction;

    /// Decode the revert data from a call to `simulateHandleOps`
    fn decode_simulate_handle_ops_revert(
        &self,
        revert_data: Bytes,
    ) -> Result<ExecutionResult, String>;
}
