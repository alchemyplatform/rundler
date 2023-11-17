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

use ethers::types::{
    spoof, transaction::eip2718::TypedTransaction, Address, BlockId, Bytes, H256, U256,
};
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
    /// Call failed due to a bug in the 0.6 entry point contract https://github.com/eth-infinitism/account-abstraction/pull/325.
    /// Special handling is required to remove the offending operation from the bundle.
    PostOpRevert,
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
    async fn balance_of(&self, address: Address, block_id: Option<BlockId>)
        -> anyhow::Result<U256>;

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
