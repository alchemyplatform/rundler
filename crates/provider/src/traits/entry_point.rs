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
use rundler_types::{GasFees, Timestamp, UserOperation, UserOpsPerAggregator, ValidationOutput};

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

/// Deposit info for an address from the entry point contract
#[derive(Clone, Debug, Default)]
pub struct DepositInfo {
    /// Amount deposited on the entry point
    pub deposit: U256,
    /// Whether the address has staked
    pub staked: bool,
    /// Amount staked on the entry point
    pub stake: u128,
    /// The amount of time in sections that must pass before the stake can be withdrawn
    pub unstake_delay_sec: u32,
    /// The time at which the stake can be withdrawn
    pub withdraw_time: u64,
}

/// Result of an execution
#[derive(Clone, Debug, Default)]
pub struct ExecutionResult {
    /// Gas used before the operation execution
    pub pre_op_gas: U256,
    /// Amount paid by the operation
    pub paid: U256,
    /// Time which the operation is valid after
    pub valid_after: Timestamp,
    /// Time which the operation is valid until
    pub valid_until: Timestamp,
    /// True if the operation execution succeeded
    pub target_success: bool,
    /// Result of the operation execution
    pub target_result: Bytes,
}

/// Trait for interacting with an entry point contract.
#[async_trait::async_trait]
#[auto_impl::auto_impl(&, Arc)]
pub trait EntryPoint: Send + Sync + 'static {
    /// Get the address of the entry point contract
    fn address(&self) -> Address;

    /// Get the balance of an address
    async fn balance_of(&self, address: Address, block_id: Option<BlockId>)
        -> anyhow::Result<U256>;

    /// Get the deposit info for an address
    async fn get_deposit_info(&self, address: Address) -> anyhow::Result<DepositInfo>;

    /// Get the balances of a list of addresses in order
    async fn get_balances(&self, addresses: Vec<Address>) -> anyhow::Result<Vec<U256>>;
}

/// Trait for handling signature aggregators
#[async_trait::async_trait]
#[auto_impl::auto_impl(&, Arc)]
pub trait SignatureAggregator: Send + Sync + 'static {
    /// The type of user operation used by this entry point
    type UO: UserOperation;

    /// Call an aggregator to aggregate signatures for a set of operations
    async fn aggregate_signatures(
        &self,
        aggregator_address: Address,
        ops: Vec<Self::UO>,
    ) -> anyhow::Result<Option<Bytes>>;

    /// Validate a user operation signature using an aggregator
    async fn validate_user_op_signature(
        &self,
        aggregator_address: Address,
        user_op: Self::UO,
        gas_cap: u64,
    ) -> anyhow::Result<AggregatorOut>;
}

/// Trait for submitting bundles of operations to an entry point contract
#[async_trait::async_trait]
#[auto_impl::auto_impl(&, Arc)]
pub trait BundleHandler: Send + Sync + 'static {
    /// The type of user operation used by this entry point
    type UO: UserOperation;

    /// Call the entry point contract's `handleOps` function
    async fn call_handle_ops(
        &self,
        ops_per_aggregator: Vec<UserOpsPerAggregator<Self::UO>>,
        beneficiary: Address,
        gas: U256,
    ) -> anyhow::Result<HandleOpsOut>;

    /// Construct the transaction to send a bundle of operations to the entry point contract
    fn get_send_bundle_transaction(
        &self,
        ops_per_aggregator: Vec<UserOpsPerAggregator<Self::UO>>,
        beneficiary: Address,
        gas: U256,
        gas_fees: GasFees,
    ) -> TypedTransaction;
}

/// Trait for calculating L1 gas costs for user operations
///
/// Used for L2 gas estimation
#[async_trait::async_trait]
#[auto_impl::auto_impl(&, Arc)]
pub trait L1GasProvider: Send + Sync + 'static {
    /// The type of user operation used by this entry point
    type UO: UserOperation;

    /// Calculate the L1 portion of the gas for a user operation on Arbitrum
    async fn calc_arbitrum_l1_gas(
        &self,
        entry_point_address: Address,
        op: Self::UO,
    ) -> anyhow::Result<U256>;

    /// Calculate the L1 portion of the gas for a user operation on optimism
    async fn calc_optimism_l1_gas(
        &self,
        entry_point_address: Address,
        op: Self::UO,
        gas_price: U256,
    ) -> anyhow::Result<U256>;
}

/// Trait for simulating user operations on an entry point contract
#[async_trait::async_trait]
#[auto_impl::auto_impl(&, Arc)]
pub trait SimulationProvider: Send + Sync + 'static {
    /// The type of user operation used by this entry point
    type UO: UserOperation;

    /// Construct a call for the entry point contract's `simulateValidation` function
    fn get_tracer_simulate_validation_call(
        &self,
        user_op: Self::UO,
        max_validation_gas: u64,
    ) -> (TypedTransaction, spoof::State);

    /// Call the entry point contract's `simulateValidation` function.
    async fn call_simulate_validation(
        &self,
        user_op: Self::UO,
        max_validation_gas: u64,
        block_hash: Option<H256>,
    ) -> anyhow::Result<ValidationOutput>;

    /// Call the entry point contract's `simulateHandleOps` function
    /// with a spoofed state
    async fn call_spoofed_simulate_op(
        &self,
        op: Self::UO,
        target: Address,
        target_call_data: Bytes,
        block_hash: H256,
        gas: U256,
        spoofed_state: &spoof::State,
    ) -> anyhow::Result<Result<ExecutionResult, String>>;

    /// Decode the revert data from a call to `simulateHandleOps`
    fn decode_simulate_handle_ops_revert(
        &self,
        revert_data: Bytes,
    ) -> Result<ExecutionResult, String>;
}

/// Trait for a provider that provides all entry point functionality
pub trait EntryPointProvider<UO>:
    EntryPoint
    + SignatureAggregator<UO = UO>
    + BundleHandler<UO = UO>
    + SimulationProvider<UO = UO>
    + L1GasProvider<UO = UO>
{
}
