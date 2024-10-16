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

use alloy_primitives::{Address, Bytes, U256};
use rundler_types::{
    da::{DAGasBlockData, DAGasUOData},
    GasFees, Timestamp, UserOperation, UserOpsPerAggregator, ValidationOutput, ValidationRevert,
};

use crate::{
    BlockHashOrNumber, BlockId, EvmCall, ProviderResult, StateOverride, TransactionRequest,
};

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
    pub stake: U256,
    /// The amount of time in sections that must pass before the stake can be withdrawn
    pub unstake_delay_sec: u32,
    /// The time at which the stake can be withdrawn
    pub withdraw_time: u64,
}

/// Result of an execution
#[derive(Clone, Debug, Default)]
pub struct ExecutionResult {
    /// Gas used before the operation execution
    pub pre_op_gas: u128,
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
#[auto_impl::auto_impl(&, &mut, Rc, Arc, Box)]
pub trait EntryPoint: Send + Sync {
    /// Get the address of the entry point contract
    fn address(&self) -> &Address;

    /// Get the balance of an address
    async fn balance_of(&self, address: Address, block_id: Option<BlockId>)
        -> ProviderResult<U256>;

    /// Get the deposit info for an address
    async fn get_deposit_info(&self, address: Address) -> ProviderResult<DepositInfo>;

    /// Get the balances of a list of addresses in order
    async fn get_balances(&self, addresses: Vec<Address>) -> ProviderResult<Vec<U256>>;
}

/// Trait for handling signature aggregators
#[async_trait::async_trait]
#[auto_impl::auto_impl(&, &mut, Rc, Arc, Box)]
pub trait SignatureAggregator: Send + Sync {
    /// The type of user operation used by this entry point
    type UO: UserOperation;

    /// Call an aggregator to aggregate signatures for a set of operations
    async fn aggregate_signatures(
        &self,
        aggregator_address: Address,
        ops: Vec<Self::UO>,
    ) -> ProviderResult<Option<Bytes>>;

    /// Validate a user operation signature using an aggregator
    async fn validate_user_op_signature(
        &self,
        aggregator_address: Address,
        user_op: Self::UO,
    ) -> ProviderResult<AggregatorOut>;
}

/// Trait for submitting bundles of operations to an entry point contract
#[async_trait::async_trait]
#[auto_impl::auto_impl(&, &mut, Rc, Arc, Box)]
pub trait BundleHandler: Send + Sync {
    /// The type of user operation used by this entry point
    type UO: UserOperation;

    /// Call the entry point contract's `handleOps` function
    ///
    /// If `gas_limit` is `None`, the maximum gas limit is used.
    async fn call_handle_ops(
        &self,
        ops_per_aggregator: Vec<UserOpsPerAggregator<Self::UO>>,
        beneficiary: Address,
        gas_limit: Option<u64>,
    ) -> ProviderResult<HandleOpsOut>;

    /// Construct the transaction to send a bundle of operations to the entry point contract
    fn get_send_bundle_transaction(
        &self,
        ops_per_aggregator: Vec<UserOpsPerAggregator<Self::UO>>,
        beneficiary: Address,
        gas_limit: u64,
        gas_fees: GasFees,
    ) -> TransactionRequest;
}

/// Trait for calculating Data Availability (DA) gas costs for user operations
///
/// Used for L2+ gas estimation
#[async_trait::async_trait]
#[auto_impl::auto_impl(&, &mut, Rc, Arc, Box)]
pub trait DAGasProvider: Send + Sync {
    /// The type of user operation used by this entry point
    type UO: UserOperation;

    /// Calculate the DA portion of the gas for a user operation
    ///
    /// Returns the da gas plus any calculated DAGasUOData and DAGasBlockData.
    /// These values can be cached and re-used if the same UO is used for multiple calls within
    /// a small time period (no hard forks impacting DA calculations).
    ///
    /// Returns zero for operations that do not require DA gas.
    async fn calc_da_gas(
        &self,
        uo: Self::UO,
        block: BlockHashOrNumber,
        gas_price: u128,
    ) -> ProviderResult<(u128, DAGasUOData, DAGasBlockData)>;
}

/// Trait for simulating user operations on an entry point contract
#[async_trait::async_trait]
#[auto_impl::auto_impl(&, &mut, Rc, Arc, Box)]
pub trait SimulationProvider: Send + Sync {
    /// The type of user operation used by this entry point
    type UO: UserOperation;

    /// Construct a call for the entry point contract's `simulateValidation` function
    fn get_tracer_simulate_validation_call(
        &self,
        user_op: Self::UO,
    ) -> ProviderResult<(TransactionRequest, StateOverride)>;

    /// Call the entry point contract's `simulateValidation` function.
    async fn simulate_validation(
        &self,
        user_op: Self::UO,
        block_id: Option<BlockId>,
    ) -> ProviderResult<Result<ValidationOutput, ValidationRevert>>;

    /// Get call data and state overrides needed to call `simulateHandleOp`
    fn get_simulate_handle_op_call(&self, op: Self::UO, state_override: StateOverride) -> EvmCall;

    /// Call the entry point contract's `simulateHandleOp` function
    /// with a spoofed state
    async fn simulate_handle_op(
        &self,
        op: Self::UO,
        target: Address,
        target_call_data: Bytes,
        block_id: BlockId,
        state_override: StateOverride,
    ) -> ProviderResult<Result<ExecutionResult, ValidationRevert>>;

    /// Decode the revert data from a call to `simulateHandleOps`
    fn decode_simulate_handle_ops_revert(
        revert_data: &Bytes,
    ) -> ProviderResult<Result<ExecutionResult, ValidationRevert>>;

    /// Returns true if this entry point uses reverts to communicate simulation
    /// results.
    fn simulation_should_revert(&self) -> bool;
}

/// Trait for a provider that provides all entry point functionality
#[auto_impl::auto_impl(&, &mut, Rc, Arc, Box)]
pub trait EntryPointProvider<UO>:
    EntryPoint
    + SignatureAggregator<UO = UO>
    + BundleHandler<UO = UO>
    + SimulationProvider<UO = UO>
    + DAGasProvider<UO = UO>
{
}
