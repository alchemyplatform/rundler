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

use alloy_primitives::{Address, Bytes, TxHash, B256, U256};
use alloy_rpc_types_eth::{
    state::StateOverride, BlockId, BlockNumberOrTag, FeeHistory, Filter, Log,
};
use alloy_rpc_types_trace::geth::{
    GethDebugTracingCallOptions, GethDebugTracingOptions, GethTrace,
};
use rundler_contracts::utils::GetGasUsed::GasUsedResult;
use rundler_types::{
    chain::ChainSpec,
    da::{DAGasBlockData, DAGasData},
    v0_6, v0_7, EntryPointVersion, ExpectedStorage, GasFees, UserOpsPerAggregator,
    ValidationOutput, ValidationRevert,
};

use super::error::ProviderResult;
use crate::{
    AggregatorOut, Block, BlockHashOrNumber, BundleHandler, DAGasOracle, DAGasOracleSync,
    DAGasProvider, DepositInfo, EntryPoint, EntryPointProvider, EvmCall,
    EvmProvider as EvmProviderTrait, ExecutionResult, FeeEstimator, HandleOpRevert, HandleOpsOut,
    RevertCheckCallType, RpcRecv, RpcSend, SignatureAggregator, SimulationProvider, Transaction,
    TransactionReceipt, TransactionRequest,
};

mockall::mock! {
    pub EvmProvider {}

    #[async_trait::async_trait]
    impl EvmProviderTrait for EvmProvider {
        async fn request<P, R>(&self, method: &'static str, params: P) -> ProviderResult<R>
        where
            P: RpcSend + 'static,
            R: RpcRecv;

        async fn fee_history(
            &self,
            block_count: u64,
            block_number: BlockNumberOrTag,
            reward_percentiles: &[f64],
        ) -> ProviderResult<FeeHistory>;

        async fn call(
            &self,
            tx: TransactionRequest,
            block: Option<BlockId>,
            state_overrides: Option<StateOverride>,
        ) -> ProviderResult<Bytes>;

        async fn send_raw_transaction(&self, tx: Bytes) -> ProviderResult<TxHash>;

        async fn send_raw_transaction_conditional(
            &self,
            tx: Bytes,
            expected_storage: &ExpectedStorage,
        ) -> ProviderResult<TxHash>;

        async fn get_block_number(&self) -> ProviderResult<u64>;

        async fn get_block(&self, block_id: BlockId) -> ProviderResult<Option<Block>>;

        async fn get_full_block(&self, block_id: BlockId) -> ProviderResult<Option<Block>>;

        async fn get_balance(&self, address: Address, block: Option<BlockId>) -> ProviderResult<U256>;

        async fn get_transaction_by_hash(&self, tx: TxHash) -> ProviderResult<Option<Transaction>>;

        async fn get_transaction_receipt(
            &self,
            tx: TxHash,
        ) -> ProviderResult<Option<TransactionReceipt>>;

        async fn debug_trace_transaction(
            &self,
            tx_hash: TxHash,
            trace_options: GethDebugTracingOptions,
        ) -> ProviderResult<GethTrace>;

        async fn debug_trace_call(
            &self,
            tx: TransactionRequest,
            block_id: Option<BlockId>,
            trace_options: GethDebugTracingCallOptions,
        ) -> ProviderResult<GethTrace>;

        async fn get_latest_block_hash_and_number(&self) -> ProviderResult<(B256, u64)>;
        /// Get the pending block hash and number
        async fn get_pending_block_hash_and_number(&self) -> ProviderResult<(B256, u64)>;

        async fn get_pending_base_fee(&self) -> ProviderResult<u128>;

        async fn get_max_priority_fee(&self) -> ProviderResult<u128>;

        async fn get_code(&self, address: Address, block: Option<BlockId>) -> ProviderResult<Bytes>;

        async fn get_transaction_count(&self, address: Address) -> ProviderResult<u64>;

        async fn get_logs(&self, filter: &Filter) -> ProviderResult<Vec<Log>>;

        async fn get_gas_used(&self, call: EvmCall) -> ProviderResult<GasUsedResult>;

        async fn batch_get_storage_at(
            &self,
            address: Address,
            slots: Vec<B256>,
        ) -> ProviderResult<Vec<B256>>;

        async fn get_code_hash(
            &self,
            addresses: Vec<Address>,
            block: Option<BlockId>,
        ) -> ProviderResult<B256>;

        async fn get_balances(
            &self,
            addresses: Vec<Address>,
        ) -> ProviderResult<Vec<(Address, U256)>>;
    }
}

mockall::mock! {
    pub EntryPointV0_6 {}

    #[async_trait::async_trait]
    impl EntryPoint for EntryPointV0_6 {
        fn version(&self) -> EntryPointVersion;
        fn address(&self) -> &Address;
        async fn balance_of(&self, address: Address, block_id: Option<BlockId>)
            -> ProviderResult<U256>;
        async fn get_deposit_info(&self, address: Address) -> ProviderResult<DepositInfo>;
        async fn get_balances(&self, addresses: Vec<Address>) -> ProviderResult<Vec<U256>>;
    }

    #[async_trait::async_trait]
    impl SignatureAggregator for EntryPointV0_6 {
        type UO = v0_6::UserOperation;
        async fn aggregate_signatures(
            &self,
            aggregator_address: Address,
            ops: Vec<v0_6::UserOperation>,
        ) -> ProviderResult<Option<Bytes>>;
        async fn validate_user_op_signature(
            &self,
            aggregator_address: Address,
            user_op: v0_6::UserOperation,
        ) -> ProviderResult<AggregatorOut>;
    }

    #[async_trait::async_trait]
    impl SimulationProvider for EntryPointV0_6 {
        type UO = v0_6::UserOperation;
        fn get_tracer_simulate_validation_call(
            &self,
            user_op: v0_6::UserOperation,
        ) -> ProviderResult<(TransactionRequest, StateOverride)>;
        async fn simulate_validation(
            &self,
            user_op: v0_6::UserOperation,
            block_id: Option<BlockId>
        ) -> ProviderResult<Result<ValidationOutput, ValidationRevert>>;
        async fn simulate_handle_op(
            &self,
            op: v0_6::UserOperation,
            target: Address,
            target_call_data: Bytes,
            block_id: BlockId,
            state_override: StateOverride,
        ) -> ProviderResult<Result<ExecutionResult, ValidationRevert>>;
        async fn simulate_handle_op_estimate_gas(
            &self,
            op: v0_6::UserOperation,
            target: Address,
            target_call_data: Bytes,
            block_id: BlockId,
            state_override: StateOverride,
        ) -> ProviderResult<Result<ExecutionResult, ValidationRevert>>;
        async fn simulate_handle_op_revert_check(
            &self,
            op: v0_6::UserOperation,
            block_id: BlockId,
            revert_check_call_type: RevertCheckCallType,
        ) -> ProviderResult<Result<u128, HandleOpRevert>>;
        fn decode_simulate_handle_ops_revert(
            revert_data: &Bytes,
        ) -> ProviderResult<Result<ExecutionResult, ValidationRevert>>;
        fn simulation_should_revert(&self) -> bool;
    }

    #[async_trait::async_trait]
    impl DAGasProvider for EntryPointV0_6 {
        type UO = v0_6::UserOperation;
        async fn calc_da_gas(
            &self,
            op: v0_6::UserOperation,
            block: BlockHashOrNumber,
            gas_price: u128,
            bundle_size: usize,
        ) -> ProviderResult<(u128, DAGasData, DAGasBlockData)>;
    }

    #[async_trait::async_trait]
    impl BundleHandler for EntryPointV0_6 {
        type UO = v0_6::UserOperation;
        async fn call_handle_ops(
            &self,
            ops_per_aggregator: Vec<UserOpsPerAggregator<v0_6::UserOperation>>,
            sender_eoa: Address,
            gas_limit: u64,
            gas_fees: GasFees,
            proxy: Option<Address>,
            validation_only: bool,
        ) -> ProviderResult<HandleOpsOut>;
        fn get_send_bundle_transaction(
            &self,
            ops_per_aggregator: Vec<UserOpsPerAggregator<v0_6::UserOperation>>,
            beneficiary: Address,
            gas_limit: u64,
            gas_fees: GasFees,
            proxy: Option<Address>,
        ) -> TransactionRequest;
        fn decode_handle_ops_revert(message: &str, revert_data: &Option<Bytes>) -> Option<HandleOpsOut>;
        fn decode_ops_from_calldata(
            chain_spec: &ChainSpec,
            calldata: &Bytes,
        ) -> Vec<UserOpsPerAggregator<v0_6::UserOperation>>;
    }

    impl EntryPointProvider<v0_6::UserOperation> for EntryPointV0_6 {}
}

mockall::mock! {
    pub EntryPointV0_7 {}

    #[async_trait::async_trait]
    impl EntryPoint for EntryPointV0_7 {
        fn version(&self) -> EntryPointVersion;
        fn address(&self) -> &Address;
        async fn balance_of(&self, address: Address, block_id: Option<BlockId>)
            -> ProviderResult<U256>;
        async fn get_deposit_info(&self, address: Address) -> ProviderResult<DepositInfo>;
        async fn get_balances(&self, addresses: Vec<Address>) -> ProviderResult<Vec<U256>>;
    }

    #[async_trait::async_trait]
    impl SignatureAggregator for EntryPointV0_7 {
        type UO = v0_7::UserOperation;
        async fn aggregate_signatures(
            &self,
            aggregator_address: Address,
            ops: Vec<v0_7::UserOperation>,
        ) -> ProviderResult<Option<Bytes>>;
        async fn validate_user_op_signature(
            &self,
            aggregator_address: Address,
            user_op: v0_7::UserOperation,
        ) -> ProviderResult<AggregatorOut>;
    }

    #[async_trait::async_trait]
    impl SimulationProvider for EntryPointV0_7 {
        type UO = v0_7::UserOperation;
        fn get_tracer_simulate_validation_call(
            &self,
            user_op: v0_7::UserOperation,
        ) -> ProviderResult<(TransactionRequest, StateOverride)>;
        async fn simulate_validation(
            &self,
            user_op: v0_7::UserOperation,
            block_id: Option<BlockId>
        ) -> ProviderResult<Result<ValidationOutput, ValidationRevert>>;
        async fn simulate_handle_op(
            &self,
            op: v0_7::UserOperation,
            target: Address,
            target_call_data: Bytes,
            block_id: BlockId,
            state_override: StateOverride,
        ) -> ProviderResult<Result<ExecutionResult, ValidationRevert>>;
        async fn simulate_handle_op_estimate_gas(
            &self,
            op: v0_7::UserOperation,
            target: Address,
            target_call_data: Bytes,
            block_id: BlockId,
            state_override: StateOverride,
        ) -> ProviderResult<Result<ExecutionResult, ValidationRevert>>;
        async fn simulate_handle_op_revert_check(
            &self,
            op: v0_7::UserOperation,
            block_id: BlockId,
            revert_check_call_type: RevertCheckCallType,
        ) -> ProviderResult<Result<u128, HandleOpRevert>>;
        fn decode_simulate_handle_ops_revert(
            revert_data: &Bytes,
        ) -> ProviderResult<Result<ExecutionResult, ValidationRevert>>;
        fn simulation_should_revert(&self) -> bool;
    }

    #[async_trait::async_trait]
    impl DAGasProvider for EntryPointV0_7 {
        type UO = v0_7::UserOperation;
        async fn calc_da_gas(
            &self,
            op: v0_7::UserOperation,
            block: BlockHashOrNumber,
            gas_price: u128,
            bundle_size: usize,
        ) -> ProviderResult<(u128, DAGasData, DAGasBlockData)>;
    }

    #[async_trait::async_trait]
    impl<'a> BundleHandler for EntryPointV0_7 {
        type UO = v0_7::UserOperation;
        async fn call_handle_ops(
            &self,
            ops_per_aggregator: Vec<UserOpsPerAggregator<v0_7::UserOperation>>,
            sender_eoa: Address,
            gas_limit: u64,
            gas_fees: GasFees,
            proxy: Option<Address>,
            validation_only: bool,
        ) -> ProviderResult<HandleOpsOut>;
        fn get_send_bundle_transaction(
            &self,
            ops_per_aggregator: Vec<UserOpsPerAggregator<v0_7::UserOperation>>,
            beneficiary: Address,
            gas_limit: u64,
            gas_fees: GasFees,
            proxy: Option<Address>,
        ) -> TransactionRequest;
        fn decode_handle_ops_revert(message: &str, revert_data: &Option<Bytes>) -> Option<HandleOpsOut>;
        fn decode_ops_from_calldata(
            chain_spec: &ChainSpec,
            calldata: &Bytes,
        ) -> Vec<UserOpsPerAggregator<v0_7::UserOperation>>;
    }

    impl EntryPointProvider<v0_7::UserOperation> for EntryPointV0_7 {}
}

mockall::mock! {
    pub DAGasOracleSync {}

    #[async_trait::async_trait]
    impl DAGasOracleSync for DAGasOracleSync {
        async fn da_block_data(&self, block: BlockHashOrNumber) -> ProviderResult<DAGasBlockData>;
        async fn da_gas_data(
            &self,
            uo_data: Bytes,
            to: Address,
            block: BlockHashOrNumber,
        ) -> ProviderResult<DAGasData>;
        fn calc_da_gas_sync(
            &self,
            data: &DAGasData,
            block_data: &DAGasBlockData,
            gas_price: u128,
            extra_bytes_len: usize,
        ) -> u128;
    }

    #[async_trait::async_trait]
    impl DAGasOracle for DAGasOracleSync {
        async fn estimate_da_gas(
            &self,
            bytes: Bytes,
            to: Address,
            block: BlockHashOrNumber,
            gas_price: u128,
            extra_data_len: usize,
        ) -> ProviderResult<(u128, DAGasData, DAGasBlockData)>;
    }
}

mockall::mock! {
    pub FeeEstimator {}

    #[async_trait::async_trait]
    impl FeeEstimator for FeeEstimator {
        async fn required_bundle_fees(
            &self,
            block_hash: B256,
            min_fees: Option<GasFees>,
        ) -> anyhow::Result<(GasFees, u128)>;
        async fn latest_bundle_fees(&self) -> anyhow::Result<(GasFees, u128)>;
        fn required_op_fees(&self, bundle_fees: GasFees) -> GasFees;
    }
}
