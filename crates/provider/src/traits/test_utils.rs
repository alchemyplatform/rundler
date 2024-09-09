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
use alloy_rpc_types_eth::{state::StateOverride, BlockId, TransactionRequest};
use rundler_types::{
    v0_6, v0_7, GasFees, UserOpsPerAggregator, ValidationOutput, ValidationRevert,
};

use crate::{
    AggregatorOut, BundleHandler, DepositInfo, EntryPoint, ExecutionResult, HandleOpsOut,
    L1GasProvider, ProviderResult, SignatureAggregator, SimulationProvider,
};

mockall::mock! {
    pub EntryPointV0_6 {}

    #[async_trait::async_trait]
    impl EntryPoint for EntryPointV0_6 {
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
            gas_cap: u128,
        ) -> ProviderResult<AggregatorOut>;
    }

    #[async_trait::async_trait]
    impl SimulationProvider for EntryPointV0_6 {
        type UO = v0_6::UserOperation;
        fn get_tracer_simulate_validation_call(
            &self,
            user_op: v0_6::UserOperation,
            max_validation_gas: u128,
        ) -> ProviderResult<(TransactionRequest, StateOverride)>;
        async fn simulate_validation(
            &self,
            user_op: v0_6::UserOperation,
            max_validation_gas: u128,
            block_id: Option<BlockId>
        ) -> ProviderResult<Result<ValidationOutput, ValidationRevert>>;
        fn get_simulate_handle_op_call(
            &self,
            op: v0_6::UserOperation,
            state_override: StateOverride,
        ) -> crate::EvmCall;
        async fn simulate_handle_op(
            &self,
            op: v0_6::UserOperation,
            target: Address,
            target_call_data: Bytes,
            block_id: BlockId,
            gas: u128,
            state_override: StateOverride,
        ) -> ProviderResult<Result<ExecutionResult, ValidationRevert>>;
        fn decode_simulate_handle_ops_revert(
            revert_data: alloy_json_rpc::ErrorPayload,
        ) -> Result<ExecutionResult, ValidationRevert>;
        fn simulation_should_revert(&self) -> bool;
    }

    #[async_trait::async_trait]
    impl L1GasProvider for EntryPointV0_6 {
        type UO = v0_6::UserOperation;
        async fn calc_l1_gas(
            &self,
            entry_point_address: Address,
            op: v0_6::UserOperation,
            gas_price: u128,
        ) -> ProviderResult<u128>;
    }

    #[async_trait::async_trait]
    impl BundleHandler for EntryPointV0_6 {
        type UO = v0_6::UserOperation;
        async fn call_handle_ops(
            &self,
            ops_per_aggregator: Vec<UserOpsPerAggregator<v0_6::UserOperation>>,
            beneficiary: Address,
            gas: u128,
        ) -> ProviderResult<HandleOpsOut>;
        fn get_send_bundle_transaction(
            &self,
            ops_per_aggregator: Vec<UserOpsPerAggregator<v0_6::UserOperation>>,
            beneficiary: Address,
            gas: u128,
            gas_fees: GasFees,
        ) -> TransactionRequest;
    }
}

mockall::mock! {
    pub EntryPointV0_7 {}

    #[async_trait::async_trait]
    impl EntryPoint for EntryPointV0_7 {
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
            gas_cap: u128,
        ) -> ProviderResult<AggregatorOut>;
    }

    #[async_trait::async_trait]
    impl SimulationProvider for EntryPointV0_7 {
        type UO = v0_7::UserOperation;
        fn get_tracer_simulate_validation_call(
            &self,
            user_op: v0_7::UserOperation,
            max_validation_gas: u128,
        ) -> ProviderResult<(TransactionRequest, StateOverride)>;
        async fn simulate_validation(
            &self,
            user_op: v0_7::UserOperation,
            max_validation_gas: u128,
            block_id: Option<BlockId>
        ) -> ProviderResult<Result<ValidationOutput, ValidationRevert>>;
        fn get_simulate_handle_op_call(
            &self,
            op: v0_7::UserOperation,
            state_override: StateOverride,
        ) -> crate::EvmCall;
        async fn simulate_handle_op(
            &self,
            op: v0_7::UserOperation,
            target: Address,
            target_call_data: Bytes,
            block_id: BlockId,
            gas: u128,
            state_override: StateOverride,
        ) -> ProviderResult<Result<ExecutionResult, ValidationRevert>>;
        fn decode_simulate_handle_ops_revert(
            revert_data: alloy_json_rpc::ErrorPayload,
        ) -> Result<ExecutionResult, ValidationRevert>;
        fn simulation_should_revert(&self) -> bool;
    }

    #[async_trait::async_trait]
    impl L1GasProvider for EntryPointV0_7 {
        type UO = v0_7::UserOperation;
        async fn calc_l1_gas(
            &self,
            entry_point_address: Address,
            op: v0_7::UserOperation,
            gas_price: u128,
        ) -> ProviderResult<u128>;
    }

    #[async_trait::async_trait]
    impl BundleHandler for EntryPointV0_7 {
        type UO = v0_7::UserOperation;
        async fn call_handle_ops(
            &self,
            ops_per_aggregator: Vec<UserOpsPerAggregator<v0_7::UserOperation>>,
            beneficiary: Address,
            gas: u128,
        ) -> ProviderResult<HandleOpsOut>;
        fn get_send_bundle_transaction(
            &self,
            ops_per_aggregator: Vec<UserOpsPerAggregator<v0_7::UserOperation>>,
            beneficiary: Address,
            gas: u128,
            gas_fees: GasFees,
        ) -> TransactionRequest;
    }
}
