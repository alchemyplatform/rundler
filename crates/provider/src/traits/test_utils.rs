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
use rundler_types::{
    v0_6, v0_7, GasFees, UserOpsPerAggregator, ValidationError, ValidationOutput, ValidationRevert,
};

use crate::{
    AggregatorOut, BundleHandler, DepositInfo, EntryPoint, ExecutionResult, HandleOpsOut,
    L1GasProvider, SignatureAggregator, SimulateOpCallData, SimulationProvider,
};

mockall::mock! {
    pub EntryPointV0_6 {}

    #[async_trait::async_trait]
    impl EntryPoint for EntryPointV0_6 {
        fn address(&self) -> Address;
        async fn balance_of(&self, address: Address, block_id: Option<BlockId>)
            -> anyhow::Result<U256>;
        async fn get_deposit_info(&self, address: Address) -> anyhow::Result<DepositInfo>;
        async fn get_balances(&self, addresses: Vec<Address>) -> anyhow::Result<Vec<U256>>;
    }

    #[async_trait::async_trait]
    impl SignatureAggregator for EntryPointV0_6 {
        type UO = v0_6::UserOperation;
        async fn aggregate_signatures(
            &self,
            aggregator_address: Address,
            ops: Vec<v0_6::UserOperation>,
        ) -> anyhow::Result<Option<Bytes>>;
        async fn validate_user_op_signature(
            &self,
            aggregator_address: Address,
            user_op: v0_6::UserOperation,
            gas_cap: u64,
        ) -> anyhow::Result<AggregatorOut>;
    }

    #[async_trait::async_trait]
    impl SimulationProvider for EntryPointV0_6 {
        type UO = v0_6::UserOperation;
        fn get_tracer_simulate_validation_call(
            &self,
            user_op: v0_6::UserOperation,
            max_validation_gas: u64,
        ) -> (TypedTransaction, spoof::State);
        async fn call_simulate_validation(
            &self,
            user_op: v0_6::UserOperation,
            max_validation_gas: u64,
            block_hash: Option<H256>
        ) -> Result<ValidationOutput, ValidationError>;
        fn get_simulate_op_call_data(
            &self,
            op: v0_6::UserOperation,
            spoofed_state: &spoof::State,
        ) -> SimulateOpCallData;
        async fn call_spoofed_simulate_op(
            &self,
            op: v0_6::UserOperation,
            target: Address,
            target_call_data: Bytes,
            block_hash: H256,
            gas: U256,
            spoofed_state: &spoof::State,
        ) -> anyhow::Result<Result<ExecutionResult, ValidationRevert>>;
        fn decode_simulate_handle_ops_revert(
            &self,
            revert_data: Bytes,
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
            gas_price: U256,
        ) -> anyhow::Result<U256>;
    }

    #[async_trait::async_trait]
    impl BundleHandler for EntryPointV0_6 {
        type UO = v0_6::UserOperation;
        async fn call_handle_ops(
            &self,
            ops_per_aggregator: Vec<UserOpsPerAggregator<v0_6::UserOperation>>,
            beneficiary: Address,
            gas: U256,
        ) -> anyhow::Result<HandleOpsOut>;
        fn get_send_bundle_transaction(
            &self,
            ops_per_aggregator: Vec<UserOpsPerAggregator<v0_6::UserOperation>>,
            beneficiary: Address,
            gas: U256,
            gas_fees: GasFees,
        ) -> TypedTransaction;
    }
}

mockall::mock! {
    pub EntryPointV0_7 {}

    #[async_trait::async_trait]
    impl EntryPoint for EntryPointV0_7 {
        fn address(&self) -> Address;
        async fn balance_of(&self, address: Address, block_id: Option<BlockId>)
            -> anyhow::Result<U256>;
        async fn get_deposit_info(&self, address: Address) -> anyhow::Result<DepositInfo>;
        async fn get_balances(&self, addresses: Vec<Address>) -> anyhow::Result<Vec<U256>>;
    }

    #[async_trait::async_trait]
    impl SignatureAggregator for EntryPointV0_7 {
        type UO = v0_7::UserOperation;
        async fn aggregate_signatures(
            &self,
            aggregator_address: Address,
            ops: Vec<v0_7::UserOperation>,
        ) -> anyhow::Result<Option<Bytes>>;
        async fn validate_user_op_signature(
            &self,
            aggregator_address: Address,
            user_op: v0_7::UserOperation,
            gas_cap: u64,
        ) -> anyhow::Result<AggregatorOut>;
    }

    #[async_trait::async_trait]
    impl SimulationProvider for EntryPointV0_7 {
        type UO = v0_7::UserOperation;
        fn get_tracer_simulate_validation_call(
            &self,
            user_op: v0_7::UserOperation,
            max_validation_gas: u64,
        ) -> (TypedTransaction, spoof::State);
        async fn call_simulate_validation(
            &self,
            user_op: v0_7::UserOperation,
            max_validation_gas: u64,
            block_hash: Option<H256>
        ) -> Result<ValidationOutput, ValidationError>;
        fn get_simulate_op_call_data(
            &self,
            op: v0_7::UserOperation,
            spoofed_state: &spoof::State,
        ) -> SimulateOpCallData;
        async fn call_spoofed_simulate_op(
            &self,
            op: v0_7::UserOperation,
            target: Address,
            target_call_data: Bytes,
            block_hash: H256,
            gas: U256,
            spoofed_state: &spoof::State,
        ) -> anyhow::Result<Result<ExecutionResult, ValidationRevert>>;
        fn decode_simulate_handle_ops_revert(
            &self,
            revert_data: Bytes,
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
            gas_price: U256,
        ) -> anyhow::Result<U256>;
    }

    #[async_trait::async_trait]
    impl BundleHandler for EntryPointV0_7 {
        type UO = v0_7::UserOperation;
        async fn call_handle_ops(
            &self,
            ops_per_aggregator: Vec<UserOpsPerAggregator<v0_7::UserOperation>>,
            beneficiary: Address,
            gas: U256,
        ) -> anyhow::Result<HandleOpsOut>;
        fn get_send_bundle_transaction(
            &self,
            ops_per_aggregator: Vec<UserOpsPerAggregator<v0_7::UserOperation>>,
            beneficiary: Address,
            gas: U256,
            gas_fees: GasFees,
        ) -> TypedTransaction;
    }
}
