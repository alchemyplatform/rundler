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

use std::marker::PhantomData;

use alloy_json_rpc::{RpcParam, RpcReturn};
use alloy_primitives::{Address, Bytes, TxHash, B256, U256};
use alloy_provider::{ext::DebugApi, network::TransactionBuilder, Provider as AlloyProvider};
use alloy_rpc_types_eth::{
    state::{AccountOverride, StateOverride},
    Block, BlockId, BlockNumberOrTag, BlockTransactionsKind, FeeHistory, Filter, Log, Transaction,
    TransactionReceipt, TransactionRequest,
};
use alloy_rpc_types_trace::geth::{
    GethDebugTracingCallOptions, GethDebugTracingOptions, GethTrace,
};
use alloy_transport::Transport;
use anyhow::Context;
use rundler_contracts::utils::{
    GetCodeHashes::{self, GetCodeHashesInstance},
    GetGasUsed::{self, GasUsedResult},
    StorageLoader,
};

use crate::{EvmCall, EvmProvider, ProviderResult};

/// Evm Provider implementation using [alloy-provider](https://github.com/alloy-rs/alloy-rs)
pub struct AlloyEvmProvider<AP, T> {
    inner: AP,
    _marker: PhantomData<T>,
}

impl<AP, T> AlloyEvmProvider<AP, T> {
    /// Create a new `AlloyEvmProvider`
    pub fn new(inner: AP) -> Self {
        Self {
            inner,
            _marker: PhantomData,
        }
    }
}

impl<AP, T> Clone for AlloyEvmProvider<AP, T>
where
    AP: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            _marker: PhantomData,
        }
    }
}

impl<AP, T> From<AP> for AlloyEvmProvider<AP, T>
where
    T: Transport + Clone,
    AP: AlloyProvider<T>,
{
    fn from(inner: AP) -> Self {
        Self::new(inner)
    }
}

#[async_trait::async_trait]
impl<AP, T> EvmProvider for AlloyEvmProvider<AP, T>
where
    T: Transport + Clone,
    AP: AlloyProvider<T>,
{
    async fn request<P, R>(&self, method: &'static str, params: P) -> ProviderResult<R>
    where
        P: RpcParam + 'static,
        R: RpcReturn,
    {
        Ok(self.inner.raw_request(method.into(), params).await?)
    }

    async fn fee_history(
        &self,
        block_count: u64,
        block_number: BlockNumberOrTag,
        reward_percentiles: &[f64],
    ) -> ProviderResult<FeeHistory> {
        Ok(self
            .inner
            .get_fee_history(block_count, block_number, reward_percentiles)
            .await?)
    }

    async fn call(
        &self,
        tx: &TransactionRequest,
        block: Option<BlockId>,
        state_overrides: &StateOverride,
    ) -> ProviderResult<Bytes> {
        let mut call = self.inner.call(tx);
        if let Some(block) = block {
            call = call.block(block);
        }
        call = call.overrides(state_overrides);

        Ok(call.await?)
    }

    async fn get_block_number(&self) -> ProviderResult<u64> {
        Ok(self.inner.get_block_number().await?)
    }

    async fn get_block(&self, block_id: BlockId) -> ProviderResult<Option<Block>> {
        Ok(self
            .inner
            .get_block(block_id, BlockTransactionsKind::Hashes)
            .await?)
    }

    async fn get_balance(&self, address: Address, block: Option<BlockId>) -> ProviderResult<U256> {
        let mut call = self.inner.get_balance(address);
        if let Some(block) = block {
            call = call.block_id(block);
        }

        Ok(call.await?)
    }

    async fn get_transaction_by_hash(&self, tx: TxHash) -> ProviderResult<Option<Transaction>> {
        Ok(self.inner.get_transaction_by_hash(tx).await?)
    }

    async fn get_transaction_receipt(
        &self,
        tx: TxHash,
    ) -> ProviderResult<Option<TransactionReceipt>> {
        Ok(self.inner.get_transaction_receipt(tx).await?)
    }

    async fn get_latest_block_hash_and_number(&self) -> ProviderResult<(B256, u64)> {
        let latest_block = EvmProvider::get_block(self, BlockId::latest())
            .await?
            .context("latest block should exist")?;
        Ok((latest_block.header.hash, latest_block.header.number))
    }

    async fn get_pending_base_fee(&self) -> ProviderResult<u128> {
        let fee_history = self.fee_history(1, BlockNumberOrTag::Latest, &[]).await?;
        Ok(fee_history
            .next_block_base_fee()
            .context("should have a next block base fee")?)
    }

    async fn get_max_priority_fee(&self) -> ProviderResult<u128> {
        Ok(self.inner.get_max_priority_fee_per_gas().await?)
    }

    async fn get_code(&self, address: Address, block: Option<BlockId>) -> ProviderResult<Bytes> {
        let mut call = self.inner.get_code_at(address);
        if let Some(block) = block {
            call = call.block_id(block);
        }

        Ok(call.await?)
    }

    async fn get_transaction_count(&self, address: Address) -> ProviderResult<u64> {
        Ok(self.inner.get_transaction_count(address).await?)
    }

    async fn get_logs(&self, filter: &Filter) -> ProviderResult<Vec<Log>> {
        Ok(self.inner.get_logs(filter).await?)
    }

    async fn debug_trace_transaction(
        &self,
        tx_hash: TxHash,
        trace_options: GethDebugTracingOptions,
    ) -> ProviderResult<GethTrace> {
        Ok(self
            .inner
            .debug_trace_transaction(tx_hash, trace_options)
            .await?)
    }

    async fn debug_trace_call(
        &self,
        tx: TransactionRequest,
        block_id: Option<BlockId>,
        trace_options: GethDebugTracingCallOptions,
    ) -> ProviderResult<GethTrace> {
        let call = if let Some(block_id) = block_id {
            self.inner.debug_trace_call(tx, block_id, trace_options)
        } else {
            self.inner
                .debug_trace_call(tx, BlockNumberOrTag::Latest.into(), trace_options)
        };

        Ok(call.await?)
    }

    async fn get_gas_used(&self, call: EvmCall) -> ProviderResult<GasUsedResult> {
        let EvmCall {
            to,
            value,
            data,
            mut state_override,
        } = call;

        let helper_addr = Address::random();
        let helper = GetGasUsed::new(helper_addr, &self.inner);

        let account = AccountOverride {
            code: Some(GetGasUsed::DEPLOYED_BYTECODE.clone()),
            ..Default::default()
        };
        state_override.insert(helper_addr, account);

        let ret = helper
            .getGas(to, value, data)
            .state(state_override)
            .call()
            .await?
            ._0;

        Ok(ret)
    }

    async fn batch_get_storage_at(
        &self,
        address: Address,
        slots: Vec<B256>,
    ) -> ProviderResult<Vec<B256>> {
        let mut overrides = StateOverride::default();
        let account = AccountOverride {
            code: Some(StorageLoader::DEPLOYED_BYTECODE.clone()),
            ..Default::default()
        };
        overrides.insert(address, account);

        let expected_ret_size = slots.len() * 32;
        let slot_data = slots
            .into_iter()
            .flat_map(|slot| slot.0)
            .collect::<Vec<_>>();

        let tx = TransactionRequest::default()
            .to(address)
            .with_input(slot_data);

        let result_bytes = self.inner.call(&tx).overrides(&overrides).await?;

        if result_bytes.len() != expected_ret_size {
            return Err(anyhow::anyhow!(
                "expected {} bytes, got {}",
                expected_ret_size,
                result_bytes.len()
            )
            .into());
        }

        Ok(result_bytes
            .chunks(32)
            .map(B256::try_from)
            .collect::<Result<Vec<_>, _>>()
            .unwrap())
    }

    async fn get_code_hash(
        &self,
        mut addresses: Vec<Address>,
        block: Option<BlockId>,
    ) -> ProviderResult<B256> {
        let helper_addr = Address::random();
        let helper = GetCodeHashesInstance::new(helper_addr, &self.inner);

        let mut overrides = StateOverride::default();
        let account = AccountOverride {
            code: Some(GetCodeHashes::DEPLOYED_BYTECODE.clone()),
            ..Default::default()
        };
        overrides.insert(helper_addr, account);

        addresses.sort();
        let mut call = helper.getCodeHashes(addresses).state(overrides);
        if let Some(block) = block {
            call = call.block(block);
        }

        let ret = call.call().await?;
        Ok(ret.hash)
    }
}

#[cfg(test)]
mod tests {
    use alloy_provider::ProviderBuilder;
    use alloy_sol_macro::sol;

    use crate::{AlloyEvmProvider, EvmProvider};

    sol!(
        #[allow(missing_docs)]
        #[sol(rpc, bytecode="0x6080604052348015600f57600080fd5b506064431060635760405162461bcd60e51b815260206004820152601660248201527f73686f756c64206e6f74206265206465706c6f79656400000000000000000000604482015260640160405180910390fd5b6102b8806100726000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c80637b34b62114610030575b600080fd5b61004361003e366004610159565b610055565b60405190815260200160405180910390f35b600080825167ffffffffffffffff81111561007257610072610127565b60405190808252806020026020018201604052801561009b578160200160208202803683370190505b50905060005b83518110156100f3578381815181106100bc576100bc610229565b60200260200101516001600160a01b03163f8282815181106100e0576100e0610229565b60209081029190910101526001016100a1565b50600081604051602001610107919061023f565b60408051601f198184030181529190528051602090910120949350505050565b634e487b7160e01b600052604160045260246000fd5b80356001600160a01b038116811461015457600080fd5b919050565b60006020828403121561016b57600080fd5b813567ffffffffffffffff81111561018257600080fd5b8201601f8101841361019357600080fd5b803567ffffffffffffffff8111156101ad576101ad610127565b8060051b604051601f19603f830116810181811067ffffffffffffffff821117156101da576101da610127565b6040529182526020818401810192908101878411156101f857600080fd5b6020850194505b8385101561021e576102108561013d565b8152602094850194016101ff565b509695505050505050565b634e487b7160e01b600052603260045260246000fd5b602080825282518282018190526000918401906040840190835b81811015610277578351835260209384019390920191600101610259565b50909594505050505056fea2646970667358221220b2b7c1db7d478df6ecb5a14ec979bf9abb43dd1f7b85388b1c502bf5099282d264736f6c634300081a0033")]
        contract GetCodeHashes {

            constructor() {
                require(block.number < 100, "should not be deployed");
            }

            function getCodeHashes(
                address[] memory addresses
            ) public view returns (bytes32 hash) {
                bytes32[] memory hashes = new bytes32[](addresses.length);
                for (uint i = 0; i < addresses.length; i++) {
                    hashes[i] = addresses[i].codehash;
                }
                bytes memory data = abi.encode(hashes);
                return keccak256(data);
            }
        }
    );

    sol!(
        #[allow(missing_docs)]
        #[sol(rpc, bytecode="0x6080604052348015600f57600080fd5b506064431060635760405162461bcd60e51b815260206004820152601660248201527f73686f756c64206e6f74206265206465706c6f79656400000000000000000000604482015260640160405180910390fd5b6102f0806100726000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c8063694f712d14610030575b600080fd5b61004361003e366004610120565b610059565b6040516100509190610225565b60405180910390f35b604080516060808201835260008083526020830181905292820152905a9050600080866001600160a01b031686866040516100949190610277565b60006040518083038185875af1925050503d80600081146100d1576040519150601f19603f3d011682016040523d82523d6000602084013e6100d6565b606091505b509150915060405180606001604052805a6100f19086610293565b8152921515602084015260409092015295945050505050565b634e487b7160e01b600052604160045260246000fd5b60008060006060848603121561013557600080fd5b83356001600160a01b038116811461014c57600080fd5b925060208401359150604084013567ffffffffffffffff81111561016f57600080fd5b8401601f8101861361018057600080fd5b803567ffffffffffffffff81111561019a5761019a61010a565b604051601f8201601f19908116603f0116810167ffffffffffffffff811182821017156101c9576101c961010a565b6040528181528282016020018810156101e157600080fd5b816020840160208301376000602083830101528093505050509250925092565b60005b8381101561021c578181015183820152602001610204565b50506000910152565b60208152815160208201526020820151151560408201526000604083015160608084015280518060808501526102628160a0860160208501610201565b601f01601f19169290920160a0019392505050565b60008251610289818460208701610201565b9190910192915050565b818103818111156102b457634e487b7160e01b600052601160045260246000fd5b9291505056fea2646970667358221220fd5c4f5bf9f90b6eab39aa46ddeda959ed5909b6e92973ab51c047771409755e64736f6c634300081a0033")]

        contract GetGasUsed {
            struct GasUsedResult {
                uint256 gasUsed;
                bool success;
                bytes result;
            }

            constructor() {
                require(block.number < 100, "should not be deployed");
            }

            function getGas(
                address target,
                uint256 value,
                bytes memory data
            ) public returns (GasUsedResult memory) {
                uint256 preGas = gasleft();
                (bool success, bytes memory result) = target.call{value : value}(data);
                return GasUsedResult({
                    gasUsed: preGas - gasleft(),
                    success: success,
                    result: result
                });
            }
        }

    );

    #[tokio::test]
    async fn test_get_code_hash_unorder_equal() {
        let alloy_provider = ProviderBuilder::new().on_anvil();

        let get_code_hashes_contract = GetCodeHashes::deploy(alloy_provider.clone()).await.unwrap();
        let get_gas_used_contract = GetGasUsed::deploy(alloy_provider.clone()).await.unwrap();

        let emv_provider = AlloyEvmProvider::new(alloy_provider);
        let address_1 = get_code_hashes_contract.address();
        let address_2 = get_gas_used_contract.address();

        let hash_1 = emv_provider
            .get_code_hash(vec![*address_1, *address_2], None)
            .await
            .unwrap();

        let hash_2 = emv_provider
            .get_code_hash(vec![*address_2, *address_1], None)
            .await
            .unwrap();

        assert_eq!(hash_1, hash_2);
    }

    #[tokio::test]
    async fn test_get_code_hash_unequal() {
        let alloy_provider = ProviderBuilder::new().on_anvil();

        let get_code_hashes_contract = GetCodeHashes::deploy(alloy_provider.clone()).await.unwrap();
        let get_gas_used_contract = GetGasUsed::deploy(alloy_provider.clone()).await.unwrap();

        let emv_provider = AlloyEvmProvider::new(alloy_provider);
        let address_1 = get_code_hashes_contract.address();
        let address_2 = get_gas_used_contract.address();

        let hash_1 = emv_provider
            .get_code_hash(vec![*address_1, *address_2], None)
            .await
            .unwrap();

        let hash_2 = emv_provider
            .get_code_hash(vec![*address_1], None)
            .await
            .unwrap();

        assert_ne!(hash_1, hash_2);
    }
}
