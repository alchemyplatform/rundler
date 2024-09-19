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
        Ok(Self::get_block(self, BlockId::pending())
            .await?
            .context("pending block should exist")?
            .header
            .base_fee_per_gas
            .context("pending block should have a nonempty base fee")?)
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
        addresses: Vec<Address>,
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

        let mut call = helper.getCodeHashes(addresses).state(overrides);
        if let Some(block) = block {
            call = call.block(block);
        }

        let ret = call.call().await?;
        Ok(ret.hash)
    }
}
