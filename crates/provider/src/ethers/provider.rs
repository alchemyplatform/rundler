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

use std::{fmt::Debug, sync::Arc, time::Duration};

use anyhow::Context;
use ethers::{
    abi::{AbiDecode, AbiEncode},
    prelude::ContractError as EthersContractError,
    providers::{
        Http, HttpRateLimitRetryPolicy, JsonRpcClient, Middleware, Provider as EthersProvider,
        ProviderError as EthersProviderError, RawCall, RetryClient, RetryClientBuilder,
    },
    types::{
        spoof, transaction::eip2718::TypedTransaction, Address, Block, BlockId, BlockNumber, Bytes,
        Eip1559TransactionRequest, FeeHistory, Filter, GethDebugTracingCallOptions,
        GethDebugTracingOptions, GethTrace, Log, Transaction, TransactionReceipt, TxHash, H256,
        U256, U64,
    },
};
use reqwest::Url;
use rundler_types::contracts::utils::{
    get_gas_used::{GasUsedResult, GetGasUsed, GETGASUSED_DEPLOYED_BYTECODE},
    storage_loader::STORAGELOADER_DEPLOYED_BYTECODE,
};
use serde::{de::DeserializeOwned, Serialize};

use super::metrics_middleware::MetricsMiddleware;
use crate::{Provider, ProviderError, ProviderResult};

#[async_trait::async_trait]
impl<C: JsonRpcClient + 'static> Provider for EthersProvider<C> {
    // We implement `ProviderLike` for `Provider` rather than for all
    // `Middleware` because forming a `PendingTransaction` specifically requires
    // a `Provider`.

    async fn request<T, R>(&self, method: &str, params: T) -> ProviderResult<R>
    where
        T: Debug + Serialize + Send + Sync + 'static,
        R: Serialize + DeserializeOwned + Debug + Send + 'static,
    {
        Ok(EthersProvider::request(self, method, params).await?)
    }

    async fn call(
        &self,
        tx: &TypedTransaction,
        block: Option<BlockId>,
        state_overrides: &spoof::State,
    ) -> ProviderResult<Bytes> {
        let mut call = self.call_raw(tx).state(state_overrides);
        if let Some(block) = block {
            call = call.block(block);
        }
        Ok(call.await?)
    }

    async fn call_constructor<A, R>(
        &self,
        bytecode: &Bytes,
        args: A,
        block_id: Option<BlockId>,
        state_overrides: &spoof::State,
    ) -> anyhow::Result<R>
    where
        A: AbiEncode + Send + Sync + 'static,
        R: AbiDecode + Send + Sync + 'static,
    {
        let mut data = bytecode.to_vec();
        data.extend(AbiEncode::encode(args));
        let tx = Eip1559TransactionRequest {
            data: Some(data.into()),
            ..Default::default()
        };
        let error = Provider::call(self, &tx.into(), block_id, state_overrides)
            .await
            .err()
            .context("called constructor should revert")?;
        get_revert_data(error).context("should decode revert data from called constructor")
    }

    async fn fee_history<T: Into<U256> + Send + Sync + Serialize + 'static>(
        &self,
        t: T,
        block_number: BlockNumber,
        reward_percentiles: &[f64],
    ) -> ProviderResult<FeeHistory> {
        Ok(Middleware::fee_history(self, t, block_number, reward_percentiles).await?)
    }

    async fn get_block_number(&self) -> ProviderResult<u64> {
        Ok(Middleware::get_block_number(self)
            .await
            .context("should get block number from provider")?
            .as_u64())
    }

    async fn get_block<T: Into<BlockId> + Send + Sync + 'static>(
        &self,
        block_hash_or_number: T,
    ) -> ProviderResult<Option<Block<H256>>> {
        Ok(Middleware::get_block(self, block_hash_or_number).await?)
    }

    async fn get_transaction<T: Send + Sync + Into<TxHash>>(
        &self,
        transaction_hash: T,
    ) -> ProviderResult<Option<Transaction>> {
        Ok(Middleware::get_transaction(self, transaction_hash).await?)
    }

    async fn get_transaction_receipt<T: Send + Sync + Into<TxHash> + 'static>(
        &self,
        transaction_hash: T,
    ) -> ProviderResult<Option<TransactionReceipt>> {
        Ok(Middleware::get_transaction_receipt(self, transaction_hash).await?)
    }

    async fn debug_trace_transaction(
        &self,
        tx_hash: TxHash,
        trace_options: GethDebugTracingOptions,
    ) -> ProviderResult<GethTrace> {
        Ok(Middleware::debug_trace_transaction(self, tx_hash, trace_options).await?)
    }

    async fn debug_trace_call(
        &self,
        tx: TypedTransaction,
        block_id: Option<BlockId>,
        trace_options: GethDebugTracingCallOptions,
    ) -> ProviderResult<GethTrace> {
        Ok(Middleware::debug_trace_call(self, tx, block_id, trace_options).await?)
    }

    async fn get_balance(&self, address: Address, block: Option<BlockId>) -> ProviderResult<U256> {
        Ok(Middleware::get_balance(self, address, block).await?)
    }

    async fn get_latest_block_hash_and_number(&self) -> ProviderResult<(H256, U64)> {
        let latest_block = Middleware::get_block(self, BlockId::Number(BlockNumber::Latest))
            .await
            .context("should load block to get hash and number")?
            .context("block should exist to get latest hash and number")?;
        Ok((
            latest_block
                .hash
                .context("hash should be present on block")?,
            latest_block
                .number
                .context("number should be present on block")?,
        ))
    }

    async fn get_base_fee(&self) -> ProviderResult<U256> {
        Ok(Middleware::get_block(self, BlockNumber::Pending)
            .await
            .context("should load pending block to get base fee")?
            .context("pending block should exist")?
            .base_fee_per_gas
            .context("pending block should have a nonempty base fee")?)
    }

    async fn get_max_priority_fee(&self) -> ProviderResult<U256> {
        Ok(self.request("eth_maxPriorityFeePerGas", ()).await?)
    }

    async fn get_logs(&self, filter: &Filter) -> ProviderResult<Vec<Log>> {
        Ok(Middleware::get_logs(self, filter).await?)
    }

    async fn get_code(&self, address: Address, block_hash: Option<H256>) -> ProviderResult<Bytes> {
        Ok(Middleware::get_code(self, address, block_hash.map(|b| b.into())).await?)
    }

    async fn get_transaction_count(&self, address: Address) -> ProviderResult<U256> {
        Ok(Middleware::get_transaction_count(self, address, None).await?)
    }

    async fn get_gas_used(
        self: &Arc<Self>,
        target: Address,
        value: U256,
        data: Bytes,
        mut state_overrides: spoof::State,
    ) -> ProviderResult<GasUsedResult> {
        let helper_addr = Address::random();
        let helper = GetGasUsed::new(helper_addr, Arc::clone(self));

        state_overrides
            .account(helper_addr)
            .code(GETGASUSED_DEPLOYED_BYTECODE.clone());

        Ok(helper
            .get_gas(target, value, data)
            .call_raw()
            .state(&state_overrides)
            .await
            .context("should get gas used")?)
    }

    async fn batch_get_storage_at(
        &self,
        address: Address,
        slots: Vec<H256>,
    ) -> ProviderResult<Vec<H256>> {
        let mut state_overrides = spoof::State::default();
        state_overrides
            .account(address)
            .code(STORAGELOADER_DEPLOYED_BYTECODE.clone());

        let expected_ret_size = slots.len() * 32;
        let slot_data = slots
            .into_iter()
            .flat_map(|slot| slot.to_fixed_bytes())
            .collect::<Vec<_>>();

        let tx: TypedTransaction = Eip1559TransactionRequest {
            to: Some(address.into()),
            data: Some(slot_data.into()),
            ..Default::default()
        }
        .into();

        let result_bytes = self
            .call_raw(&tx)
            .state(&state_overrides)
            .await
            .context("should call storage loader")?;

        if result_bytes.len() != expected_ret_size {
            return Err(anyhow::anyhow!(
                "expected {} bytes, got {}",
                expected_ret_size,
                result_bytes.len()
            )
            .into());
        }

        Ok(result_bytes.chunks(32).map(H256::from_slice).collect())
    }
}

impl From<EthersProviderError> for ProviderError {
    fn from(e: EthersProviderError) -> Self {
        match e {
            EthersProviderError::JsonRpcClientError(e) => {
                if let Some(jsonrpc_error) = e.as_error_response() {
                    ProviderError::JsonRpcError(jsonrpc_error.clone())
                } else {
                    ProviderError::Other(anyhow::anyhow!(e.to_string()))
                }
            }
            _ => ProviderError::Other(anyhow::anyhow!(e.to_string())),
        }
    }
}

impl<M: Middleware> From<EthersContractError<M>> for ProviderError {
    fn from(e: EthersContractError<M>) -> Self {
        ProviderError::ContractError(e.to_string())
    }
}

// Gets and decodes the revert data from a provider error, if it is a revert error.
fn get_revert_data<D: AbiDecode>(error: ProviderError) -> Result<D, ProviderError> {
    let ProviderError::JsonRpcError(jsonrpc_error) = &error else {
        return Err(error);
    };
    if !jsonrpc_error.is_revert() {
        return Err(error);
    }
    match jsonrpc_error.decode_revert_data() {
        Some(ret) => Ok(ret),
        None => Err(error),
    }
}

/// Construct a new Ethers provider from a URL and a poll interval.
///
/// Creates a provider with a retry client that retries 10 times, with an initial backoff of 500ms.
pub fn new_provider(
    url: &str,
    poll_interval: Option<Duration>,
) -> anyhow::Result<Arc<EthersProvider<RetryClient<MetricsMiddleware<Http>>>>> {
    let parsed_url = Url::parse(url).context("provider url should be valid")?;

    let http_client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(1))
        .build()
        .context("failed to build reqwest client")?;
    let http = MetricsMiddleware::new(Http::new_with_client(parsed_url, http_client));

    let client = RetryClientBuilder::default()
        // these retries are if the server returns a 429
        .rate_limit_retries(10)
        // these retries are if the connection is dubious
        .timeout_retries(3)
        .initial_backoff(Duration::from_millis(500))
        .build(http, Box::<HttpRateLimitRetryPolicy>::default());

    let mut provider = EthersProvider::new(client);

    if let Some(poll_interval) = poll_interval {
        provider = provider.interval(poll_interval);
    }

    Ok(Arc::new(provider))
}
