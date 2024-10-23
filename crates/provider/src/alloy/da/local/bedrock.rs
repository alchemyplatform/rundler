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

use alloy_primitives::{Address, Bytes};
use alloy_provider::Provider as AlloyProvider;
use alloy_rpc_types_eth::state::{AccountOverride, StateOverride};
use alloy_transport::Transport;
use anyhow::Context;
use reth_tasks::pool::BlockingTaskPool;
use rundler_types::da::{BedrockDAGasBlockData, BedrockDAGasUOData, DAGasBlockData, DAGasUOData};
use rundler_utils::cache::LruMap;
use tokio::sync::Mutex as TokioMutex;
use tracing::error;

use super::multicall::{self, Multicall::MulticallInstance, MULTICALL_BYTECODE};
use crate::{
    alloy::da::optimism::GasPriceOracle::{
        baseFeeScalarCall, blobBaseFeeCall, blobBaseFeeScalarCall, l1BaseFeeCall,
        GasPriceOracleCalls, GasPriceOracleInstance,
    },
    BlockHashOrNumber, DAGasOracle, DAGasOracleSync, ProviderResult,
};

// From https://github.com/ethereum-optimism/optimism/blob/f93f9f40adcd448168c6ea27820aeee5da65fcbd/packages/contracts-bedrock/src/L2/GasPriceOracle.sol#L26
const DECIMAL_SCALAR: u128 = 1_000_000_000_000;
const COST_INTERCEPT: i128 = -42_585_600;
const COST_FASTLZ_COEF: i128 = 836_500;
const MIN_TRANSACTION_SIZE: i128 = 100_000_000;

/// Local Bedrock DA gas oracle
///
/// Details: https://github.com/ethereum-optimism/specs/blob/main/specs/protocol/fjord/exec-engine.md#fjord-l1-cost-fee-changes-fastlz-estimator
#[derive(Debug)]
pub(crate) struct LocalBedrockDAGasOracle<AP, T> {
    oracle: GasPriceOracleInstance<T, AP>,
    multicaller: MulticallInstance<T, AP>,
    block_data_cache: TokioMutex<LruMap<BlockHashOrNumber, BedrockDAGasBlockData>>,
    blocking_task_pool: BlockingTaskPool,
}

impl<AP, T> LocalBedrockDAGasOracle<AP, T>
where
    AP: AlloyProvider<T> + Clone,
    T: Transport + Clone,
{
    pub(crate) fn new(oracle_address: Address, provider: AP) -> Self {
        let oracle = GasPriceOracleInstance::new(oracle_address, provider.clone());
        let multicaller = MulticallInstance::new(Address::random(), provider);
        Self {
            oracle,
            multicaller,
            block_data_cache: TokioMutex::new(LruMap::new(100)),
            blocking_task_pool: BlockingTaskPool::build()
                .expect("failed to build blocking task pool"),
        }
    }
}

#[async_trait::async_trait]
impl<AP, T> DAGasOracle for LocalBedrockDAGasOracle<AP, T>
where
    AP: AlloyProvider<T>,
    T: Transport + Clone,
{
    async fn estimate_da_gas(
        &self,
        data: Bytes,
        to: Address,
        block: BlockHashOrNumber,
        gas_price: u128,
    ) -> ProviderResult<(u128, DAGasUOData, DAGasBlockData)> {
        let block_data = self.block_data(block).await?;
        let uo_data = self.uo_data(data, to, block).await?;
        let da_gas = self.calc_da_gas_sync(&uo_data, &block_data, gas_price);
        Ok((da_gas, uo_data, block_data))
    }
}

#[async_trait::async_trait]
impl<AP, T> DAGasOracleSync for LocalBedrockDAGasOracle<AP, T>
where
    AP: AlloyProvider<T>,
    T: Transport + Clone,
{
    async fn block_data(&self, block: BlockHashOrNumber) -> ProviderResult<DAGasBlockData> {
        let mut cache = self.block_data_cache.lock().await;
        match cache.get(&block) {
            Some(block_data) => Ok(DAGasBlockData::Bedrock(block_data.clone())),
            None => {
                let block_data = self.get_block_data(block).await?;
                cache.insert(block, block_data.clone());
                Ok(DAGasBlockData::Bedrock(block_data))
            }
        }
    }

    async fn uo_data(
        &self,
        uo_data: Bytes,
        _to: Address,
        _block: BlockHashOrNumber,
    ) -> ProviderResult<DAGasUOData> {
        let uo_data = self.get_uo_data(uo_data).await?;
        Ok(DAGasUOData::Bedrock(uo_data))
    }

    fn calc_da_gas_sync(
        &self,
        uo_data: &DAGasUOData,
        block_data: &DAGasBlockData,
        gas_price: u128,
    ) -> u128 {
        let block_da_data = match block_data {
            DAGasBlockData::Bedrock(block_da_data) => block_da_data,
            _ => panic!("LocalBedrockDAGasOracle only supports Bedrock block data"),
        };
        let uo_data = match uo_data {
            DAGasUOData::Bedrock(uo_data) => uo_data,
            _ => panic!("LocalBedrockDAGasOracle only supports Bedrock user operation data"),
        };

        let fee_scaled = (block_da_data.base_fee_scalar * 16 * block_da_data.l1_base_fee
            + block_da_data.blob_base_fee_scalar * block_da_data.blob_base_fee)
            as u128;
        let l1_fee = (uo_data.uo_units as u128 * fee_scaled) / DECIMAL_SCALAR;
        l1_fee.checked_div(gas_price).unwrap_or(u128::MAX)
    }
}

impl<AP, T> LocalBedrockDAGasOracle<AP, T>
where
    AP: AlloyProvider<T>,
    T: Transport + Clone,
{
    async fn is_fjord(&self) -> bool {
        self.oracle
            .isFjord()
            .call()
            .await
            .map(|r| r.isFjord)
            .map_err(|e| error!("failed to check if fjord: {:?}", e))
            .unwrap_or(true) // Fail-open. Assume fjord if we can't check, so this can be used downstream in asserts w/o panic on RPC errors.
    }

    async fn get_block_data(
        &self,
        block: BlockHashOrNumber,
    ) -> ProviderResult<BedrockDAGasBlockData> {
        assert!(self.is_fjord().await);

        let calls = vec![
            multicall::create_call(
                *self.oracle.address(),
                GasPriceOracleCalls::baseFeeScalar(baseFeeScalarCall {}),
            ),
            multicall::create_call(
                *self.oracle.address(),
                GasPriceOracleCalls::l1BaseFee(l1BaseFeeCall {}),
            ),
            multicall::create_call(
                *self.oracle.address(),
                GasPriceOracleCalls::blobBaseFeeScalar(blobBaseFeeScalarCall {}),
            ),
            multicall::create_call(
                *self.oracle.address(),
                GasPriceOracleCalls::blobBaseFee(blobBaseFeeCall {}),
            ),
        ];

        let mut overrides = StateOverride::default();
        let account = AccountOverride {
            code: Some(MULTICALL_BYTECODE.clone()),
            ..Default::default()
        };
        overrides.insert(*self.multicaller.address(), account);

        let result = self
            .multicaller
            .aggregate3(calls)
            .call()
            .overrides(&overrides)
            .block(block.into())
            .await?;

        if result.returnData.len() != 4 {
            Err(anyhow::anyhow!(
                "multicall returned unexpected number of results"
            ))?;
        } else if result.returnData.iter().any(|r| !r.success) {
            Err(anyhow::anyhow!("multicall returned some failed results"))?;
        }

        let base_fee_scalar =
            multicall::decode_result::<baseFeeScalarCall>(&result.returnData[0].returnData)?._0
                as u64;
        let l1_base_fee =
            multicall::decode_result::<l1BaseFeeCall>(&result.returnData[1].returnData)?
                ._0
                .try_into()
                .context("l1_base_fee too large for u64")?;
        let blob_base_fee_scalar =
            multicall::decode_result::<blobBaseFeeScalarCall>(&result.returnData[2].returnData)?._0
                as u64;
        let blob_base_fee =
            multicall::decode_result::<blobBaseFeeCall>(&result.returnData[3].returnData)?
                ._0
                .try_into()
                .context("blob_base_fee too large for u64")?;

        Ok(BedrockDAGasBlockData {
            base_fee_scalar,
            l1_base_fee,
            blob_base_fee_scalar,
            blob_base_fee,
        })
    }

    async fn get_uo_data(&self, data: Bytes) -> ProviderResult<BedrockDAGasUOData> {
        // Blocking call compressing potentially a lot of data.
        // Generally takes more than 100µs so should be spawned on blocking threadpool.
        // https://ryhl.io/blog/async-what-is-blocking/
        // https://docs.rs/tokio/latest/tokio/index.html#cpu-bound-tasks-and-blocking-code
        let compressed_len = self
            .blocking_task_pool
            .spawn(move || {
                let mut buf = vec![0; data.len() * 2];
                rundler_bindings_fastlz::compress(&data, &mut buf).len() as u64
            })
            .await
            .map_err(|e| anyhow::anyhow!("failed to compress data: {:?}", e))?;

        let compressed_with_buffer = compressed_len + 68;

        let estimated_size = COST_INTERCEPT + COST_FASTLZ_COEF * compressed_with_buffer as i128;
        let uo_units = estimated_size.clamp(MIN_TRANSACTION_SIZE, u64::MAX as i128);

        Ok(BedrockDAGasUOData {
            uo_units: uo_units as u64,
        })
    }
}
