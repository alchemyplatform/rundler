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
use alloy_provider::network::AnyNetwork;
use anyhow::Context;
use reth_tasks::pool::BlockingTaskPool;
use rundler_contracts::multicall3::{self, Multicall3::Multicall3Instance};
use rundler_types::{
    chain::ChainSpec,
    da::{BedrockDAGasBlockData, BedrockDAGasData, DAGasBlockData, DAGasData},
};
use rundler_utils::cache::LruMap;
use tokio::sync::Mutex as TokioMutex;
use tracing::{error, instrument};

use super::DAMetrics;
use crate::{
    AlloyProvider, BlockHashOrNumber, DAGasOracle, DAGasOracleSync, ProviderResult,
    alloy::da::optimism::GasPriceOracle::{
        GasPriceOracleCalls, GasPriceOracleInstance, baseFeeScalarCall, blobBaseFeeCall,
        blobBaseFeeScalarCall, l1BaseFeeCall,
    },
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
pub(crate) struct LocalBedrockDAGasOracle<AP> {
    oracle: GasPriceOracleInstance<AP, AnyNetwork>,
    multicaller: Multicall3Instance<AP, AnyNetwork>,
    block_data_cache: TokioMutex<LruMap<BlockHashOrNumber, BedrockDAGasBlockData>>,
    blocking_task_pool: BlockingTaskPool,
    metrics: DAMetrics,
}

impl<AP> LocalBedrockDAGasOracle<AP>
where
    AP: AlloyProvider,
{
    pub(crate) fn new(oracle_address: Address, provider: AP, chain_spec: &ChainSpec) -> Self {
        let oracle = GasPriceOracleInstance::new(oracle_address, provider.clone());
        let multicaller = Multicall3Instance::new(chain_spec.multicall3_address, provider);
        Self {
            oracle,
            multicaller,
            block_data_cache: TokioMutex::new(LruMap::new(100)),
            blocking_task_pool: BlockingTaskPool::build()
                .expect("failed to build blocking task pool"),
            metrics: DAMetrics::default(),
        }
    }
}

#[async_trait::async_trait]
impl<AP> DAGasOracle for LocalBedrockDAGasOracle<AP>
where
    AP: AlloyProvider,
{
    #[instrument(skip_all)]
    async fn estimate_da_gas(
        &self,
        data: Bytes,
        to: Address,
        block: BlockHashOrNumber,
        gas_price: u128,
        extra_bytes_len: usize,
    ) -> ProviderResult<(u128, DAGasData, DAGasBlockData)> {
        let block_data = self.da_block_data(block).await?;
        let gas_data = self.da_gas_data(data, to, block).await?;
        let da_gas = self.calc_da_gas_sync(&gas_data, &block_data, gas_price, extra_bytes_len);
        Ok((da_gas, gas_data, block_data))
    }
}

#[async_trait::async_trait]
impl<AP> DAGasOracleSync for LocalBedrockDAGasOracle<AP>
where
    AP: AlloyProvider,
{
    #[instrument(skip_all)]
    async fn da_block_data(&self, block: BlockHashOrNumber) -> ProviderResult<DAGasBlockData> {
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

    #[instrument(skip_all)]
    async fn da_gas_data(
        &self,
        data: Bytes,
        _to: Address,
        _block: BlockHashOrNumber,
    ) -> ProviderResult<DAGasData> {
        let gas_data = self.get_gas_data(data).await?;
        Ok(DAGasData::Bedrock(gas_data))
    }

    fn calc_da_gas_sync(
        &self,
        gas_data: &DAGasData,
        block_data: &DAGasBlockData,
        gas_price: u128,
        extra_data_len: usize,
    ) -> u128 {
        let block_da_data = match block_data {
            DAGasBlockData::Bedrock(block_da_data) => block_da_data,
            _ => panic!("LocalBedrockDAGasOracle only supports Bedrock block data"),
        };
        let gas_data = match gas_data {
            DAGasData::Bedrock(gas_data) => gas_data,
            _ => panic!("LocalBedrockDAGasOracle only supports Bedrock data"),
        };

        let fee_scaled = (block_da_data.base_fee_scalar as u128)
            .saturating_mul(16_u128)
            .saturating_mul(block_da_data.l1_base_fee as u128)
            .saturating_add(
                (block_da_data.blob_base_fee_scalar as u128)
                    .saturating_mul(block_da_data.blob_base_fee),
            );

        let units = gas_data.units + (extra_data_to_units(extra_data_len) as u128);

        let l1_fee = (units * fee_scaled) / DECIMAL_SCALAR;
        l1_fee.checked_div(gas_price).unwrap_or(u128::MAX)
    }
}

impl<AP> LocalBedrockDAGasOracle<AP>
where
    AP: AlloyProvider,
{
    #[instrument(skip_all)]
    async fn is_fjord(&self) -> bool {
        self.oracle
            .isFjord()
            .call()
            .await
            .map_err(|e| error!("failed to check if fjord: {:?}", e))
            .unwrap_or(true) // Fail-open. Assume fjord if we can't check, so this can be used downstream in asserts w/o panic on RPC errors.
    }

    #[instrument(skip_all)]
    async fn get_block_data(
        &self,
        block: BlockHashOrNumber,
    ) -> ProviderResult<BedrockDAGasBlockData> {
        assert!(self.is_fjord().await);

        let calls = vec![
            multicall3::create_call(
                *self.oracle.address(),
                GasPriceOracleCalls::baseFeeScalar(baseFeeScalarCall {}),
            ),
            multicall3::create_call(
                *self.oracle.address(),
                GasPriceOracleCalls::l1BaseFee(l1BaseFeeCall {}),
            ),
            multicall3::create_call(
                *self.oracle.address(),
                GasPriceOracleCalls::blobBaseFeeScalar(blobBaseFeeScalarCall {}),
            ),
            multicall3::create_call(
                *self.oracle.address(),
                GasPriceOracleCalls::blobBaseFee(blobBaseFeeCall {}),
            ),
        ];

        let result = self
            .multicaller
            .aggregate3(calls)
            .call()
            .block(block.into())
            .await?;

        if result.len() != 4 {
            Err(anyhow::anyhow!(
                "multicall returned unexpected number of results"
            ))?;
        } else if result.iter().any(|r| !r.success) {
            Err(anyhow::anyhow!("multicall returned some failed results"))?;
        }

        let base_fee_scalar =
            multicall3::decode_result::<baseFeeScalarCall>(&result[0].returnData)? as u64;
        let l1_base_fee = multicall3::decode_result::<l1BaseFeeCall>(&result[1].returnData)?
            .try_into()
            .context("l1_base_fee too large for u64")?;
        let blob_base_fee_scalar =
            multicall3::decode_result::<blobBaseFeeScalarCall>(&result[2].returnData)? as u64;
        let blob_base_fee = multicall3::decode_result::<blobBaseFeeCall>(&result[3].returnData)?
            .try_into()
            .context("blob_base_fee too large for u128")?;

        self.metrics.l1_base_fee.set(l1_base_fee as f64);
        self.metrics.blob_base_fee.set(blob_base_fee as f64);

        Ok(BedrockDAGasBlockData {
            base_fee_scalar,
            l1_base_fee,
            blob_base_fee_scalar,
            blob_base_fee,
        })
    }

    #[instrument(skip_all)]
    async fn get_gas_data(&self, data: Bytes) -> ProviderResult<BedrockDAGasData> {
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
        let units = estimated_size.clamp(MIN_TRANSACTION_SIZE, u64::MAX as i128);

        Ok(BedrockDAGasData {
            units: units.try_into().unwrap(),
        })
    }
}

fn extra_data_to_units(extra_data_len: usize) -> u64 {
    // https://github.com/ethereum-optimism/optimism/blob/d39eb247e60584c87b75baec937ddd20701225a5/packages/contracts-bedrock/src/L2/GasPriceOracle.sol#L239
    // bytes are all scaled up by 1e6
    (extra_data_len * 1_000_000) as u64
}
