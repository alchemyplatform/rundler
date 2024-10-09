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
use alloy_sol_types::sol;
use alloy_transport::Transport;
use rundler_utils::cache::LruMap;
use tokio::sync::Mutex;
use GasPriceOracle::GasPriceOracleInstance;

use crate::{alloy::da::DAGasOracle, BlockHashOrNumber, ProviderResult};

// From https://github.com/ethereum-optimism/optimism/blob/f93f9f40adcd448168c6ea27820aeee5da65fcbd/packages/contracts-bedrock/src/L2/GasPriceOracle.sol#L54
sol! {
    #[sol(rpc)]
    interface GasPriceOracle {
        bool public isFjord;

        function baseFeeScalar() public view returns (uint32);
        function l1BaseFee() public view returns (uint32);
        function blobBaseFeeScalar() public view returns (uint32);
        function blobBaseFee() public view returns (uint32);
    }
}

const DECIMAL_SCALAR: u128 = 1_000_000_000_000;
const COST_INTERCEPT: i128 = -42_585_600;
const COST_FASTLZ_COEF: i128 = 836_500;
const MIN_TRANSACTION_SIZE: i128 = 100_000_000;

/// Local Bedrock DA gas oracle
///
/// Details: https://github.com/ethereum-optimism/specs/blob/main/specs/protocol/fjord/exec-engine.md#fjord-l1-cost-fee-changes-fastlz-estimator
pub(crate) struct LocalBedrockDAGasOracle<AP, T> {
    oracle: GasPriceOracleInstance<T, AP>,
    block_da_data_cache: Mutex<LruMap<BlockHashOrNumber, BlockDAData>>,
}

#[derive(Debug, Clone, Copy)]
struct BlockDAData {
    base_fee_scalar: u64,
    l1_base_fee: u64,
    blob_base_fee_scalar: u64,
    blob_base_fee: u64,
}

impl<AP, T> LocalBedrockDAGasOracle<AP, T>
where
    AP: AlloyProvider<T>,
    T: Transport + Clone,
{
    pub(crate) fn new(oracle_address: Address, provider: AP) -> Self {
        let oracle = GasPriceOracleInstance::new(oracle_address, provider);
        Self {
            oracle,
            block_da_data_cache: Mutex::new(LruMap::new(100)),
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
        _to: Address,
        data: Bytes,
        block: BlockHashOrNumber,
        gas_price: u128,
    ) -> ProviderResult<u128> {
        let block_da_data = {
            let mut cache = self.block_da_data_cache.lock().await;

            match cache.get(&block) {
                Some(block_da_data) => *block_da_data,
                None => {
                    let block_da_data = self.get_block_da_data(block).await?;
                    cache.insert(block, block_da_data);
                    block_da_data
                }
            }
        };

        let l1_fee = Self::fjord_l1_fee(data, &block_da_data);
        Ok(l1_fee.checked_div(gas_price).unwrap_or(u128::MAX))
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
            .unwrap_or(false)
    }

    async fn get_block_da_data(&self, block: BlockHashOrNumber) -> ProviderResult<BlockDAData> {
        assert!(self.is_fjord().await);

        let base_fee_scalar = self
            .oracle
            .baseFeeScalar()
            .block(block.into())
            .call()
            .await?
            ._0 as u64;
        let l1_base_fee = self.oracle.l1BaseFee().block(block.into()).call().await?._0 as u64;
        let blob_base_fee_scalar = self
            .oracle
            .blobBaseFeeScalar()
            .block(block.into())
            .call()
            .await?
            ._0 as u64;
        let blob_base_fee = self
            .oracle
            .blobBaseFee()
            .block(block.into())
            .call()
            .await?
            ._0 as u64;

        Ok(BlockDAData {
            base_fee_scalar,
            l1_base_fee,
            blob_base_fee_scalar,
            blob_base_fee,
        })
    }

    fn fjord_l1_fee(data: Bytes, block_da_data: &BlockDAData) -> u128 {
        let mut buf = vec![0; data.len() * 2];
        let compressed = rundler_bindings_fastlz::compress(&data, &mut buf);
        let compressed_length = compressed.len() as u64;

        Self::fjord_l1_cost(compressed_length + 68, block_da_data)
    }

    fn fjord_l1_cost(fast_lz_size: u64, block_da_data: &BlockDAData) -> u128 {
        let estimated_size = Self::fjord_linear_regression(fast_lz_size) as u128;
        let fee_scaled = (block_da_data.base_fee_scalar * 16 * block_da_data.l1_base_fee
            + block_da_data.blob_base_fee_scalar * block_da_data.blob_base_fee)
            as u128;
        (estimated_size * fee_scaled) / DECIMAL_SCALAR
    }

    fn fjord_linear_regression(fast_lz_size: u64) -> u64 {
        let estimated_size = COST_INTERCEPT + COST_FASTLZ_COEF * fast_lz_size as i128;
        let ret = estimated_size.clamp(MIN_TRANSACTION_SIZE, u64::MAX as i128);
        ret as u64
    }
}
