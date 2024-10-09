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

use std::sync::Mutex as StdMutex;

use alloy_primitives::{Address, Bytes, B256};
use alloy_provider::Provider as AlloyProvider;
use alloy_transport::Transport;
use anyhow::Context;
use rundler_utils::cache::LruMap;
use tokio::sync::Mutex as TokioMutex;

use crate::{
    alloy::da::{arbitrum::NodeInterface::NodeInterfaceInstance, DAGasOracle},
    BlockHashOrNumber, ProviderResult,
};

/// Cached Arbitrum Nitro DA gas oracle
///
/// The goal of this oracle is to only need to make maximum
/// 1 network call per block + 1 network call per distinct UO
pub(crate) struct CachedNitroDAGasOracle<AP, T> {
    node_interface: NodeInterfaceInstance<T, AP>,
    // Use a tokio::Mutex here to ensure only one network call per block, other threads can async wait for the result
    block_da_data_cache: TokioMutex<LruMap<BlockHashOrNumber, BlockDAData>>,
    // Use a std::sync::Mutex here as both reads and writes to the LRU cache require interior mutability
    uo_cache: StdMutex<LruMap<B256, u128>>,
}

#[derive(Debug, Clone, Copy)]
struct BlockDAData {
    l1_base_fee: u128,
    base_fee: u128,
}

impl<AP, T> CachedNitroDAGasOracle<AP, T>
where
    AP: AlloyProvider<T>,
    T: Transport + Clone,
{
    pub(crate) fn new(oracle_address: Address, provider: AP) -> Self {
        Self {
            node_interface: NodeInterfaceInstance::new(oracle_address, provider),
            block_da_data_cache: TokioMutex::new(LruMap::new(100)),
            uo_cache: StdMutex::new(LruMap::new(10000)),
        }
    }
}

const CACHE_UNITS_SCALAR: u128 = 1_000_000;

#[async_trait::async_trait]
impl<AP, T> DAGasOracle for CachedNitroDAGasOracle<AP, T>
where
    AP: AlloyProvider<T>,
    T: Transport + Clone,
{
    async fn estimate_da_gas(
        &self,
        hash: B256,
        to: Address,
        data: Bytes,
        block: BlockHashOrNumber,
        _gas_price: u128,
    ) -> ProviderResult<u128> {
        let mut cache = self.block_da_data_cache.lock().await;
        match cache.get(&block) {
            Some(block_da_data) => {
                // Found the block, drop the block cache
                let block_da_data = *block_da_data;
                drop(cache);

                // Check if we have uo units cached
                let maybe_uo_units = self.uo_cache.lock().unwrap().get(&hash).cloned();

                if let Some(uo_units) = maybe_uo_units {
                    // Double cache hit, calculate the da fee from the cached uo units
                    Ok(calculate_da_fee(uo_units, &block_da_data))
                } else {
                    // UO cache miss, make remote call to get the da fee
                    let (_, uo_units, gas_estimate_for_l1) =
                        self.get_da_data(to, data, block).await?;
                    self.uo_cache.lock().unwrap().insert(hash, uo_units);
                    Ok(gas_estimate_for_l1)
                }
            }
            None => {
                // Block cache miss, make remote call to get the da fee
                let (block_da_data, uo_units, gas_estimate_for_l1) =
                    self.get_da_data(to, data, block).await?;
                cache.insert(block, block_da_data);
                drop(cache);

                self.uo_cache.lock().unwrap().insert(hash, uo_units);
                Ok(gas_estimate_for_l1)
            }
        }
    }
}

impl<AP, T> CachedNitroDAGasOracle<AP, T>
where
    AP: AlloyProvider<T>,
    T: Transport + Clone,
{
    async fn get_da_data(
        &self,
        to: Address,
        data: Bytes,
        block: BlockHashOrNumber,
    ) -> ProviderResult<(BlockDAData, u128, u128)> {
        let ret = self
            .node_interface
            .gasEstimateL1Component(to, true, data)
            .block(block.into())
            .call()
            .await?;

        let l1_base_fee = ret
            .l1BaseFeeEstimate
            .try_into()
            .context("Arbitrum NodeInterface returned l1BaseFeeEstimate too big for u128")?;
        let base_fee = ret
            .baseFee
            .try_into()
            .context("Arbitrum NodeInterface returned baseFee too big for u128")?;

        let block_da_data = BlockDAData {
            l1_base_fee,
            base_fee,
        };

        // Calculate UO units from the gas estimate for L1
        let uo_units = calculate_uo_units(ret.gasEstimateForL1 as u128, &block_da_data);

        Ok((block_da_data, uo_units, ret.gasEstimateForL1 as u128))
    }
}

// DA Fee to gas units conversion.
//
// See https://github.com/OffchainLabs/nitro/blob/32c3f4b36d5eb0b4bbd37a82afe6c0c707ebe78d/execution/nodeInterface/NodeInterface.go#L515
// and https://github.com/OffchainLabs/nitro/blob/32c3f4b36d5eb0b4bbd37a82afe6c0c707ebe78d/arbos/l1pricing/l1pricing.go#L582
//
// Errors should round down

// Calculate the da fee from the cahed scaled UO units
fn calculate_da_fee(uo_units: u128, block_da_data: &BlockDAData) -> u128 {
    // Multiply by l1_base_fee
    let a = uo_units.saturating_mul(block_da_data.l1_base_fee);
    // Add 10%
    let b = a.saturating_mul(11).saturating_div(10);
    // Divide by base_fee
    let c = if block_da_data.base_fee == 0 {
        0 // avoid division by zero, if this is the case then there is no way to pay for DA fee so we might as well return 0
    } else {
        b.saturating_div(block_da_data.base_fee)
    };
    // Scale down
    c / CACHE_UNITS_SCALAR
}

// Calculate scaled UO units from the da fee
fn calculate_uo_units(da_fee: u128, block_da_data: &BlockDAData) -> u128 {
    // Undo base fee division, scale up to reduce rounding error
    let a = da_fee
        .saturating_mul(CACHE_UNITS_SCALAR)
        .saturating_mul(block_da_data.base_fee);
    // Undo 10% increase
    let b = a.saturating_mul(10).saturating_div(11);
    // Undo l1_base_fee division
    if block_da_data.l1_base_fee == 0 {
        0
    } else {
        b.saturating_div(block_da_data.l1_base_fee)
    }
}
