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
use alloy_transport::Transport;
use anyhow::Context;
use rundler_types::da::{DAGasBlockData, DAGasUOData, NitroDAGasBlockData, NitroDAGasUOData};
use rundler_utils::cache::LruMap;
use tokio::sync::Mutex as TokioMutex;

use crate::{
    alloy::da::arbitrum::NodeInterface::NodeInterfaceInstance, BlockHashOrNumber, DAGasOracle,
    DAGasOracleSync, ProviderResult,
};

/// Cached Arbitrum Nitro DA gas oracle
///
/// The goal of this oracle is to only need to make maximum
/// 1 network call per block + 1 network call per distinct UO
pub(crate) struct CachedNitroDAGasOracle<AP, T> {
    node_interface: NodeInterfaceInstance<T, AP>,
    // Use a tokio::Mutex here to ensure only one network call per block, other threads can async wait for the result
    block_data_cache: TokioMutex<LruMap<BlockHashOrNumber, NitroDAGasBlockData>>,
}

impl<AP, T> CachedNitroDAGasOracle<AP, T>
where
    AP: AlloyProvider<T>,
    T: Transport + Clone,
{
    pub(crate) fn new(oracle_address: Address, provider: AP) -> Self {
        Self {
            node_interface: NodeInterfaceInstance::new(oracle_address, provider),
            block_data_cache: TokioMutex::new(LruMap::new(100)),
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
        data: Bytes,
        to: Address,
        block: BlockHashOrNumber,
        _gas_price: u128,
    ) -> ProviderResult<(u128, DAGasUOData, DAGasBlockData)> {
        let mut cache = self.block_data_cache.lock().await;
        match cache.get(&block) {
            Some(block_da_data) => {
                // Found the block, drop the block cache
                let block_da_data = block_da_data.clone();
                drop(cache);

                let uo_data = self.get_uo_data(to, data, block).await?;
                let uo_data = DAGasUOData::Nitro(uo_data);
                let block_data = DAGasBlockData::Nitro(block_da_data);
                let l1_gas_estimate = self.calc_da_gas_sync(&uo_data, &block_data, _gas_price);

                Ok((l1_gas_estimate, uo_data, block_data))
            }
            None => {
                // Block cache miss, make remote call to get the da fee
                let (gas_estimate_for_l1, block_da_data) =
                    self.call_oracle_contract(to, data, block).await?;
                cache.insert(block, block_da_data.clone());
                drop(cache);

                let uo_units = calculate_uo_units(gas_estimate_for_l1, &block_da_data);

                Ok((
                    gas_estimate_for_l1,
                    DAGasUOData::Nitro(NitroDAGasUOData { uo_units }),
                    DAGasBlockData::Nitro(block_da_data),
                ))
            }
        }
    }
}

#[async_trait::async_trait]
impl<AP, T> DAGasOracleSync for CachedNitroDAGasOracle<AP, T>
where
    AP: AlloyProvider<T>,
    T: Transport + Clone,
{
    async fn block_data(&self, block: BlockHashOrNumber) -> ProviderResult<DAGasBlockData> {
        let mut cache = self.block_data_cache.lock().await;
        match cache.get(&block) {
            Some(block_data) => Ok(DAGasBlockData::Nitro(block_data.clone())),
            None => {
                let block_data = self.get_block_data(block).await?;
                cache.insert(block, block_data.clone());
                Ok(DAGasBlockData::Nitro(block_data))
            }
        }
    }

    async fn uo_data(
        &self,
        uo_data: Bytes,
        to: Address,
        block: BlockHashOrNumber,
    ) -> ProviderResult<DAGasUOData> {
        let uo_data = self.get_uo_data(to, uo_data, block).await?;
        Ok(DAGasUOData::Nitro(uo_data))
    }

    fn calc_da_gas_sync(
        &self,
        uo_data: &DAGasUOData,
        block_data: &DAGasBlockData,
        _gas_price: u128,
    ) -> u128 {
        let uo_units = match uo_data {
            DAGasUOData::Nitro(uo_data) => uo_data.uo_units,
            _ => panic!("NitroDAGasOracle only supports Nitro DAGasUOData"),
        };
        let block_data = match block_data {
            DAGasBlockData::Nitro(block_data) => block_data,
            _ => panic!("NitroDAGasOracle only supports Nitro DAGasBlockData"),
        };

        calculate_da_fee(uo_units, block_data)
    }
}

impl<AP, T> CachedNitroDAGasOracle<AP, T>
where
    AP: AlloyProvider<T>,
    T: Transport + Clone,
{
    async fn get_block_data(
        &self,
        block: BlockHashOrNumber,
    ) -> ProviderResult<NitroDAGasBlockData> {
        // phantom data, not important for the calculation
        let data = Bytes::new();
        let to = Address::ZERO;

        let (_, block_data) = self.call_oracle_contract(to, data, block).await?;

        Ok(block_data)
    }

    async fn get_uo_data(
        &self,
        to: Address,
        data: Bytes,
        block: BlockHashOrNumber,
    ) -> ProviderResult<NitroDAGasUOData> {
        let (l1_gas_estimate, block_da_data) = self.call_oracle_contract(to, data, block).await?;
        let uo_units = calculate_uo_units(l1_gas_estimate, &block_da_data);
        Ok(NitroDAGasUOData { uo_units })
    }

    async fn call_oracle_contract(
        &self,
        to: Address,
        data: Bytes,
        block: BlockHashOrNumber,
    ) -> ProviderResult<(u128, NitroDAGasBlockData)> {
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

        Ok((
            ret.gasEstimateForL1 as u128,
            NitroDAGasBlockData {
                l1_base_fee,
                base_fee,
            },
        ))
    }
}

// DA Fee to gas units conversion.
//
// See https://github.com/OffchainLabs/nitro/blob/32c3f4b36d5eb0b4bbd37a82afe6c0c707ebe78d/execution/nodeInterface/NodeInterface.go#L515
// and https://github.com/OffchainLabs/nitro/blob/32c3f4b36d5eb0b4bbd37a82afe6c0c707ebe78d/arbos/l1pricing/l1pricing.go#L582
//
// Errors should round down

// Calculate the da fee from the cached scaled UO units
fn calculate_da_fee(uo_units: u128, block_da_data: &NitroDAGasBlockData) -> u128 {
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
fn calculate_uo_units(da_fee: u128, block_da_data: &NitroDAGasBlockData) -> u128 {
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
