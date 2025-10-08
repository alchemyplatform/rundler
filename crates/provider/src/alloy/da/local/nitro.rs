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
use moka::future::Cache;
use rundler_types::da::{DAGasBlockData, DAGasData, NitroDAGasBlockData, NitroDAGasData};
use tracing::instrument;

use super::DAMetrics;
use crate::{
    alloy::da::arbitrum::NodeInterface::NodeInterfaceInstance, AlloyProvider, BlockHashOrNumber,
    DAGasOracle, DAGasOracleSync, ProviderResult,
};

/// Cached Arbitrum Nitro DA gas oracle
///
/// The goal of this oracle is to only need to make maximum
/// 1 network call per block + 1 network call per distinct data
pub(crate) struct CachedNitroDAGasOracle<AP> {
    node_interface: NodeInterfaceInstance<AP, AnyNetwork>,
    block_data_cache: Cache<BlockHashOrNumber, NitroDAGasBlockData>,
    metrics: DAMetrics,
}

impl<AP> CachedNitroDAGasOracle<AP>
where
    AP: AlloyProvider,
{
    pub(crate) fn new(oracle_address: Address, provider: AP) -> Self {
        Self {
            node_interface: NodeInterfaceInstance::new(oracle_address, provider),
            block_data_cache: Cache::builder().max_capacity(100).build(),
            metrics: DAMetrics::default(),
        }
    }
}

const CACHE_UNITS_SCALAR: u128 = 1_000_000;

#[async_trait::async_trait]
impl<AP> DAGasOracle for CachedNitroDAGasOracle<AP>
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
        let block_da_data = self.get_cache_data(block).await?;

        let gas_data = self.get_gas_data(to, data, block).await?;
        let gas_data = DAGasData::Nitro(gas_data);
        let block_data = DAGasBlockData::Nitro(block_da_data);
        let l1_gas_estimate =
            self.calc_da_gas_sync(&gas_data, &block_data, gas_price, extra_bytes_len);
        Ok((l1_gas_estimate, gas_data, block_data))
    }
}

#[async_trait::async_trait]
impl<AP> DAGasOracleSync for CachedNitroDAGasOracle<AP>
where
    AP: AlloyProvider,
{
    #[instrument(skip_all)]
    async fn da_block_data(&self, block: BlockHashOrNumber) -> ProviderResult<DAGasBlockData> {
        let block_data = self.get_cache_data(block).await?;

        Ok(DAGasBlockData::Nitro(block_data))
    }

    #[instrument(skip_all)]
    async fn da_gas_data(
        &self,
        data: Bytes,
        to: Address,
        block: BlockHashOrNumber,
    ) -> ProviderResult<DAGasData> {
        let gas_data = self.get_gas_data(to, data, block).await?;
        Ok(DAGasData::Nitro(gas_data))
    }

    fn calc_da_gas_sync(
        &self,
        data: &DAGasData,
        block_data: &DAGasBlockData,
        _gas_price: u128,
        extra_data_len: usize,
    ) -> u128 {
        let units = match data {
            DAGasData::Nitro(data) => data.units,
            _ => panic!("NitroDAGasOracle only supports Nitro DAGasData"),
        };
        let block_data = match block_data {
            DAGasBlockData::Nitro(block_data) => block_data,
            _ => panic!("NitroDAGasOracle only supports Nitro DAGasBlockData"),
        };

        let units = units + extra_data_to_units(extra_data_len);

        calculate_da_fee(units, block_data)
    }
}

impl<AP> CachedNitroDAGasOracle<AP>
where
    AP: AlloyProvider,
{
    async fn get_cache_data(
        &self,
        block: BlockHashOrNumber,
    ) -> ProviderResult<NitroDAGasBlockData> {
        let data = self
            .block_data_cache
            .try_get_with(block, async { self.get_block_data(block).await })
            .await
            .context(format!("failed to get block data {:?}", block))?;

        Ok(data)
    }

    async fn get_block_data(
        &self,
        block: BlockHashOrNumber,
    ) -> ProviderResult<NitroDAGasBlockData> {
        // phantom data, not important for the calculation
        let data = Bytes::new();
        let to = Address::ZERO;

        let (_, block_data) = self.call_oracle_contract(to, data, block).await?;
        self.metrics
            .per_unit_l1_fee
            .set(block_data.l1_base_fee as f64);

        Ok(block_data)
    }

    async fn get_gas_data(
        &self,
        to: Address,
        data: Bytes,
        block: BlockHashOrNumber,
    ) -> ProviderResult<NitroDAGasData> {
        let (l1_gas_estimate, block_da_data) = self.call_oracle_contract(to, data, block).await?;
        let units = calculate_units(l1_gas_estimate, &block_da_data);
        Ok(NitroDAGasData { units })
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

// Calculate the da fee from the cached scaled units
fn calculate_da_fee(units: u128, block_da_data: &NitroDAGasBlockData) -> u128 {
    // Multiply by l1_base_fee
    let a = units.saturating_mul(block_da_data.l1_base_fee);
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

// Calculate scaled units from the da fee
fn calculate_units(da_fee: u128, block_da_data: &NitroDAGasBlockData) -> u128 {
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

// https://github.com/ethereum/go-ethereum/blob/52766bedb9316cd6cddacbb282809e3bdfba143e/params/protocol_params.go#L94
const TX_NON_ZERO_GAS_EIP_2028: u128 = 16;

fn extra_data_to_units(extra_data_len: usize) -> u128 {
    (extra_data_len as u128)
        .saturating_mul(TX_NON_ZERO_GAS_EIP_2028)
        .saturating_mul(CACHE_UNITS_SCALAR)
        .saturating_mul(101)
        .saturating_div(100)
}
