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
use rundler_types::chain::{ChainSpec, DAGasOracleContractType};

use crate::{BlockHashOrNumber, ProviderResult};

mod arbitrum;
use arbitrum::ArbitrumNitroDAGasOracle;
mod optimism;
use optimism::OptimismBedrockDAGasOracle;

/// Trait for a DA gas oracle
#[async_trait::async_trait]
#[auto_impl::auto_impl(&, &mut, Rc, Arc, Box)]
pub(crate) trait DAGasOracle: Send + Sync {
    async fn estimate_da_gas(
        &self,
        to: Address,
        data: Bytes,
        block: BlockHashOrNumber,
        gas_price: u128,
    ) -> ProviderResult<u128>;
}

struct ZeroDAGasOracle;

#[async_trait::async_trait]
impl DAGasOracle for ZeroDAGasOracle {
    async fn estimate_da_gas(
        &self,
        _to: Address,
        _data: Bytes,
        _block: BlockHashOrNumber,
        _gas_price: u128,
    ) -> ProviderResult<u128> {
        Ok(0)
    }
}

pub(crate) fn da_gas_oracle_for_chain<'a, AP, T>(
    chain_spec: &ChainSpec,
    provider: AP,
) -> Box<dyn DAGasOracle + 'a>
where
    AP: AlloyProvider<T> + 'a,
    T: Transport + Clone,
{
    match chain_spec.da_gas_oracle_contract_type {
        DAGasOracleContractType::ArbitrumNitro => Box::new(ArbitrumNitroDAGasOracle::new(
            chain_spec.da_gas_oracle_contract_address,
            provider,
        )),
        DAGasOracleContractType::OptimismBedrock => Box::new(OptimismBedrockDAGasOracle::new(
            chain_spec.da_gas_oracle_contract_address,
            provider,
        )),
        DAGasOracleContractType::None => Box::new(ZeroDAGasOracle),
    }
}
