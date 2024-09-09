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
use rundler_types::chain::{ChainSpec, L1GasOracleContractType};

use crate::ProviderResult;

pub(crate) mod v0_6;
pub(crate) mod v0_7;

mod arbitrum;
mod optimism;

#[derive(Debug, Default)]
pub(crate) enum L1GasOracle {
    ArbitrumNitro(Address),
    OptimismBedrock(Address),
    #[default]
    None,
}

impl L1GasOracle {
    fn new(chain_spec: &ChainSpec) -> L1GasOracle {
        match chain_spec.l1_gas_oracle_contract_type {
            L1GasOracleContractType::ArbitrumNitro => {
                L1GasOracle::ArbitrumNitro(chain_spec.l1_gas_oracle_contract_address)
            }
            L1GasOracleContractType::OptimismBedrock => {
                L1GasOracle::OptimismBedrock(chain_spec.l1_gas_oracle_contract_address)
            }
            L1GasOracleContractType::None => L1GasOracle::None,
        }
    }

    async fn estimate_l1_gas<AP: AlloyProvider<T>, T: Transport + Clone>(
        &self,
        provider: AP,
        to_address: Address,
        data: Bytes,
        gas_price: u128,
    ) -> ProviderResult<u128> {
        match self {
            L1GasOracle::ArbitrumNitro(oracle_address) => {
                arbitrum::estimate_l1_gas(provider, *oracle_address, to_address, data).await
            }
            L1GasOracle::OptimismBedrock(oracle_address) => {
                optimism::estimate_l1_gas(provider, *oracle_address, to_address, data, gas_price)
                    .await
            }
            L1GasOracle::None => Ok(0),
        }
    }
}
