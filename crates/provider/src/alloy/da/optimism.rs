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
use anyhow::Context;
use rundler_types::da::{DAGasBlockData, DAGasUOData};
use GasPriceOracle::GasPriceOracleInstance;

use super::DAGasOracle;
use crate::{BlockHashOrNumber, ProviderResult};

// From https://github.com/ethereum-optimism/optimism/blob/f93f9f40adcd448168c6ea27820aeee5da65fcbd/packages/contracts-bedrock/src/L2/GasPriceOracle.sol#L54
sol! {
    #[sol(rpc)]
    interface GasPriceOracle {
        bool public isFjord;

        function baseFeeScalar() public view returns (uint32);
        function l1BaseFee() public view returns (uint256);
        function blobBaseFeeScalar() public view returns (uint32);
        function blobBaseFee() public view returns (uint256);

        function getL1Fee(bytes memory _data) external view returns (uint256);
    }
}

pub(super) struct OptimismBedrockDAGasOracle<AP, T> {
    oracle: GasPriceOracleInstance<T, AP>,
}

impl<AP, T> OptimismBedrockDAGasOracle<AP, T>
where
    AP: AlloyProvider<T>,
    T: Transport + Clone,
{
    pub(crate) fn new(oracle_address: Address, provider: AP) -> Self {
        let oracle = GasPriceOracleInstance::new(oracle_address, provider);
        Self { oracle }
    }
}

#[async_trait::async_trait]
impl<AP, T> DAGasOracle for OptimismBedrockDAGasOracle<AP, T>
where
    AP: AlloyProvider<T>,
    T: Transport + Clone,
{
    async fn estimate_da_gas(
        &self,
        data: Bytes,
        _to: Address,
        block: BlockHashOrNumber,
        gas_price: u128,
    ) -> ProviderResult<(u128, DAGasUOData, DAGasBlockData)> {
        if gas_price == 0 {
            Err(anyhow::anyhow!("gas price cannot be zero"))?;
        }

        let l1_fee: u128 = self
            .oracle
            .getL1Fee(data)
            .block(block.into())
            .call()
            .await?
            ._0
            .try_into()
            .context("failed to convert DA fee to u128")?;

        Ok((
            l1_fee.checked_div(gas_price).unwrap_or(u128::MAX),
            DAGasUOData::Empty,
            DAGasBlockData::Empty,
        ))
    }
}
