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
mod local;
use local::LocalBedrockDAGasOracle;

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
        DAGasOracleContractType::LocalBedrock => Box::new(LocalBedrockDAGasOracle::new(
            chain_spec.da_gas_oracle_contract_address,
            provider,
        )),
        DAGasOracleContractType::None => Box::new(ZeroDAGasOracle),
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{address, b256, bytes, uint, U256};
    use alloy_provider::ProviderBuilder;
    use alloy_sol_types::SolValue;
    use rundler_contracts::v0_7::PackedUserOperation;

    use super::*;

    // This test may begin to fail if an optimism sepolia fork changes how the L1 gas oracle works.
    // If that happens, we should update the local bedrock oracle to match the new fork logic in
    // a backwards compatible way based on the fork booleans in the contract.
    #[tokio::test]
    async fn compare_opt_latest() {
        let provider = opt_provider();
        let block = provider.get_block_number().await.unwrap();

        compare_opt_and_local_bedrock(provider, block.into()).await;
    }

    // This test should never fail for a block on the Fjord fork of optimism sepolia.
    #[tokio::test]
    async fn compare_opt_fixed() {
        let provider = opt_provider();

        compare_opt_and_local_bedrock(provider, 18343127.into()).await;
    }

    async fn compare_opt_and_local_bedrock(
        provider: impl AlloyProvider + Clone,
        block: BlockHashOrNumber,
    ) {
        let oracle_addr = address!("420000000000000000000000000000000000000F");

        let opt_contract_oracle = OptimismBedrockDAGasOracle::new(oracle_addr, provider.clone());
        let local_contract_oracle = LocalBedrockDAGasOracle::new(oracle_addr, provider.clone());

        let gas_price = 1;
        let to = Address::random();

        let puo = PackedUserOperation {
            sender: address!("f497A8026717FbbA3944c3dd2533c0716b7685e2"),
            nonce: uint!(0x23_U256),
            initCode: Bytes::default(),
            callData: bytes!("b61d27f6000000000000000000000000f497a8026717fbba3944c3dd2533c0716b7685e2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000004d087d28800000000000000000000000000000000000000000000000000000000"),
            accountGasLimits: b256!("000000000000000000000000000114fc0000000000000000000000000012c9b5"),
            preVerificationGas: U256::from(48916),
            gasFees: b256!("000000000000000000000000524121000000000000000000000000109a4a441a"),
            paymasterAndData: Bytes::default(),
            signature: bytes!("0b83faeeac250d4c4a2459c1d6e1f8427f96af246d7fb3027b10bb05d934912f23a9491c16ab97ab32ac88179f279e871387c23547aa2e27b83fc358058e71fa1c"),
        };
        let uo_data: Bytes = puo.abi_encode().into();

        let opt_gas = opt_contract_oracle
            .estimate_da_gas(to, uo_data.clone(), block, gas_price)
            .await
            .unwrap();
        let local_gas = local_contract_oracle
            .estimate_da_gas(to, uo_data, block, gas_price)
            .await
            .unwrap();

        assert_eq!(opt_gas, local_gas);
    }

    fn opt_provider() -> impl AlloyProvider + Clone {
        ProviderBuilder::new()
            .on_http("https://sepolia.optimism.io".parse().unwrap())
            .boxed()
    }
}
