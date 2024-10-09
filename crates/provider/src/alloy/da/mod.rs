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

use alloy_primitives::{Address, Bytes, B256};
use alloy_provider::Provider as AlloyProvider;
use alloy_transport::Transport;
use rundler_types::chain::{ChainSpec, DAGasOracleContractType};

use crate::{BlockHashOrNumber, ProviderResult};

mod arbitrum;
use arbitrum::ArbitrumNitroDAGasOracle;
mod optimism;
use optimism::OptimismBedrockDAGasOracle;
mod local;
use local::{CachedNitroDAGasOracle, LocalBedrockDAGasOracle};

/// Trait for a DA gas oracle
#[async_trait::async_trait]
#[auto_impl::auto_impl(&, &mut, Rc, Arc, Box)]
pub(crate) trait DAGasOracle: Send + Sync {
    async fn estimate_da_gas(
        &self,
        hash: B256,
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
        _hash: B256,
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
    AP: AlloyProvider<T> + Clone + 'a,
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
        DAGasOracleContractType::CachedNitro => Box::new(CachedNitroDAGasOracle::new(
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

    // Run these tests locally with `ALCHEMY_API_KEY=<key> cargo test -- --ignored`

    // This test may begin to fail if an optimism sepolia fork changes how the L1 gas oracle works.
    // If that happens, we should update the local bedrock oracle to match the new fork logic in
    // a backwards compatible way based on the fork booleans in the contract.
    #[tokio::test]
    #[ignore]
    async fn compare_opt_latest() {
        let provider = opt_provider();
        let block = provider.get_block_number().await.unwrap();
        println!("block: {}", block);

        compare_opt_and_local_bedrock(provider, block.into()).await;
    }

    // This test should never fail for a block on the Fjord fork of optimism sepolia.
    #[tokio::test]
    #[ignore]
    async fn compare_opt_fixed() {
        let provider = opt_provider();
        // let block: BlockHashOrNumber = 18343127.into();
        let block: BlockHashOrNumber = 18434733.into();

        compare_opt_and_local_bedrock(provider, block).await;
    }

    #[tokio::test]
    #[ignore]
    async fn compare_arb_latest() {
        let provider = arb_provider();
        let block = provider.get_block_number().await.unwrap();
        let (uo, hash) = test_uo_data_1();

        compare_arb_and_cached_on_data(provider, block.into(), hash, uo).await;
    }

    #[tokio::test]
    #[ignore]
    async fn compare_arb_fixed() {
        let provider = arb_provider();
        let block: BlockHashOrNumber = 262113260.into();
        let (uo, hash) = test_uo_data_1();

        compare_arb_and_cached_on_data(provider, block, hash, uo).await;
    }

    #[tokio::test]
    #[ignore]
    async fn compare_arb_multiple() {
        let (uo1, hash1) = test_uo_data_1();
        let (uo2, hash2) = test_uo_data_2();
        let provider = arb_provider();

        let oracle_addr = address!("00000000000000000000000000000000000000C8");
        let contract_oracle = ArbitrumNitroDAGasOracle::new(oracle_addr, provider.clone());
        let cached_oracle = CachedNitroDAGasOracle::new(oracle_addr, provider);

        let block: BlockHashOrNumber = 262113260.into();
        compare_oracles_on_data(&contract_oracle, &cached_oracle, block, hash1, uo1.clone()).await;
        compare_oracles_on_data(&contract_oracle, &cached_oracle, block, hash2, uo2.clone()).await;

        let block: BlockHashOrNumber = 262113261.into();
        compare_oracles_on_data(&contract_oracle, &cached_oracle, block, hash1, uo1.clone()).await;
        compare_oracles_on_data(&contract_oracle, &cached_oracle, block, hash2, uo2.clone()).await;

        let block: BlockHashOrNumber = 262113262.into();
        compare_oracles_on_data(&contract_oracle, &cached_oracle, block, hash1, uo1).await;
        compare_oracles_on_data(&contract_oracle, &cached_oracle, block, hash2, uo2).await;
    }

    async fn compare_oracles(
        oracle_a: &impl DAGasOracle,
        oracle_b: &impl DAGasOracle,
        block: BlockHashOrNumber,
    ) {
        let (uo, hash) = test_uo_data_1();
        compare_oracles_on_data(oracle_a, oracle_b, block, hash, uo).await;
    }

    async fn compare_oracles_on_data(
        oracle_a: &impl DAGasOracle,
        oracle_b: &impl DAGasOracle,
        block: BlockHashOrNumber,
        hash: B256,
        data: Bytes,
    ) {
        let gas_price = 1;
        let to = Address::random();

        let gas_a = oracle_a
            .estimate_da_gas(hash, to, data.clone(), block, gas_price)
            .await
            .unwrap();
        let gas_b = oracle_b
            .estimate_da_gas(hash, to, data, block, gas_price)
            .await
            .unwrap();

        // Allow for some variance with oracle b being within 0.1% smaller than oracle a
        println!("gas_a: {}", gas_a);
        println!("gas_b: {}", gas_b);
        let ratio = gas_b as f64 / gas_a as f64;
        assert!((0.999..=1.000).contains(&ratio));
    }

    async fn compare_opt_and_local_bedrock(
        provider: impl AlloyProvider + Clone,
        block: BlockHashOrNumber,
    ) {
        let oracle_addr = address!("420000000000000000000000000000000000000F");

        let contract_oracle = OptimismBedrockDAGasOracle::new(oracle_addr, provider.clone());
        let local_oracle = LocalBedrockDAGasOracle::new(oracle_addr, provider);

        compare_oracles(&contract_oracle, &local_oracle, block).await;
    }

    async fn compare_arb_and_cached_on_data(
        provider: impl AlloyProvider + Clone,
        block: BlockHashOrNumber,
        hash: B256,
        data: Bytes,
    ) {
        let oracle_addr = address!("00000000000000000000000000000000000000C8");

        let contract_oracle = ArbitrumNitroDAGasOracle::new(oracle_addr, provider.clone());
        let cached_oracle = CachedNitroDAGasOracle::new(oracle_addr, provider);

        compare_oracles_on_data(&contract_oracle, &cached_oracle, block, hash, data).await;
    }

    fn opt_provider() -> impl AlloyProvider + Clone {
        ProviderBuilder::new()
            .on_http(
                format!("https://opt-sepolia.g.alchemy.com/v2/{}", get_api_key())
                    .parse()
                    .unwrap(),
            )
            .boxed()
    }

    fn arb_provider() -> impl AlloyProvider + Clone {
        ProviderBuilder::new()
            .on_http(
                format!("https://arb-mainnet.g.alchemy.com/v2/{}", get_api_key())
                    .parse()
                    .unwrap(),
            )
            .boxed()
    }

    fn test_uo_data_1() -> (Bytes, B256) {
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
        (
            puo.abi_encode().into(),
            b256!("0000000000000000000000000000000000000000000000000000000000000001"),
        )
    }

    fn test_uo_data_2() -> (Bytes, B256) {
        let puo = PackedUserOperation {
            sender: address!("f497A8026717FbbA3944c3dd2533c0716b7685e2"),
            nonce: uint!(0x24_U256), // changed this
            initCode: Bytes::default(),
            callData: bytes!("b61d27f6000000000000000000000000f497a8026717fbba3944c3dd2533c0716b7685e2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000004d087d28800000000000000000000000000000000000000000000000000000000"),
            accountGasLimits: b256!("000000000000000000000000000114fc0000000000000000000000000012c9b5"),
            preVerificationGas: U256::from(48916),
            gasFees: b256!("000000000000000000000000524121000000000000000000000000109a4a441a"),
            paymasterAndData: Bytes::default(),
            signature: bytes!("00"), // removed this, should result in different costs
        };
        (
            puo.abi_encode().into(),
            b256!("0000000000000000000000000000000000000000000000000000000000000002"),
        )
    }

    fn get_api_key() -> String {
        std::env::var("ALCHEMY_API_KEY").expect("ALCHEMY_API_KEY must be set")
    }
}
