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

use std::fs::File;

use rundler_types::{ChainSpec, OptionalChainSpec};

#[tokio::main]
async fn main() {
    let chain_spec = resolve_chain_spec(
        Some("arbitrum".to_string()),
        Some("chain_spec.yaml".to_string()),
    );
    println!("{:?}", chain_spec);
}

// Chain spec configuration precedence:
// 1. env vars (CHAIN_* prefixed)
// 2. file (--chain-spec-file)
// 3. preset network (--network)
//
// `ChainSpec` resolution precedence:
// 1. existing
// 2. base (if defined)
// 3. defaults

fn resolve_chain_spec(network: Option<String>, file: Option<String>) -> ChainSpec {
    let network_spec = get_network_spec(&network);

    let file_spec = match file {
        Some(file) => {
            let file = File::open(file).expect("should open file");
            serde_yaml::from_reader(file).expect("should parse yaml")
        }
        None => OptionalChainSpec::default(),
    };

    let env_spec = match envy::prefixed("CHAIN_").from_env::<OptionalChainSpec>() {
        Ok(config) => config,
        Err(error) => panic!("{:#?}", error),
    };

    let spec = env_spec.merge(file_spec).merge(network_spec);
    let base_spec = get_network_spec(&spec.base);
    spec.merge(base_spec).into()
}

fn get_network_spec(network: &Option<String>) -> OptionalChainSpec {
    match network.as_deref() {
        Some("arbitrum") => serde_yaml::from_str::<OptionalChainSpec>(ARBITRUM_SPEC)
            .expect("should parse ARBITRUM_SPEC yaml"),
        Some("polygon") => serde_yaml::from_str::<OptionalChainSpec>(POLYGON_SPEC)
            .expect("should parse POLYGON_SPEC yaml"),
        Some("polygon_mumbai") => serde_yaml::from_str::<OptionalChainSpec>(POLYGON_MUMBAI_SPEC)
            .expect("should parse POLYGON_MUMBAI_SPEC yaml"),
        _ => OptionalChainSpec::default(),
    }
}

const ARBITRUM_SPEC: &str = "
id: 42161
supports_eip1559: false
l1_gas_oracle_contract_type: ArbitrumNitro
l1_gas_oracle_contract_address: 0x00000000000000000000000000000000000000C8
";

const POLYGON_SPEC: &str = "
id: 137
use_fee_history_oracle: true
fee_history_oracle_blocks: 30
fee_history_oracle_percentile: 33.3
max_with_provider_fee: true
";

const POLYGON_MUMBAI_SPEC: &str = "
base: polygon
id: 80001
";
