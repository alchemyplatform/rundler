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

use config::{Config, Environment, File, FileFormat};
use paste::paste;
use rundler_types::chain::ChainSpec;

/// Resolve the chain spec from the network flag and a chain spec file
pub fn resolve_chain_spec(network: &Option<String>, file: &Option<String>) -> ChainSpec {
    // get the base config from the hierarchy of
    // - ENV
    // - file
    // - network flag

    let mut base_getter = Config::builder();
    if let Some(file) = &file {
        base_getter = base_getter.add_source(File::with_name(file.as_str()));
    }
    if let Some(network) = &network {
        base_getter = base_getter.add_source(File::from_str(
            get_hardcoded_chain_spec(network.to_lowercase().as_str()),
            FileFormat::Toml,
        ));
    }
    let base_config = base_getter
        .add_source(Environment::with_prefix("CHAIN"))
        .build()
        .expect("should build config");
    let base = base_config.get::<String>("base").ok();

    // construct the config from the hierarchy of
    // - ENV
    // - file
    // - network flag
    // - base (if defined)
    // - defaults

    let default = serde_json::to_string(&ChainSpec::default()).expect("should serialize to string");
    let mut config_builder =
        Config::builder().add_source(File::from_str(default.as_str(), FileFormat::Json));

    if let Some(base) = base {
        config_builder = config_builder.add_source(File::from_str(
            get_hardcoded_chain_spec(base.as_str()),
            FileFormat::Toml,
        ));
    }
    if let Some(file) = &file {
        config_builder = config_builder.add_source(File::with_name(file.as_str()));
    }
    if let Some(network) = &network {
        config_builder = config_builder.add_source(File::from_str(
            get_hardcoded_chain_spec(network.to_lowercase().as_str()),
            FileFormat::Toml,
        ));
    }
    let c = config_builder
        .add_source(Environment::with_prefix("CHAIN"))
        .build()
        .expect("should build config");

    let id = c.get::<u64>("id").ok();
    if let Some(id) = id {
        if id == 0 {
            panic!("chain id must be non-zero");
        }
    } else {
        panic!("chain id must be defined");
    }

    c.try_deserialize().expect("should deserialize config")
}

macro_rules! define_hardcoded_chain_specs {
    ($($network:ident),+) => {
        paste! {
            $(
                const [< $network:upper _SPEC >]: &str = include_str!(concat!("../../chain_specs/", stringify!($network), ".toml"));
            )+

            fn get_hardcoded_chain_spec(network: &str) -> &'static str {
                match network {
                    $(
                        stringify!($network) => [< $network:upper _SPEC >],
                    )+
                    _ => panic!("unknown hardcoded network: {}", network),
                }
            }

            pub const HARDCODED_CHAIN_SPECS: &[&'static str] = &[$(stringify!($network),)+];
        }
    };
}

define_hardcoded_chain_specs!(
    ethereum,
    ethereum_goerli,
    ethereum_sepolia,
    optimism,
    optimism_goerli,
    optimism_sepolia,
    base,
    base_goerli,
    base_sepolia,
    arbitrum,
    arbitrum_goerli,
    arbitrum_sepolia,
    polygon,
    polygon_mumbai,
    polygon_amoy
);
