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
    // get sources
    let file_source = file.as_ref().map(|f| File::with_name(f.as_str()));
    let network_source = network.as_ref().map(|n| {
        File::from_str(
            get_hardcoded_chain_spec(n.to_lowercase().as_str()),
            FileFormat::Toml,
        )
    });

    // get the base config from the hierarchy of
    // - ENV
    // - file
    // - network flag
    let mut base_getter = Config::builder();
    if let Some(network_source) = &network_source {
        base_getter = base_getter.add_source(network_source.clone());
    }
    if let Some(file_source) = &file_source {
        base_getter = base_getter.add_source(file_source.clone());
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
        let base_spec = get_hardcoded_chain_spec(base.as_str());

        // base config must not have a base key, recursive base is not allowed
        Config::builder()
            .add_source(File::from_str(base_spec, FileFormat::Toml))
            .build()
            .expect("should build base config")
            .get::<String>("base")
            .expect_err("base config must not have a base key");

        config_builder = config_builder.add_source(File::from_str(base_spec, FileFormat::Toml));
    }
    if let Some(network_source) = network_source {
        config_builder = config_builder.add_source(network_source);
    }
    if let Some(file_source) = file_source {
        config_builder = config_builder.add_source(file_source);
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
    dev,
    ethereum,
    ethereum_sepolia,
    optimism,
    optimism_sepolia,
    base,
    base_sepolia,
    arbitrum,
    arbitrum_sepolia,
    polygon,
    polygon_amoy,
    avax,
    bera_bartio,
    avax_fuji
);
