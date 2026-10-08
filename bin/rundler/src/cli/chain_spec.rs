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
    resolve_chain_spec_with_env(network, file, Environment::with_prefix("CHAIN"))
}

fn resolve_chain_spec_with_env(
    network: &Option<String>,
    file: &Option<String>,
    env: Environment,
) -> ChainSpec {
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
        .add_source(env.clone())
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
        .add_source(env)
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

    let chain_spec: ChainSpec = c.try_deserialize().expect("should deserialize config");
    if let Err(e) = chain_spec.validate_gas_schedules() {
        panic!("{e:#}");
    }
    chain_spec
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
    ethereum_glamsterdam_devnet,
    optimism,
    optimism_sepolia,
    base,
    base_sepolia,
    arbitrum,
    arbitrum_sepolia,
    polygon,
    polygon_amoy,
    avax,
    avax_fuji
);

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use rundler_types::chain::ForkActivation;

    use super::*;

    fn resolve(network: &str, env: &[(&str, &str)]) -> ChainSpec {
        let env: HashMap<String, String> = env
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        resolve_chain_spec_with_env(
            &Some(network.to_string()),
            &None,
            Environment::with_prefix("CHAIN").source(Some(env)),
        )
    }

    #[test]
    fn glamsterdam_activation_defaults_to_never() {
        let spec = resolve("ethereum", &[]);
        assert_eq!(spec.glamsterdam_activation, ForkActivation::Never);
        assert_eq!(spec.glamsterdam_per_user_op_v0_7_gas, None);
    }

    #[test]
    fn network_sets_glamsterdam_activation() {
        let spec = resolve("ethereum_sepolia", &[]);
        assert_eq!(
            spec.glamsterdam_activation,
            ForkActivation::Timestamp(1791294816)
        );
        // inherited from the ethereum base spec
        assert!(spec.eip7623_enabled);
    }

    #[test]
    fn env_sets_glamsterdam_activation() {
        let spec = resolve(
            "ethereum",
            &[("CHAIN_GLAMSTERDAM_ACTIVATION", "1791294816")],
        );
        assert_eq!(
            spec.glamsterdam_activation,
            ForkActivation::Timestamp(1791294816)
        );

        let spec = resolve("ethereum", &[("CHAIN_GLAMSTERDAM_ACTIVATION", "genesis")]);
        assert_eq!(spec.glamsterdam_activation, ForkActivation::Genesis);
    }

    #[test]
    fn env_never_overrides_network_activation() {
        let spec = resolve(
            "ethereum_sepolia",
            &[("CHAIN_GLAMSTERDAM_ACTIVATION", "never")],
        );
        assert_eq!(spec.glamsterdam_activation, ForkActivation::Never);
    }

    #[test]
    fn env_sets_glamsterdam_override() {
        let spec = resolve(
            "ethereum",
            &[
                ("CHAIN_GLAMSTERDAM_ACTIVATION", "genesis"),
                ("CHAIN_GLAMSTERDAM_PER_USER_OP_V0_7_GAS", "40000"),
            ],
        );
        assert_eq!(spec.glamsterdam_per_user_op_v0_7_gas, Some(40_000));
        assert_eq!(spec.glamsterdam_gas_schedule().per_user_op_v0_7_gas, 40_000);
    }

    #[test]
    #[should_panic(expected = "should deserialize config")]
    fn malformed_activation_is_rejected() {
        resolve("ethereum", &[("CHAIN_GLAMSTERDAM_ACTIVATION", "soon")]);
    }

    #[test]
    #[should_panic(expected = "invalid Glamsterdam gas schedule")]
    fn invalid_glamsterdam_schedule_is_rejected() {
        resolve(
            "ethereum",
            &[
                ("CHAIN_GLAMSTERDAM_ACTIVATION", "genesis"),
                (
                    "CHAIN_GLAMSTERDAM_EIP7623_CALLDATA_FLOOR_ZERO_BYTE_GAS",
                    "1",
                ),
            ],
        );
    }

    #[test]
    fn all_hardcoded_specs_resolve() {
        for network in HARDCODED_CHAIN_SPECS {
            resolve(network, &[]);
        }
    }

    #[test]
    fn glamsterdam_devnet_activates_glamsterdam_at_genesis() {
        let spec = resolve("ethereum_glamsterdam_devnet", &[]);
        assert_eq!(spec.id, 7091047534);
        assert_eq!(spec.glamsterdam_activation, ForkActivation::Genesis);
        assert_eq!(spec.transaction_gas_limit(), 16_777_216);
        let spec = spec.at_timestamp(0);
        assert_eq!(spec.transaction_intrinsic_gas(), 15_000);
        assert_eq!(spec.zero_deposit_refund_gas(), 97_920);
    }
}
