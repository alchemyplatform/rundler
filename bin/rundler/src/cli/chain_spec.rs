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
use rundler_types::{chain::ChainSpec, v0_6::V06_SIMULATED_BUNDLE_MIN_PER_USER_OP_WORD_GAS};

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
    check_chain_spec(&chain_spec);
    chain_spec
}

fn check_chain_spec(chain_spec: &ChainSpec) {
    // The v0.6 bundle gas limit sized from simulation relies on the pre-verification gas
    // to cover copying the call data into memory
    if chain_spec.v06_bundle_gas_limit_from_simulation
        && chain_spec.per_user_op_word_gas < V06_SIMULATED_BUNDLE_MIN_PER_USER_OP_WORD_GAS
    {
        panic!(
            "per_user_op_word_gas must be at least {V06_SIMULATED_BUNDLE_MIN_PER_USER_OP_WORD_GAS} when v06_bundle_gas_limit_from_simulation is enabled, got {}",
            chain_spec.per_user_op_word_gas
        );
    }
    if let Err(e) = chain_spec.validate_gas_schedules() {
        panic!("{e:#}");
    }
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
    avax_fuji
);

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use rundler_types::chain::ForkActivation;

    use super::*;

    #[test]
    fn test_v06_bundle_gas_limit_from_simulation_only_on_avax() {
        // resolve_chain_spec applies CHAIN_* environment overrides on top of every spec
        if std::env::var_os("CHAIN_V06_BUNDLE_GAS_LIMIT_FROM_SIMULATION").is_some() {
            return;
        }
        for network in HARDCODED_CHAIN_SPECS {
            let chain_spec = resolve_chain_spec(&Some((*network).to_string()), &None);
            let expected = matches!(*network, "avax" | "avax_fuji");
            assert_eq!(
                chain_spec.v06_bundle_gas_limit_from_simulation, expected,
                "unexpected v06_bundle_gas_limit_from_simulation for {network}"
            );
        }
    }

    #[test]
    fn test_check_chain_spec_word_gas_with_v06_simulated_sizing() {
        check_chain_spec(&ChainSpec {
            v06_bundle_gas_limit_from_simulation: true,
            per_user_op_word_gas: V06_SIMULATED_BUNDLE_MIN_PER_USER_OP_WORD_GAS,
            ..Default::default()
        });
        // The default word gas is fine while the flag is off
        check_chain_spec(&ChainSpec::default());
    }

    #[test]
    #[should_panic(expected = "per_user_op_word_gas must be at least 17")]
    fn test_check_chain_spec_word_gas_too_low_with_v06_simulated_sizing() {
        check_chain_spec(&ChainSpec {
            v06_bundle_gas_limit_from_simulation: true,
            ..Default::default()
        });
    }

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
}
