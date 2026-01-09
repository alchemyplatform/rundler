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

use std::sync::Arc;

use rundler_bls::BlsSignatureAggregatorV0_7;
use rundler_pbh::PbhSignatureAggregator;
use rundler_provider::Providers;
use rundler_types::{
    EntryPointVersion,
    aggregator::SignatureAggregator,
    chain::{ChainSpec, ContractRegistry},
};

use super::CommonArgs;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
#[clap(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AggregatorType {
    Bls,
    Pbh,
}

/// Instantiate aggregators and pass to chain spec
pub fn instantiate_aggregators(
    args: &CommonArgs,
    chain_spec: &mut ChainSpec,
    providers: &(impl Providers + 'static),
) {
    let mut registry = ContractRegistry::<Arc<dyn SignatureAggregator>>::default();

    if args.enabled_aggregators.contains(&AggregatorType::Bls) {
        let bls_address = get_option_value(&args.aggregator_options, "BLS_ADDRESS")
            .map(|v| v.parse().expect("invalid BLS_ADDRESS"));

        let ep_v0_7 = providers
            .ep_v0_7(EntryPointVersion::V0_7)
            .as_ref()
            .expect("BLS aggregator requires entry point v0.7");
        let bls_aggregator = BlsSignatureAggregatorV0_7::new(ep_v0_7.clone(), bls_address);
        registry.register(bls_aggregator.address(), Arc::new(bls_aggregator));
    }

    if args.enabled_aggregators.contains(&AggregatorType::Pbh) {
        let pbh_address = get_option_value(&args.aggregator_options, "PBH_ADDRESS")
            .map(|v| v.parse().expect("invalid PBH_ADDRESS"));

        let ep_v0_7 = providers
            .ep_v0_7(EntryPointVersion::V0_7)
            .as_ref()
            .expect("PBH aggregator requires entry point v0.7");
        let pbh_aggregator = PbhSignatureAggregator::new(ep_v0_7.clone(), pbh_address);
        registry.register(pbh_aggregator.address(), Arc::new(pbh_aggregator));
    }

    chain_spec.set_signature_aggregators(Arc::new(registry));
}

fn get_option_value<'a>(options: &'a [(String, String)], key: &str) -> Option<&'a str> {
    options
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}
