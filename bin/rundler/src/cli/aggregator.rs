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
use rundler_provider::Providers;
use rundler_types::{aggregator::SignatureAggregatorRegistry, chain::ChainSpec};

use super::CommonArgs;

/// Instantiate aggregators and pass to chain spec
pub fn instantiate_aggregators(
    args: &CommonArgs,
    chain_spec: &mut ChainSpec,
    providers: &(impl Providers + 'static),
) {
    let mut registry = SignatureAggregatorRegistry::default();

    if args.bls_aggregation_enabled {
        if let Some(ep_v0_7) = providers.ep_v0_7() {
            let bls_aggregator = BlsSignatureAggregatorV0_7::new(ep_v0_7.clone());
            registry.register(Arc::new(bls_aggregator));
        }
    }

    chain_spec.set_signature_aggregators(Arc::new(registry));
}
