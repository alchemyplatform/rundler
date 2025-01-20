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

// TODO: instantiate aggregators and pass to chain spec

use std::sync::Arc;

use rundler_bls::BlsSignatureAggregator;
use rundler_provider::Providers;
use rundler_types::{aggregator::SignatureAggregatorRegistry, chain::ChainSpec};

/// Instantiate aggregators and pass to chain spec
pub fn instantiate_aggregators(chain_spec: &mut ChainSpec, providers: &(impl Providers + 'static)) {
    let mut registry = SignatureAggregatorRegistry::default();
    let bls_aggregator = BlsSignatureAggregator::new(providers.ep_v0_7().as_ref().unwrap().clone());
    registry.register(Arc::new(bls_aggregator));

    chain_spec.set_signature_aggregators(Arc::new(registry));
}
