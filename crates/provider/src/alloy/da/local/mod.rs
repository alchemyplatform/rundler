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

use metrics::Gauge;
use metrics_derive::Metrics;

mod bedrock;
pub(crate) use bedrock::LocalBedrockDAGasOracle;

mod nitro;
pub(crate) use nitro::CachedNitroDAGasOracle;

#[derive(Metrics, Clone)]
#[metrics(scope = "provider_da")]
struct DAMetrics {
    #[metric(describe = "l1 base fee in wei (only bedrock)")]
    l1_base_fee: Gauge,
    #[metric(describe = "blob base fee in wei (only bedrock)")]
    blob_base_fee: Gauge,
    #[metric(describe = "per unit l1 fee in wei (only nitro)")]
    per_unit_l1_fee: Gauge,
}
