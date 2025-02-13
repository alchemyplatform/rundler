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
use rundler_types::{proxy::SubmissionProxy, UserOperationVariant, UserOpsPerAggregator};

/// Submission proxy for the PBH aggregator
#[derive(Debug)]
pub struct PbhSubmissionProxy {
    address: Address,
}

#[async_trait::async_trait]
impl SubmissionProxy for PbhSubmissionProxy {
    fn address(&self) -> Address {
        self.address
    }

    async fn process_revert(
        &self,
        revert_data: Bytes,
        _ops: Vec<UserOpsPerAggregator<UserOperationVariant>>,
    ) -> Vec<B256> {
        tracing::info!(
            "PBH submission proxy received revert data, processing unimplemented: {revert_data:?}"
        );
        vec![]
    }
}

impl PbhSubmissionProxy {
    /// Create a new submission proxy
    pub fn new(address: Address) -> Self {
        Self { address }
    }
}
