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

#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::EnumString)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE", ascii_case_insensitive)]
pub(crate) enum SubmissionProxyType {
    PassThrough,
    Pbh,
}

#[derive(Debug)]
pub(crate) struct PassThroughProxy {
    address: Address,
}

#[async_trait::async_trait]
impl SubmissionProxy for PassThroughProxy {
    fn address(&self) -> Address {
        self.address
    }

    async fn process_revert(
        &self,
        _revert_data: Bytes,
        _ops: Vec<UserOpsPerAggregator<UserOperationVariant>>,
    ) -> Vec<B256> {
        vec![]
    }
}

impl PassThroughProxy {
    pub(crate) fn new(address: Address) -> Self {
        Self { address }
    }
}
