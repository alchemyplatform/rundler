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

use ethers::types::H256;

use super::UserOperationEventProvider;
use crate::types::{RpcUserOperationByHash, RpcUserOperationReceipt};

#[derive(Debug)]
pub(crate) struct UserOperationEventProviderV0_7;

#[async_trait::async_trait]
impl UserOperationEventProvider for UserOperationEventProviderV0_7 {
    async fn get_mined_by_hash(
        &self,
        _hash: H256,
    ) -> anyhow::Result<Option<RpcUserOperationByHash>> {
        unimplemented!()
    }

    async fn get_receipt(&self, _hash: H256) -> anyhow::Result<Option<RpcUserOperationReceipt>> {
        unimplemented!()
    }
}
