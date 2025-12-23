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

//! Submission proxy types

use std::fmt::Debug;

use alloy_primitives::{Address, Bytes};

use crate::{UserOperationId, UserOperationVariant, UserOpsPerAggregator};

/// Submission proxy trait
#[async_trait::async_trait]
#[auto_impl::auto_impl(&, &mut, Rc, Arc, Box)]
pub trait SubmissionProxy: Sync + Send + Debug {
    /// Onchain address of the submission proxy
    fn address(&self) -> Address;

    /// Process a revert from a submission proxy and return the hashes of ops that should be rejected
    async fn process_revert(
        &self,
        revert_data: &Bytes,
        ops: &[UserOpsPerAggregator<UserOperationVariant>],
    ) -> Vec<UserOperationId>;
}

#[cfg(feature = "test-utils")]
mockall::mock! {
    #[derive(Debug)]
    pub SubmissionProxy {}

    #[async_trait::async_trait]
    impl SubmissionProxy for SubmissionProxy {
        fn address(&self) -> Address;

        async fn process_revert(
            &self,
            revert_data: &Bytes,
            ops: &[UserOpsPerAggregator<UserOperationVariant>],
        ) -> Vec<UserOperationId>;
    }
}
