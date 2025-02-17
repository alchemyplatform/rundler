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

//! Signature aggregator types and registry

use std::fmt::Debug;

use alloy_primitives::{Address, Bytes};

use crate::UserOperationVariant;

/// Costs associated with an aggregator
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AggregatorCosts {
    /// Fixed gas of the aggregator's `validateSignatures` function
    pub execution_fixed_gas: u128,
    /// Variable gas of the aggregator's `validateSignatures` function
    pub execution_variable_gas: u128,
    /// Fixed length of the aggregated signature
    pub sig_fixed_length: u128,
    /// Variable length of the aggregated signature
    pub sig_variable_length: u128,
}

/// Signature aggregator errors
#[derive(Debug, thiserror::Error)]
pub enum SignatureAggregatorError {
    /// Aggregator is not supported
    #[error("Unsupported aggregator: {0}")]
    UnsupportedAggregator(Address),
    /// Signature validation reverted
    #[error("Signature validation reverted: {0}")]
    ValidationReverted(Bytes),
    /// Invalid user operation
    #[error("Invalid user operation: {0}")]
    InvalidUserOperation(String),
    /// Provider error
    #[error("Provider error: {0}")]
    ProviderError(String),
}

/// Result type for signature aggregator functions
pub type SignatureAggregatorResult<T> = Result<T, SignatureAggregatorError>;

/// Trait for signature aggregators
#[async_trait::async_trait]
#[auto_impl::auto_impl(&, &mut, Rc, Arc, Box)]
pub trait SignatureAggregator: Sync + Send + Debug {
    /// Onchain address of the aggregator
    fn address(&self) -> Address;

    /// Costs associated with the aggregator
    fn costs(&self) -> &AggregatorCosts;

    /// Dummy signature for the aggregator
    fn dummy_uo_signature(&self) -> &Bytes;

    /// Validate the signature of a user operation
    async fn validate_user_op_signature(
        &self,
        user_op: &UserOperationVariant,
    ) -> SignatureAggregatorResult<Bytes>;

    /// Aggregate multiple signatures
    async fn aggregate_signatures(
        &self,
        uos: Vec<UserOperationVariant>,
    ) -> SignatureAggregatorResult<Bytes>;
}

#[cfg(feature = "test-utils")]
mockall::mock! {
    #[derive(Debug)]
    pub SignatureAggregator {}

    #[async_trait::async_trait]
    impl SignatureAggregator for SignatureAggregator {
        /// Onchain address of the aggregator
        fn address(&self) -> Address;

        /// Costs associated with the aggregator
        fn costs(&self) -> &AggregatorCosts;

        /// Dummy signature for the aggregator
        fn dummy_uo_signature(&self) -> &Bytes;

        /// Validate the signature of a user operation
        async fn validate_user_op_signature(
            &self,
            user_op: &UserOperationVariant,
        ) -> SignatureAggregatorResult<Bytes>;

        /// Aggregate multiple signatures
        async fn aggregate_signatures(
            &self,
            uos: Vec<UserOperationVariant>,
        ) -> SignatureAggregatorResult<Bytes>;
    }
}
