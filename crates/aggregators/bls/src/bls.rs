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

use std::fmt::Debug;

use alloy_primitives::{address, bytes, Address, Bytes};
use rundler_provider::{AggregatorOut, SignatureAggregator as EpSignatureAggregator};
use rundler_types::{
    aggregator::{
        AggregatorCosts, SignatureAggregator, SignatureAggregatorError, SignatureAggregatorResult,
    },
    UserOperationVariant,
};

const BLS_AGGREGATOR_ADDRESS: Address = address!("3d900228285c4e6c03f0de464eaded5e35c88b3c");
const BLS_DUMMY_SIG: Bytes = bytes!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

// TODO(danc): fill these out
const BLS_AGGREGATOR_FIXED_GAS: u128 = 1_000_000;
const BLS_AGGREGATOR_VARIABLE_GAS: u128 = 50_000;
const BLS_AGGREGATOR_SIG_FIXED_LENGTH: u128 = 64;
const BLS_AGGREGATOR_SIG_VARIABLE_LENGTH: u128 = 0;

/// BLS signature aggregator
pub struct BlsSignatureAggregator<EP, UO> {
    entry_point: EP,
    costs: AggregatorCosts,
    _phantom: std::marker::PhantomData<UO>,
}

#[async_trait::async_trait]
impl<EP, UO> SignatureAggregator for BlsSignatureAggregator<EP, UO>
where
    EP: EpSignatureAggregator<UO = UO>,
    UO: From<UserOperationVariant> + Send + Sync,
{
    fn address(&self) -> Address {
        BLS_AGGREGATOR_ADDRESS
    }

    fn costs(&self) -> &AggregatorCosts {
        &self.costs
    }

    fn dummy_uo_signature(&self) -> Bytes {
        BLS_DUMMY_SIG.clone()
    }

    async fn validate_user_op_signature(
        &self,
        user_op: &UserOperationVariant,
    ) -> SignatureAggregatorResult<Bytes> {
        let uo = user_op.clone().into();
        match self
            .entry_point
            .validate_user_op_signature(BLS_AGGREGATOR_ADDRESS, uo)
            .await
        {
            Ok(sig) => match sig {
                AggregatorOut::ValidationReverted => {
                    Err(SignatureAggregatorError::ValidationReverted)
                }
                AggregatorOut::SuccessWithInfo(into) => Ok(into.signature),
            },
            Err(e) => Err(SignatureAggregatorError::ProviderError(e.to_string())),
        }
    }

    async fn aggregate_signatures(
        &self,
        uos: &[UserOperationVariant],
    ) -> SignatureAggregatorResult<Bytes> {
        match self
            .entry_point
            .aggregate_signatures(
                BLS_AGGREGATOR_ADDRESS,
                // TODO(danc): fix all these clones
                uos.iter().map(|uo| uo.clone().into()).collect(),
            )
            .await
        {
            Ok(sig) => Ok(sig.unwrap_or_default()),
            Err(e) => Err(SignatureAggregatorError::ProviderError(e.to_string())),
        }
    }
}

impl<EP, UO> BlsSignatureAggregator<EP, UO> {
    /// Create a new BLS signature aggregator
    pub fn new(entry_point: EP) -> Self {
        Self {
            entry_point,
            costs: AggregatorCosts {
                execution_fixed_gas: BLS_AGGREGATOR_FIXED_GAS,
                execution_variable_gas: BLS_AGGREGATOR_VARIABLE_GAS,
                sig_fixed_length: BLS_AGGREGATOR_SIG_FIXED_LENGTH,
                sig_variable_length: BLS_AGGREGATOR_SIG_VARIABLE_LENGTH,
            },
            _phantom: Default::default(),
        }
    }
}

impl<EP, UO> Debug for BlsSignatureAggregator<EP, UO> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlsSignatureAggregator").finish()
    }
}
