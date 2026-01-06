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

use alloy_primitives::{Address, Bytes, address, bytes};
use rundler_provider::{AggregatorOut, SignatureAggregator as EpSignatureAggregator};
use rundler_types::{
    UserOperationVariant,
    aggregator::{
        AggregatorCosts, SignatureAggregator, SignatureAggregatorError, SignatureAggregatorResult,
    },
    v0_7::UserOperation,
};

const BLS_AGGREGATOR_ADDRESS: Address = address!("9d3a231e887a495ce6c454e7a38ed5e734bd5de4");
const BLS_AGGREGATOR_FIXED_GAS: u128 = 125_000;
const BLS_AGGREGATOR_VARIABLE_GAS: u128 = 120_000;
const BLS_AGGREGATOR_SIG_FIXED_LENGTH: u128 = 64;
const BLS_AGGREGATOR_SIG_VARIABLE_LENGTH: u128 = 0;

static BLS_DUMMY_UO_SIG: Bytes = bytes!(""); // UO signatures are empty for BLS
static BLS_AGGREGATOR_COSTS: AggregatorCosts = AggregatorCosts {
    execution_fixed_gas: BLS_AGGREGATOR_FIXED_GAS,
    execution_variable_gas: BLS_AGGREGATOR_VARIABLE_GAS,
    sig_fixed_length: BLS_AGGREGATOR_SIG_FIXED_LENGTH,
    sig_variable_length: BLS_AGGREGATOR_SIG_VARIABLE_LENGTH,
};

/// BLS signature aggregator
pub struct BlsSignatureAggregatorV0_7<EP> {
    entry_point: EP,
    address: Address,
}

#[async_trait::async_trait]
impl<EP> SignatureAggregator for BlsSignatureAggregatorV0_7<EP>
where
    EP: EpSignatureAggregator<UO = UserOperation>,
{
    fn address(&self) -> Address {
        self.address
    }

    fn costs(&self) -> &AggregatorCosts {
        &BLS_AGGREGATOR_COSTS
    }

    fn dummy_uo_signature(&self) -> &Bytes {
        &BLS_DUMMY_UO_SIG
    }

    async fn validate_user_op_signature(
        &self,
        user_op: &UserOperationVariant,
    ) -> SignatureAggregatorResult<Bytes> {
        if !user_op.is_v0_7() {
            return Err(SignatureAggregatorError::InvalidUserOperation(
                "User operation is not v0.7".to_string(),
            ));
        }

        let uo = user_op.clone().into();
        match self
            .entry_point
            .validate_user_op_signature(self.address, uo)
            .await
        {
            Ok(sig) => match sig {
                AggregatorOut::ValidationReverted(revert) => {
                    Err(SignatureAggregatorError::ValidationReverted(revert))
                }
                AggregatorOut::SuccessWithInfo(into) => Ok(into.signature),
            },
            Err(e) => Err(SignatureAggregatorError::ProviderError(e.to_string())),
        }
    }

    async fn aggregate_signatures(
        &self,
        uos: Vec<UserOperationVariant>,
    ) -> SignatureAggregatorResult<Bytes> {
        let uos = uos
            .into_iter()
            .map(|uo| {
                if !uo.is_v0_7() {
                    Err(SignatureAggregatorError::InvalidUserOperation(
                        "User operation is not v0.7".to_string(),
                    ))
                } else {
                    Ok(uo.into())
                }
            })
            .collect::<SignatureAggregatorResult<Vec<UserOperation>>>()?;

        match self
            .entry_point
            .aggregate_signatures(self.address, uos)
            .await
        {
            Ok(sig) => Ok(sig.unwrap_or_default()),
            Err(e) => Err(SignatureAggregatorError::ProviderError(e.to_string())),
        }
    }
}

impl<EP> BlsSignatureAggregatorV0_7<EP> {
    /// Create a new BLS signature aggregator
    pub fn new(entry_point: EP, address_override: Option<Address>) -> Self {
        let address = address_override.unwrap_or(BLS_AGGREGATOR_ADDRESS);

        Self {
            entry_point,
            address,
        }
    }
}

impl<EP> Debug for BlsSignatureAggregatorV0_7<EP> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlsSignatureAggregator")
            .field("address", &self.address)
            .finish()
    }
}
