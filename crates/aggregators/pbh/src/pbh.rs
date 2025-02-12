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
use alloy_sol_types::{sol, SolValue};
use rundler_provider::{AggregatorOut, SignatureAggregator as EpSignatureAggregator};
use rundler_types::{
    aggregator::{
        AggregatorCosts, SignatureAggregator, SignatureAggregatorError, SignatureAggregatorResult,
    },
    v0_7::UserOperation,
    UserOperationVariant,
};

sol! {
    struct PBHPayload {
        uint256 root;
        uint256 pbhExternalNullifier;
        uint256 nullifierHash;
        uint256[8] proof;
    }
}

const PBH_AGGREGATOR_ADDRESS: Address = address!("8c7b929F59267DfF86392F08D03DF40F04cf50b3");
// TODO(pbh): verify these values with onchain data
const PBH_AGGREGATOR_FIXED_GAS: u128 = 50_000;
const PBH_AGGREGATOR_VARIABLE_GAS: u128 = 200_000;

const PBH_AGGREGATOR_SIG_FIXED_LENGTH: u128 = 0;
const PBH_AGGREGATOR_SIG_VARIABLE_LENGTH: u128 = PBH_PROOF_LENGTH as u128;

const PBH_PROOF_LENGTH: usize = 352;

// 352 bytes of 0xFF
static PBH_DUMMY_UO_SIG: Bytes = bytes!("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
static PBH_AGGREGATOR_COSTS: AggregatorCosts = AggregatorCosts {
    execution_fixed_gas: PBH_AGGREGATOR_FIXED_GAS,
    execution_variable_gas: PBH_AGGREGATOR_VARIABLE_GAS,
    sig_fixed_length: PBH_AGGREGATOR_SIG_FIXED_LENGTH,
    sig_variable_length: PBH_AGGREGATOR_SIG_VARIABLE_LENGTH,
};

/// PBH signature aggregator
#[derive(Clone)]
pub struct PbhSignatureAggregator<EP> {
    entry_point: EP,
    address: Address,
}

#[async_trait::async_trait]
impl<EP> SignatureAggregator for PbhSignatureAggregator<EP>
where
    EP: EpSignatureAggregator<UO = UserOperation>,
{
    fn address(&self) -> Address {
        self.address
    }

    fn costs(&self) -> &AggregatorCosts {
        &PBH_AGGREGATOR_COSTS
    }

    fn dummy_uo_signature(&self) -> &Bytes {
        &PBH_DUMMY_UO_SIG
    }

    // TODO(pbh): Replace this with local proof validation
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
        uos: Vec<UserOperationVariant>,
    ) -> SignatureAggregatorResult<Bytes> {
        let mut agg_proofs = Vec::new();

        for user_op in uos {
            if !user_op.is_v0_7() {
                return Err(SignatureAggregatorError::InvalidUserOperation(
                    "User operation is not v0.7".to_string(),
                ));
            }
            let uo: UserOperation = user_op.clone().into();

            if uo.signature.len() < PBH_PROOF_LENGTH {
                return Err(SignatureAggregatorError::InvalidUserOperation(format!(
                    "User operation signature is not the correct length: {} < {}",
                    uo.signature.len(),
                    PBH_PROOF_LENGTH
                )));
            }

            let proof_start = uo.signature.len() - PBH_PROOF_LENGTH;
            agg_proofs.push(
                PBHPayload::abi_decode(&uo.signature[proof_start..], true).map_err(|e| {
                    SignatureAggregatorError::InvalidUserOperation(format!(
                        "Malformed PBH proof: {}",
                        e
                    ))
                })?,
            );
        }

        Ok(agg_proofs.abi_encode().into())
    }
}

impl<EP> PbhSignatureAggregator<EP> {
    /// Create a new PBH signature aggregator
    pub fn new(entry_point: EP, address_override: Option<Address>) -> Self {
        let address = address_override.unwrap_or(PBH_AGGREGATOR_ADDRESS);

        Self {
            entry_point,
            address,
        }
    }
}

impl<EP> Debug for PbhSignatureAggregator<EP> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PbhSignatureAggregator")
            .field("address", &self.address)
            .finish()
    }
}
