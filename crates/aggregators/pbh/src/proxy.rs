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

use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_sol_types::{sol, SolInterface, SolValue};
use rundler_types::{
    proxy::SubmissionProxy, UserOperation as _, UserOperationVariant, UserOpsPerAggregator,
};
use PBHEntryPoint::{InvalidExternalNullifier, InvalidNullifier, PBHEntryPointErrors};

sol! {
    contract PBHEntryPoint {
        error InvalidExternalNullifier(uint256 externalNullifier, uint256 signalHash, string reason);
        error InvalidNullifier(uint256 nullifierHash, uint256 signalHash);
    }
}

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
        revert_data: &Bytes,
        ops: &[UserOpsPerAggregator<UserOperationVariant>],
    ) -> Vec<B256> {
        let Ok(decoded) = PBHEntryPointErrors::abi_decode(revert_data) else {
            tracing::warn!("unknown revert data for PBH submission proxy: {revert_data:?}");
            return vec![];
        };

        let signal_hash = match decoded {
            PBHEntryPointErrors::InvalidExternalNullifier(InvalidExternalNullifier {
                externalNullifier,
                signalHash,
                reason,
            }) => {
                tracing::info!("PBH proxy decoded error: invalid external nullifier: {externalNullifier}, signal hash: {signalHash}, reason: {reason}");
                signalHash
            }
            PBHEntryPointErrors::InvalidNullifier(InvalidNullifier {
                nullifierHash,
                signalHash,
            }) => {
                tracing::info!("PBH proxy decoded error: invalid nullifier: {nullifierHash}, signal hash: {signalHash}");
                signalHash
            }
        };

        ops.iter()
            .flat_map(|a| a.user_ops.iter())
            .find(|uo| get_signal_hash(uo) == signal_hash)
            .map(|uo| {
                let uo_hash = uo.hash();
                tracing::info!(
                    "PBH proxy process_revert found invalid user operation: {uo_hash:?}"
                );
                vec![uo_hash]
            })
            .unwrap_or_default()
    }
}

fn get_signal_hash(uo: &UserOperationVariant) -> U256 {
    // ABI encode sender, nonce, call_data
    // keccak256 hash, shift right 8 bits to fit into field
    U256::from_be_bytes(
        alloy_primitives::keccak256(SolValue::abi_encode_packed(&(
            uo.sender(),
            uo.nonce(),
            uo.call_data(),
        )))
        .into(),
    ) >> 8
}

impl PbhSubmissionProxy {
    /// Create a new submission proxy
    pub fn new(address: Address) -> Self {
        Self { address }
    }
}
