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

use alloy_primitives::B256;
use futures_util::future;
use metrics::Histogram;
use rundler_provider::{
    BlockHashOrNumber, BlockId, DAGasProvider, EntryPoint, EvmProvider, FeeEstimator,
    ProviderResult,
};
use rundler_types::{AuthorityState, PvgState, UserOperation, chain::ChainSpec, da::DAGasData};
use rundler_utils::guard_timer::CustomTimerGuard;
use tracing::instrument;

/// Estimates only the DA gas portion for the given user operation
///
/// `random_op` is either the user operation submitted via `sendUserOperation`
/// or the user operation that was submitted via `estimateUserOperationGas` and filled
/// in via its `random_fill()` call. It is used to calculate the DA portion of the pre_verification_gas
/// on networks that require it.
///
/// Networks that require Data Availability (DA) pre_verification_gas are those that charge extra calldata fees
/// that can scale based on DA gas prices.
///
/// Returns estimated da gas
#[instrument(skip_all)]
async fn estimate_da_gas_only<UO: UserOperation, E: DAGasProvider<UO = UO>>(
    chain_spec: &ChainSpec,
    entry_point: &E,
    random_op: &UO,
    block: BlockHashOrNumber,
    gas_price: u128,
) -> anyhow::Result<u128> {
    // TODO(bundle): assuming a bundle size of 1
    let bundle_size = 1;

    let da_gas = if chain_spec.da_pre_verification_gas {
        entry_point
            .calc_da_gas(random_op.clone(), block, gas_price, bundle_size)
            .await?
            .0
    } else {
        0
    };

    Ok(da_gas)
}

/// Estimates only the DA gas portion for the given user operation with fee estimation
///
/// This function handles the gas price calculation internally and is meant to be called
/// from the estimation implementations.
///
/// Returns estimated da gas
#[instrument(skip_all)]
#[allow(clippy::too_many_arguments)]
pub async fn estimate_da_gas_with_fees<
    UO: UserOperation,
    E: DAGasProvider<UO = UO>,
    F: FeeEstimator,
>(
    chain_spec: &ChainSpec,
    entry_point: &E,
    fee_estimator: &F,
    random_op: &UO,
    max_fee_per_gas: Option<u128>,
    max_priority_fee_per_gas: Option<u128>,
    block: BlockHashOrNumber,
    pvg_timer: Histogram,
) -> anyhow::Result<u128> {
    let _timer = CustomTimerGuard::new(pvg_timer);
    let gas_price = if !chain_spec.da_pre_verification_gas {
        return Ok(0);
    } else {
        let block_hash = match block {
            BlockHashOrNumber::Hash(hash) => hash,
            BlockHashOrNumber::Number(_) => {
                return Err(anyhow::anyhow!(
                    "Block number not supported for fee estimation"
                ));
            }
        };
        let (bundle_fees, base_fee) = fee_estimator.required_bundle_fees(block_hash, None).await?;
        if let (Some(max_fee), Some(prio_fee)) = (
            max_fee_per_gas.filter(|fee| *fee != 0),
            max_priority_fee_per_gas.filter(|fee| *fee != 0),
        ) {
            std::cmp::min(max_fee, base_fee.saturating_add(prio_fee))
        } else {
            base_fee.saturating_add(bundle_fees.max_priority_fee_per_gas)
        }
    };

    estimate_da_gas_only(chain_spec, entry_point, random_op, block, gas_price).await
}

/// Calculate the required pre_verification_gas for the given user operation and the provided base fee.
///
/// The effective gas price is calculated as min(base_fee + max_priority_fee_per_gas, max_fee_per_gas)
#[instrument(skip_all)]
pub async fn calc_required_pre_verification_gas<UO: UserOperation, E: DAGasProvider<UO = UO>>(
    chain_spec: &ChainSpec,
    entry_point: &E,
    op: &UO,
    block_hash: B256,
    base_fee: u128,
    verification_efficiency_accept_threshold: f64,
    pvg_state: &PvgState,
) -> anyhow::Result<(u128, DAGasData)> {
    // TODO(bundle): assuming a bundle size of 1
    let bundle_size = 1;

    let (da_gas, uo_data) = if chain_spec.da_pre_verification_gas {
        let (da_gas, uo_data, _) = entry_point
            .calc_da_gas(
                op.clone(),
                block_hash.into(),
                op.gas_price(base_fee),
                bundle_size,
            )
            .await?;
        (da_gas, uo_data)
    } else {
        (0, DAGasData::Empty)
    };

    Ok((
        op.required_pre_verification_gas(
            chain_spec,
            bundle_size,
            da_gas,
            Some(verification_efficiency_accept_threshold),
            pvg_state,
        ),
        uo_data,
    ))
}

/// Reads the on-chain state that the state-dependent part of pre-verification gas depends on
/// (see [`UserOperation::state_pre_verification_gas`]).
///
/// Reads only what applies to `op`: the sender's EntryPoint deposit when it has no paymaster,
/// and the sender's code, nonce and balance when it carries an EIP-7702 authorization. Makes no
/// calls and returns [`PvgState::unknown`] when no gas schedule of the chain has state-dependent terms.
#[instrument(skip_all)]
pub async fn load_pvg_state<UO, P, E>(
    chain_spec: &ChainSpec,
    provider: &P,
    entry_point: &E,
    op: &UO,
    block: Option<BlockId>,
) -> ProviderResult<PvgState>
where
    UO: UserOperation,
    P: EvmProvider,
    E: EntryPoint,
{
    if !chain_spec.pvg_may_depend_on_state() {
        return Ok(PvgState::unknown());
    }
    let (sender_deposit_is_zero, authority) = future::try_join(
        sender_deposit_is_zero(entry_point, op, block),
        authority_state(provider, op, block),
    )
    .await?;

    Ok(PvgState {
        sender_deposit_is_zero,
        authority,
    })
}

async fn sender_deposit_is_zero<UO: UserOperation, E: EntryPoint>(
    entry_point: &E,
    op: &UO,
    block: Option<BlockId>,
) -> ProviderResult<Option<bool>> {
    // A paymaster pays and receives the refund; the sender's deposit is not written.
    if op.paymaster().is_some() {
        return Ok(None);
    }
    let deposit = entry_point.balance_of(op.sender(), block).await?;
    Ok(Some(deposit.is_zero()))
}

async fn authority_state<UO: UserOperation, P: EvmProvider>(
    provider: &P,
    op: &UO,
    block: Option<BlockId>,
) -> ProviderResult<Option<AuthorityState>> {
    if op.authorization_tuple().is_none() {
        return Ok(None);
    }
    let sender = op.sender();
    let (code, nonce, balance) = future::try_join3(
        provider.get_code(sender, block),
        provider.get_transaction_count(sender, block),
        provider.get_balance(sender, block),
    )
    .await?;
    Ok(Some(AuthorityState::from_account(&code, nonce, balance)))
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Address, Bytes, U256, bytes};
    use rundler_provider::{MockEntryPointV0_7, MockEvmProvider};
    use rundler_types::{
        EntryPointVersion,
        authorization::Eip7702Auth,
        chain::ForkActivation,
        v0_7::{
            UserOperation as UserOperationV0_7, UserOperationBuilder, UserOperationRequiredFields,
        },
    };

    use super::*;

    const SENDER: Address = Address::repeat_byte(0x11);

    fn glamsterdam_spec() -> ChainSpec {
        ChainSpec {
            glamsterdam_activation: ForkActivation::Genesis,
            ..ChainSpec::default()
        }
        .at_timestamp(0)
        .into_owned()
    }

    fn op(spec: &ChainSpec, paymaster: bool, authorization: bool) -> UserOperationV0_7 {
        let mut builder = UserOperationBuilder::new(
            spec,
            EntryPointVersion::V0_7,
            UserOperationRequiredFields {
                sender: SENDER,
                nonce: U256::ZERO,
                call_data: Bytes::new(),
                call_gas_limit: 0,
                verification_gas_limit: 100_000,
                pre_verification_gas: 0,
                max_priority_fee_per_gas: 1,
                max_fee_per_gas: 1,
                signature: Bytes::new(),
            },
        );
        if paymaster {
            builder = builder.paymaster(Address::repeat_byte(0x22), 50_000, 0, Bytes::new());
        }
        if authorization {
            builder = builder.authorization_tuple(Eip7702Auth::new_dummy(spec.id, Address::ZERO));
        }
        builder.build()
    }

    #[tokio::test]
    async fn load_pvg_state_makes_no_calls_before_glamsterdam() {
        let spec = ChainSpec::default();
        // No expectations: any call panics.
        let (provider, entry_point) = (MockEvmProvider::new(), MockEntryPointV0_7::new());
        let state = load_pvg_state(
            &spec,
            &provider,
            &entry_point,
            &op(&spec, false, true),
            None,
        )
        .await
        .unwrap();
        assert_eq!(state, PvgState::unknown());
    }

    #[tokio::test]
    async fn load_pvg_state_reads_self_paying_sender_deposit() {
        let spec = glamsterdam_spec();
        let provider = MockEvmProvider::new();
        let mut entry_point = MockEntryPointV0_7::new();
        entry_point
            .expect_balance_of()
            .withf(|address, _| *address == SENDER)
            .returning(|_, _| Ok(U256::ZERO));

        let state = load_pvg_state(
            &spec,
            &provider,
            &entry_point,
            &op(&spec, false, false),
            None,
        )
        .await
        .unwrap();
        assert_eq!(state.sender_deposit_is_zero, Some(true));
        assert_eq!(state.authority, None);
    }

    #[tokio::test]
    async fn load_pvg_state_reads_authority_but_not_paymaster_sponsored_deposit() {
        let spec = glamsterdam_spec();
        let mut provider = MockEvmProvider::new();
        provider
            .expect_get_code()
            .returning(|_, _| Ok(bytes!("ef01001234567890123456789012345678901234567890")));
        provider
            .expect_get_transaction_count()
            .returning(|_, _| Ok(3));
        provider
            .expect_get_balance()
            .returning(|_, _| Ok(U256::ZERO));
        // No balance_of expectation: a paymaster-sponsored op must not read the sender deposit.
        let entry_point = MockEntryPointV0_7::new();

        let state = load_pvg_state(&spec, &provider, &entry_point, &op(&spec, true, true), None)
            .await
            .unwrap();
        assert_eq!(state.sender_deposit_is_zero, None);
        assert_eq!(state.authority, Some(AuthorityState::HasCode));
    }

    #[tokio::test]
    async fn load_pvg_state_reads_authority_at_one_block() {
        let spec = glamsterdam_spec();
        let block = BlockId::hash(B256::repeat_byte(0x33));
        let at_block = move |b: &Option<BlockId>| *b == Some(block);
        let mut provider = MockEvmProvider::new();
        // Missing at the priced block; a nonce read at a later block would make it look existing.
        provider
            .expect_get_code()
            .withf(move |_, b| at_block(b))
            .returning(|_, _| Ok(Bytes::new()));
        provider
            .expect_get_transaction_count()
            .withf(move |_, b| at_block(b))
            .returning(|_, _| Ok(0));
        provider
            .expect_get_balance()
            .withf(move |_, b| at_block(b))
            .returning(|_, _| Ok(U256::ZERO));
        let entry_point = MockEntryPointV0_7::new();

        let state = load_pvg_state(
            &spec,
            &provider,
            &entry_point,
            &op(&spec, true, true),
            Some(block),
        )
        .await
        .unwrap();
        assert_eq!(state.authority, Some(AuthorityState::Missing));
    }

    #[tokio::test]
    async fn required_pvg_includes_state_gas_with_glamsterdam() {
        let spec = glamsterdam_spec();
        let uo = op(&spec, false, true);
        let missing = PvgState {
            sender_deposit_is_zero: Some(true),
            authority: Some(AuthorityState::Missing),
        };
        let funded = PvgState {
            sender_deposit_is_zero: Some(false),
            authority: Some(AuthorityState::HasCode),
        };
        let with_state = uo.required_pre_verification_gas(&spec, 1, 0, None, &missing);
        let without_state = uo.required_pre_verification_gas(&spec, 1, 0, None, &funded);
        assert_eq!(with_state - without_state, 97_920 + 35_190 + 183_600);
    }
}
