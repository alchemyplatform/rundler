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

#![warn(missing_docs, unreachable_pub, unused_crate_dependencies)]
#![deny(unused_must_use, rust_2018_idioms)]
#![doc(test(
    no_crate_inject,
    attr(deny(warnings, rust_2018_idioms), allow(dead_code, unused_variables))
))]

//! Rundler providers
//! A provider is a type that provides access to blockchain data and functions

mod alloy;
pub use alloy::{
    entry_point::{
        v0_6::{
            decode_ops_from_calldata as decode_v0_6_ops_from_calldata,
            EntryPointProvider as AlloyEntryPointV0_6,
        },
        v0_7::{
            decode_ops_from_calldata as decode_v0_7_ops_from_calldata,
            decode_validation_revert as decode_v0_7_validation_revert,
            EntryPointProvider as AlloyEntryPointV0_7,
        },
    },
    evm::AlloyEvmProvider,
    new_alloy_da_gas_oracle, new_alloy_evm_provider, new_alloy_provider,
};
mod fees;
pub use alloy_provider::network::{AnyHeader, AnyNetwork, AnyReceiptEnvelope, AnyTxEnvelope};
pub use alloy_serde::WithOtherFields;
use alloy_transport::{BoxTransport, Transport};
pub use fees::new_fee_estimator;
mod traits;
// re-export alloy RPC types
use std::marker::PhantomData;

pub use alloy_consensus::{ReceiptWithBloom, Transaction as TransactionTrait};
pub use alloy_json_rpc::{RpcParam, RpcReturn};
pub use alloy_network::TransactionBuilder;
pub use alloy_rpc_types_eth::{
    state::{AccountOverride, StateOverride},
    BlockHashOrNumber, BlockId, BlockNumberOrTag, FeeHistory, Filter, FilterBlockOption,
    Header as BlockHeader, Log, RpcBlockHash,
};
pub use alloy_rpc_types_trace::geth::{
    CallConfig as GethDebugTracerCallConfig, CallFrame as GethDebugTracerCallFrame,
    GethDebugBuiltInTracerType, GethDebugTracerType, GethDebugTracingCallOptions,
    GethDebugTracingOptions, GethTrace,
};
// re-export contract types
pub use rundler_contracts::utils::GetGasUsed::GasUsedResult;
use rundler_types::{
    v0_6::UserOperation as UserOperationV0_6, v0_7::UserOperation as UserOperationV0_7,
    UserOperation, UserOperationVariant,
};
#[cfg(any(test, feature = "test-utils"))]
pub use traits::test_utils::*;
pub use traits::*;

/// Transaction request type for all networks.
pub type TransactionRequest = alloy_rpc_types_eth::TransactionRequest;
/// Transaction receipt type for all networks.
pub type TransactionReceipt = alloy_rpc_types_eth::TransactionReceipt<AnyReceiptEnvelope<Log>>;
/// Transaction type for all networks.
pub type Transaction = alloy_rpc_types_eth::Transaction<AnyTxEnvelope>;
/// Block type for all networks.
pub type Block = alloy_rpc_types_eth::Block<
    WithOtherFields<Transaction>,
    alloy_rpc_types_eth::Header<AnyHeader>,
>;
/// Alloy provider type for all networks.
pub trait AlloyProvider<T: Transport + Clone = BoxTransport>:
    alloy_provider::Provider<T, AnyNetwork> + Clone
{
}
impl<T: Transport + Clone, AP: alloy_provider::Provider<T, AnyNetwork> + Clone> AlloyProvider<T>
    for AP
{
}

/// A trait that provides access to various providers.
pub trait Providers: Send + Sync + Clone {
    /// The EVM provider.
    type Evm: EvmProvider + Clone;

    /// The entry point provider for v0.6.
    type EntryPointV0_6: EntryPointProvider<UserOperationV0_6> + Clone;

    /// The entry point provider for v0.7.
    type EntryPointV0_7: EntryPointProvider<UserOperationV0_7> + Clone;

    /// The DA gas oracle provider.
    type DAGasOracle: DAGasOracle + Clone;

    /// The DA gas oracle sync provider.
    type DAGasOracleSync: DAGasOracleSync + Clone;

    /// The fee estimator.
    type FeeEstimator: FeeEstimator + Clone;

    /// Returns the EVM provider.
    fn evm(&self) -> &Self::Evm;

    /// Returns the entry point provider for v0.6.
    fn ep_v0_6(&self) -> &Option<Self::EntryPointV0_6>;

    /// Returns the entry point provider for v0.7.
    fn ep_v0_7(&self) -> &Option<Self::EntryPointV0_7>;

    /// Returns the DA gas oracle.
    fn da_gas_oracle(&self) -> &Self::DAGasOracle;

    /// Returns the DA gas oracle sync provider.
    fn da_gas_oracle_sync(&self) -> &Option<Self::DAGasOracleSync>;

    /// Returns the fee estimator.
    fn fee_estimator(&self) -> &Self::FeeEstimator;

    /// Returns the providers with the entry point for v0.6.
    #[allow(clippy::type_complexity)]
    fn ep_v0_6_providers(
        &self,
    ) -> Option<
        ProvidersWithEntryPoint<
            UserOperationV0_6,
            Self::Evm,
            Self::EntryPointV0_6,
            Self::DAGasOracleSync,
            Self::FeeEstimator,
        >,
    > {
        self.ep_v0_6().as_ref().map(|ep| ProvidersWithEntryPoint {
            evm: self.evm().clone(),
            ep: ep.clone(),
            da_gas_oracle_sync: self.da_gas_oracle_sync().clone(),
            fee_estimator: self.fee_estimator().clone(),
            _phantom: PhantomData,
        })
    }

    /// Returns the providers with the entry point for v0.7.
    #[allow(clippy::type_complexity)]
    fn ep_v0_7_providers(
        &self,
    ) -> Option<
        ProvidersWithEntryPoint<
            UserOperationV0_7,
            Self::Evm,
            Self::EntryPointV0_7,
            Self::DAGasOracleSync,
            Self::FeeEstimator,
        >,
    > {
        self.ep_v0_7().as_ref().map(|ep| ProvidersWithEntryPoint {
            evm: self.evm().clone(),
            ep: ep.clone(),
            da_gas_oracle_sync: self.da_gas_oracle_sync().clone(),
            fee_estimator: self.fee_estimator().clone(),
            _phantom: PhantomData,
        })
    }
}

/// Trait for providers with a specific entry point.
pub trait ProvidersWithEntryPointT: Send + Sync + Clone {
    /// User operation type.
    type UO: UserOperation + From<UserOperationVariant> + Into<UserOperationVariant>;

    /// The EVM provider.
    type Evm: EvmProvider + Clone;

    /// The entry point provider.
    type EntryPoint: EntryPointProvider<Self::UO> + Clone;

    /// The DA gas oracle sync provider.
    type DAGasOracleSync: DAGasOracleSync + Clone;

    /// The fee estimator.
    type FeeEstimator: FeeEstimator + Clone;

    /// Returns the EVM provider.
    fn evm(&self) -> &Self::Evm;

    /// Returns the entry point provider.
    fn entry_point(&self) -> &Self::EntryPoint;

    /// Returns the DA gas oracle sync provider.
    fn da_gas_oracle_sync(&self) -> &Option<Self::DAGasOracleSync>;

    /// Returns the fee estimator.
    fn fee_estimator(&self) -> &Self::FeeEstimator;
}

/// Container for providers with a specific entry point.
#[derive(Clone)]
pub struct ProvidersWithEntryPoint<UO, E, EP, D, F> {
    evm: E,
    ep: EP,
    da_gas_oracle_sync: Option<D>,
    fee_estimator: F,
    _phantom: PhantomData<UO>,
}

impl<UO, E, EP, D, F> ProvidersWithEntryPoint<UO, E, EP, D, F> {
    /// Create a new ProvidersWithEntryPoint.
    pub fn new(evm: E, ep: EP, da_gas_oracle_sync: Option<D>, fee_estimator: F) -> Self {
        Self {
            evm,
            ep,
            da_gas_oracle_sync,
            fee_estimator,
            _phantom: PhantomData,
        }
    }
}

impl<UO, E, EP, D, F> ProvidersWithEntryPointT for ProvidersWithEntryPoint<UO, E, EP, D, F>
where
    UO: UserOperation + From<UserOperationVariant> + Into<UserOperationVariant>,
    E: EvmProvider + Clone,
    EP: EntryPointProvider<UO> + Clone,
    D: DAGasOracleSync + Clone,
    F: FeeEstimator + Clone,
{
    type UO = UO;
    type Evm = E;
    type EntryPoint = EP;
    type DAGasOracleSync = D;
    type FeeEstimator = F;

    fn evm(&self) -> &Self::Evm {
        &self.evm
    }

    fn entry_point(&self) -> &Self::EntryPoint {
        &self.ep
    }

    fn da_gas_oracle_sync(&self) -> &Option<Self::DAGasOracleSync> {
        &self.da_gas_oracle_sync
    }

    fn fee_estimator(&self) -> &Self::FeeEstimator {
        &self.fee_estimator
    }
}
