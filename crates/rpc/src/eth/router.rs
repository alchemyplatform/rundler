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

use std::{
    collections::HashMap,
    fmt::{self, Debug},
    marker::PhantomData,
    sync::Arc,
};

use alloy_primitives::{Address, B256};
use rundler_provider::{EntryPoint, SimulationProvider, StateOverride, TransactionReceipt};
use rundler_sim::{GasEstimationError, GasEstimator};
use rundler_types::{
    EntryPointAbiVersion, EntryPointVersion, GasEstimate, UserOperation, UserOperationOptionalGas,
    UserOperationVariant,
};

use super::events::UserOperationEventProvider;
use crate::{
    eth::{EthRpcError, error::EthResult},
    types::{
        RpcGasEstimate, RpcGasEstimateV0_6, RpcGasEstimateV0_7, RpcUserOperationByHash,
        RpcUserOperationReceipt,
    },
};

#[derive(Default)]
pub(crate) struct EntryPointRouterBuilder {
    entry_points: HashMap<Address, Arc<dyn EntryPointRoute>>,
}

impl EntryPointRouterBuilder {
    pub(crate) fn add_route<R>(mut self, route: R) -> Self
    where
        R: EntryPointRoute + 'static,
    {
        self.entry_points.insert(route.address(), Arc::new(route));
        self
    }

    pub(crate) fn build(self) -> EntryPointRouter {
        EntryPointRouter {
            entry_points: self.entry_points,
        }
    }
}

#[derive(Clone)]
pub(crate) struct EntryPointRouter {
    entry_points: HashMap<Address, Arc<dyn EntryPointRoute>>,
}

impl fmt::Debug for EntryPointRouter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntryPointRouter")
            .field(
                "entry_points",
                &self.entry_points.keys().collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl EntryPointRouter {
    pub(crate) fn entry_points(&self) -> impl Iterator<Item = &Address> {
        self.entry_points.keys()
    }

    pub(crate) fn check_and_get_route(
        &self,
        entry_point: &Address,
        uo: &UserOperationVariant,
    ) -> EthResult<&Arc<dyn EntryPointRoute>> {
        let route = self.get_route(entry_point)?;

        match route.version().abi_version() {
            EntryPointAbiVersion::V0_6 => {
                if !matches!(uo, UserOperationVariant::V0_6(_)) {
                    return Err(EthRpcError::InvalidParams(format!(
                        "Invalid user operation for entry point: {:?}",
                        route.address()
                    )));
                }
            }
            EntryPointAbiVersion::V0_7 => {
                if !matches!(uo, UserOperationVariant::V0_7(_)) {
                    return Err(EthRpcError::InvalidParams(format!(
                        "Invalid user operation for entry point: {:?}",
                        route.address()
                    )));
                }
            }
        }

        Ok(route)
    }

    pub(crate) async fn get_mined_by_hash(
        &self,
        entry_point: &Address,
        hash: B256,
    ) -> EthResult<Option<RpcUserOperationByHash>> {
        self.get_route(entry_point)?
            .get_mined_by_hash(hash)
            .await
            .map_err(Into::into)
    }

    pub(crate) async fn get_mined_from_tx_receipt(
        &self,
        entry_point: &Address,
        uo_hash: B256,
        tx_receipt: TransactionReceipt,
    ) -> EthResult<Option<RpcUserOperationByHash>> {
        self.get_route(entry_point)?
            .get_mined_from_tx_receipt(uo_hash, tx_receipt)
            .await
            .map_err(Into::into)
    }

    pub(crate) async fn get_receipt(
        &self,
        entry_point: &Address,
        hash: B256,
        bundle_transaction: Option<B256>,
    ) -> EthResult<Option<RpcUserOperationReceipt>> {
        self.get_route(entry_point)?
            .get_receipt(hash, bundle_transaction)
            .await
            .map_err(Into::into)
    }

    pub(crate) async fn get_receipt_from_tx_receipt(
        &self,
        entry_point: &Address,
        uo_hash: B256,
        tx_receipt: TransactionReceipt,
    ) -> EthResult<Option<RpcUserOperationReceipt>> {
        self.get_route(entry_point)?
            .get_receipt_from_tx_receipt(uo_hash, tx_receipt)
            .await
            .map_err(Into::into)
    }

    pub(crate) async fn estimate_gas(
        &self,
        entry_point: &Address,
        uo: UserOperationOptionalGas,
        state_override: Option<StateOverride>,
    ) -> EthResult<RpcGasEstimate> {
        let route = self.get_route(entry_point)?;

        match route.version().abi_version() {
            EntryPointAbiVersion::V0_6 => {
                if !matches!(uo, UserOperationOptionalGas::V0_6(_)) {
                    return Err(EthRpcError::InvalidParams(format!(
                        "Invalid user operation for entry point: {:?}",
                        route.address()
                    )));
                }
                let e = route.estimate_gas(uo, state_override).await?;
                Ok(RpcGasEstimateV0_6::from(e).into())
            }
            EntryPointAbiVersion::V0_7 => {
                if !matches!(uo, UserOperationOptionalGas::V0_7(_)) {
                    return Err(EthRpcError::InvalidParams(format!(
                        "Invalid user operation for entry point: {:?}",
                        route.address()
                    )));
                }
                let e = route.estimate_gas(uo, state_override).await?;
                Ok(RpcGasEstimateV0_7::from(e).into())
            }
        }
    }

    pub(crate) async fn check_signature(
        &self,
        entry_point: &Address,
        uo: UserOperationVariant,
    ) -> EthResult<bool> {
        self.check_and_get_route(entry_point, &uo)?
            .check_signature(uo)
            .await
            .map_err(Into::into)
    }

    fn get_route(&self, entry_point: &Address) -> EthResult<&Arc<dyn EntryPointRoute>> {
        let route = self
            .entry_points
            .get(entry_point)
            .ok_or(EthRpcError::InvalidParams(format!(
                "No entry point found for address: {:?}",
                entry_point
            )))?;
        Ok(route)
    }
}

#[async_trait::async_trait]
pub(crate) trait EntryPointRoute: Send + Sync {
    fn version(&self) -> EntryPointVersion;
    fn address(&self) -> Address;

    async fn get_mined_by_hash(&self, hash: B256)
    -> anyhow::Result<Option<RpcUserOperationByHash>>;

    async fn get_mined_from_tx_receipt(
        &self,
        uo_hash: B256,
        tx_receipt: TransactionReceipt,
    ) -> anyhow::Result<Option<RpcUserOperationByHash>>;

    async fn get_receipt(
        &self,
        hash: B256,
        bundle_transaction: Option<B256>,
    ) -> anyhow::Result<Option<RpcUserOperationReceipt>>;

    async fn get_receipt_from_tx_receipt(
        &self,
        uo_hash: B256,
        tx_receipt: TransactionReceipt,
    ) -> anyhow::Result<Option<RpcUserOperationReceipt>>;

    async fn estimate_gas(
        &self,
        uo: UserOperationOptionalGas,
        state_override: Option<StateOverride>,
    ) -> Result<GasEstimate, GasEstimationError>;

    async fn check_signature(&self, uo: UserOperationVariant) -> anyhow::Result<bool>;
}

#[derive(Debug)]
pub(crate) struct EntryPointRouteImpl<UO, E, G, EV> {
    entry_point: E,
    gas_estimator: G,
    event_provider: EV,
    _uo_type: PhantomData<UO>,
}

#[async_trait::async_trait]
impl<UO, E, G, EV> EntryPointRoute for EntryPointRouteImpl<UO, E, G, EV>
where
    UO: UserOperation + From<UserOperationVariant>,
    E: EntryPoint + SimulationProvider<UO = UO>,
    G: GasEstimator<UserOperationOptionalGas = UO::OptionalGas>,
    G::UserOperationOptionalGas: From<UserOperationOptionalGas>,
    EV: UserOperationEventProvider,
{
    fn version(&self) -> EntryPointVersion {
        self.entry_point.version()
    }

    fn address(&self) -> Address {
        *self.entry_point.address()
    }

    async fn get_mined_by_hash(
        &self,
        hash: B256,
    ) -> anyhow::Result<Option<RpcUserOperationByHash>> {
        self.event_provider.get_mined_by_hash(hash).await
    }

    async fn get_mined_from_tx_receipt(
        &self,
        uo_hash: B256,
        tx_receipt: TransactionReceipt,
    ) -> anyhow::Result<Option<RpcUserOperationByHash>> {
        self.event_provider
            .get_mined_from_tx_receipt(uo_hash, tx_receipt)
            .await
    }

    async fn get_receipt(
        &self,
        hash: B256,
        bundle_transaction: Option<B256>,
    ) -> anyhow::Result<Option<RpcUserOperationReceipt>> {
        if let Some(bundle_transaction) = bundle_transaction {
            self.event_provider
                .get_receipt_from_tx_hash(hash, bundle_transaction)
                .await
        } else {
            self.event_provider.get_receipt(hash).await
        }
    }

    async fn get_receipt_from_tx_receipt(
        &self,
        uo_hash: B256,
        tx_receipt: TransactionReceipt,
    ) -> anyhow::Result<Option<RpcUserOperationReceipt>> {
        self.event_provider
            .get_receipt_from_tx_receipt(uo_hash, tx_receipt)
            .await
    }

    async fn estimate_gas(
        &self,
        uo: UserOperationOptionalGas,
        state_override: Option<StateOverride>,
    ) -> Result<GasEstimate, GasEstimationError> {
        self.gas_estimator
            .estimate_op_gas(uo.into(), state_override.unwrap_or_default())
            .await
    }

    async fn check_signature(&self, uo: UserOperationVariant) -> anyhow::Result<bool> {
        let output = self
            .entry_point
            .simulate_validation(uo.into(), None)
            .await??;

        Ok(!output.return_info.account_sig_failed)
    }
}

impl<UO, E, G, EP> EntryPointRouteImpl<UO, E, G, EP> {
    pub(crate) fn new(entry_point: E, gas_estimator: G, event_provider: EP) -> Self {
        Self {
            entry_point,
            gas_estimator,
            event_provider,
            _uo_type: PhantomData,
        }
    }
}
