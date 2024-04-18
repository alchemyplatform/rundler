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

use std::{fmt::Debug, marker::PhantomData, sync::Arc};

use ethers::types::{spoof, Address, H256};
use rundler_provider::{EntryPoint, SimulationProvider};
use rundler_sim::{GasEstimationError, GasEstimator};
use rundler_types::{
    EntryPointVersion, GasEstimate, UserOperation, UserOperationOptionalGas, UserOperationVariant,
};

use super::events::UserOperationEventProvider;
use crate::{
    eth::{error::EthResult, EthRpcError},
    types::{
        RpcGasEstimate, RpcGasEstimateV0_6, RpcGasEstimateV0_7, RpcUserOperationByHash,
        RpcUserOperationReceipt,
    },
};

#[derive(Default)]
pub(crate) struct EntryPointRouterBuilder {
    entry_points: Vec<Address>,
    v0_6: Option<(Address, Arc<dyn EntryPointRoute>)>,
    v0_7: Option<(Address, Arc<dyn EntryPointRoute>)>,
}

impl EntryPointRouterBuilder {
    pub(crate) fn v0_6<R>(mut self, route: R) -> Self
    where
        R: EntryPointRoute,
    {
        if route.version() != EntryPointVersion::V0_6 {
            panic!(
                "Invalid entry point version for route: {:?}",
                route.version()
            );
        }

        self.entry_points.push(route.address());
        self.v0_6 = Some((route.address(), Arc::new(route)));
        self
    }

    pub(crate) fn v0_7<R>(mut self, route: R) -> Self
    where
        R: EntryPointRoute,
    {
        if route.version() != EntryPointVersion::V0_7 {
            panic!(
                "Invalid entry point version for route: {:?}",
                route.version()
            );
        }

        self.entry_points.push(route.address());
        self.v0_7 = Some((route.address(), Arc::new(route)));
        self
    }

    pub(crate) fn build(self) -> EntryPointRouter {
        EntryPointRouter {
            entry_points: self.entry_points,
            v0_6: self.v0_6,
            v0_7: self.v0_7,
        }
    }
}

#[derive(Clone)]
pub(crate) struct EntryPointRouter {
    entry_points: Vec<Address>,
    v0_6: Option<(Address, Arc<dyn EntryPointRoute>)>,
    v0_7: Option<(Address, Arc<dyn EntryPointRoute>)>,
}

impl EntryPointRouter {
    pub(crate) fn entry_points(&self) -> impl Iterator<Item = &Address> {
        self.entry_points.iter()
    }

    pub(crate) fn check_and_get_route(
        &self,
        entry_point: &Address,
        uo: &UserOperationVariant,
    ) -> EthResult<&Arc<dyn EntryPointRoute>> {
        match self.get_ep_version(entry_point)? {
            EntryPointVersion::V0_6 => {
                if !matches!(uo, UserOperationVariant::V0_6(_)) {
                    return Err(EthRpcError::InvalidParams(format!(
                        "Invalid user operation for entry point: {:?}",
                        entry_point
                    )));
                }
                Ok(&self.v0_6.as_ref().unwrap().1)
            }
            EntryPointVersion::V0_7 => {
                if !matches!(uo, UserOperationVariant::V0_7(_)) {
                    return Err(EthRpcError::InvalidParams(format!(
                        "Invalid user operation for entry point: {:?}",
                        entry_point
                    )));
                }
                Ok(&self.v0_7.as_ref().unwrap().1)
            }
            EntryPointVersion::Unspecified => unreachable!("unspecified entry point version"),
        }
    }

    pub(crate) async fn get_mined_by_hash(
        &self,
        entry_point: &Address,
        hash: H256,
    ) -> EthResult<Option<RpcUserOperationByHash>> {
        self.get_route(entry_point)?
            .get_mined_by_hash(hash)
            .await
            .map_err(Into::into)
    }

    pub(crate) async fn get_receipt(
        &self,
        entry_point: &Address,
        hash: H256,
    ) -> EthResult<Option<RpcUserOperationReceipt>> {
        self.get_route(entry_point)?
            .get_receipt(hash)
            .await
            .map_err(Into::into)
    }

    pub(crate) async fn estimate_gas(
        &self,
        entry_point: &Address,
        uo: UserOperationOptionalGas,
        state_override: Option<spoof::State>,
    ) -> EthResult<RpcGasEstimate> {
        match self.get_ep_version(entry_point)? {
            EntryPointVersion::V0_6 => {
                if !matches!(uo, UserOperationOptionalGas::V0_6(_)) {
                    return Err(EthRpcError::InvalidParams(format!(
                        "Invalid user operation for entry point: {:?}",
                        entry_point
                    )));
                }

                let e = self
                    .v0_6
                    .as_ref()
                    .unwrap()
                    .1
                    .estimate_gas(uo, state_override)
                    .await?;

                Ok(RpcGasEstimateV0_6::from(e).into())
            }
            EntryPointVersion::V0_7 => {
                if !matches!(uo, UserOperationOptionalGas::V0_7(_)) {
                    return Err(EthRpcError::InvalidParams(format!(
                        "Invalid user operation for entry point: {:?}",
                        entry_point
                    )));
                }

                let e = self
                    .v0_7
                    .as_ref()
                    .unwrap()
                    .1
                    .estimate_gas(uo, state_override)
                    .await?;

                Ok(RpcGasEstimateV0_7::from(e).into())
            }
            EntryPointVersion::Unspecified => unreachable!("unspecified entry point version"),
        }
    }

    pub(crate) async fn check_signature(
        &self,
        entry_point: &Address,
        uo: UserOperationVariant,
        max_verification_gas: u64,
    ) -> EthResult<bool> {
        self.check_and_get_route(entry_point, &uo)?
            .check_signature(uo, max_verification_gas)
            .await
            .map_err(Into::into)
    }

    fn get_ep_version(&self, entry_point: &Address) -> EthResult<EntryPointVersion> {
        if let Some((addr, _)) = self.v0_6 {
            if addr == *entry_point {
                return Ok(EntryPointVersion::V0_6);
            }
        }
        if let Some((addr, _)) = self.v0_7 {
            if addr == *entry_point {
                return Ok(EntryPointVersion::V0_7);
            }
        }

        Err(EthRpcError::InvalidParams(format!(
            "No entry point found for address: {:?}",
            entry_point
        )))
    }

    fn get_route(&self, entry_point: &Address) -> EthResult<&Arc<dyn EntryPointRoute>> {
        let ep = self.get_ep_version(entry_point)?;

        match ep {
            EntryPointVersion::V0_6 => Ok(&self.v0_6.as_ref().unwrap().1),
            EntryPointVersion::V0_7 => Ok(&self.v0_7.as_ref().unwrap().1),
            EntryPointVersion::Unspecified => unreachable!("unspecified entry point version"),
        }
    }
}

#[async_trait::async_trait]
pub(crate) trait EntryPointRoute: Send + Sync + 'static {
    fn version(&self) -> EntryPointVersion;

    fn address(&self) -> Address;

    async fn get_mined_by_hash(&self, hash: H256)
        -> anyhow::Result<Option<RpcUserOperationByHash>>;

    async fn get_receipt(&self, hash: H256) -> anyhow::Result<Option<RpcUserOperationReceipt>>;

    async fn estimate_gas(
        &self,
        uo: UserOperationOptionalGas,
        state_override: Option<spoof::State>,
    ) -> Result<GasEstimate, GasEstimationError>;

    async fn check_signature(
        &self,
        uo: UserOperationVariant,
        max_verification_gas: u64,
    ) -> anyhow::Result<bool>;
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
        UO::entry_point_version()
    }

    fn address(&self) -> Address {
        self.entry_point.address()
    }

    async fn get_mined_by_hash(
        &self,
        hash: H256,
    ) -> anyhow::Result<Option<RpcUserOperationByHash>> {
        self.event_provider.get_mined_by_hash(hash).await
    }

    async fn get_receipt(&self, hash: H256) -> anyhow::Result<Option<RpcUserOperationReceipt>> {
        self.event_provider.get_receipt(hash).await
    }

    async fn estimate_gas(
        &self,
        uo: UserOperationOptionalGas,
        state_override: Option<spoof::State>,
    ) -> Result<GasEstimate, GasEstimationError> {
        self.gas_estimator
            .estimate_op_gas(uo.into(), state_override.unwrap_or_default())
            .await
    }

    async fn check_signature(
        &self,
        uo: UserOperationVariant,
        max_verification_gas: u64,
    ) -> anyhow::Result<bool> {
        let output = self
            .entry_point
            .call_simulate_validation(uo.into(), max_verification_gas, None)
            .await?;

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
