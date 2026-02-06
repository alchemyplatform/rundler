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
//! JSON-RPC server for the Rundler.

mod chain_resolver;
pub use chain_resolver::{ChainResolver, ResolvedChain};

/// Multi-chain gateway infrastructure.
pub mod gateway;
pub use gateway::{
    ChainBackend, ChainConfig, ChainId, ChainRouter, ChainRoutingLayer, ChainRoutingMiddleware,
    GatewayConfig,
};

mod debug;
pub use debug::{DebugApiClient, DebugApiServer};

mod admin;
pub use admin::{AdminApiClient, AdminApiServer};

mod error;

mod eth;
pub use eth::{EthApiClient, EthApiServer};

mod health;

mod rundler;
pub use rundler::{RundlerApiClient, RundlerApiServer, RundlerApiSettings};

mod task;
pub use task::{Args as RpcTaskArgs, RpcTask, build_rpc_module};

mod rpc_metrics;
mod types;
pub use types::{
    ApiNamespace, RpcAdminClearState, RpcAdminSetTracking, RpcBundlerSponsorship,
    RpcDebugPaymasterBalance, RpcGasEstimate, RpcGasEstimateV0_6, RpcGasEstimateV0_7,
    RpcMinedUserOperation, RpcReputationInput, RpcReputationOutput, RpcStakeInfo, RpcStakeStatus,
    RpcUserOperation, RpcUserOperationByHash, RpcUserOperationOptionalGas,
    RpcUserOperationOptionalGasV0_6, RpcUserOperationOptionalGasV0_7, RpcUserOperationPermissions,
    RpcUserOperationReceipt, RpcUserOperationV0_6, RpcUserOperationV0_7, convert_permissions,
    convert_user_operation, convert_user_operation_optional_gas, parse_user_operation,
    parse_user_operation_permissions, user_operation_to_json,
};
mod utils;
