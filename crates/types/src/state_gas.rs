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

//! EIP-8037 state gas: how a user operation's state gas is paid for.

use serde::{Deserialize, Serialize};

/// EIP-7825 `TX_MAX_GAS_LIMIT`: the most execution gas a transaction can use.
///
/// Under EIP-8037, transaction gas above this limit becomes the state-gas reservoir, which state
/// charges draw from first and which `gasleft()` does not see.
pub const TX_MAX_GAS_LIMIT: u64 = 1 << 24;

/// How a user operation's EIP-8037 state gas is paid for.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StateGasMode {
    /// The bundle transaction stays within [`TX_MAX_GAS_LIMIT`], so the reservoir is empty: state
    /// gas is charged within the op's verification and call gas limits, and the EntryPoint
    /// meters it like execution gas.
    #[default]
    Metered,
    /// The op is bundled alone with `tx.gas = TX_MAX_GAS_LIMIT + S`, so its state gas `S` comes
    /// from the reservoir. The EntryPoint does not see it, so the op pays for it through
    /// preVerificationGas, and its gas limits cover execution only.
    Reservoir,
}
