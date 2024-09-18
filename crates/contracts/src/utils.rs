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

use alloy_sol_macro::sol;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    GetCodeHashes,
    "contracts/out/utils/GetCodeHashes.sol/GetCodeHashes.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    GetGasUsed,
    "contracts/out/utils/GetGasUsed.sol/GetGasUsed.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    StorageLoader,
    "contracts/out/utils/StorageLoader.sol/StorageLoader.json"
);
