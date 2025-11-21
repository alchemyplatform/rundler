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

//! JSON-RPC utilities

/// The error code for internal errors in JSON-RPC responses
pub const INTERNAL_ERROR_CODE: i64 = -32603;

/// Check if a JSON-RPC response indicates an execution revert
pub fn check_execution_reverted(message: &str) -> bool {
    message == "execution reverted"
}
