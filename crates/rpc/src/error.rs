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

use jsonrpsee::types::{ErrorObject, ErrorObjectOwned};
use serde::Serialize;

pub(crate) fn rpc_err(code: i32, msg: impl Into<String>) -> ErrorObjectOwned {
    create_rpc_err(code, msg, None::<()>)
}

pub(crate) fn rpc_err_with_data<S: Serialize>(
    code: i32,
    msg: impl Into<String>,
    data: S,
) -> ErrorObjectOwned {
    create_rpc_err(code, msg, Some(data))
}

fn create_rpc_err<S: Serialize>(
    code: i32,
    msg: impl Into<String>,
    data: Option<S>,
) -> ErrorObjectOwned {
    ErrorObject::owned(code, msg.into(), data)
}
