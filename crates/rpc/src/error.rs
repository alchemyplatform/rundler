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
