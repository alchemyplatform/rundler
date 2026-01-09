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

use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::{SolCall, SolInterface, sol};

// From https://github.com/mds1/multicall
sol! {
    #[sol(rpc)]
    interface Multicall3 {
        struct Call3 {
            address target;
            bool allowFailure;
            bytes callData;
        }

        struct Call3Value {
            address target;
            bool allowFailure;
            uint256 value;
            bytes callData;
        }

        struct Result {
            bool success;
            bytes returnData;
        }

        function aggregate3(Call3[] calldata calls) public payable returns (Result[] memory returnData);
        function aggregate3Value(Call3Value[] calldata calls) public payable returns (Result[] memory returnData);
    }
}

pub fn create_call(target: Address, call: impl SolInterface) -> Multicall3::Call3 {
    Multicall3::Call3 {
        target,
        allowFailure: false,
        callData: call.abi_encode().into(),
    }
}

pub fn create_call_value(
    target: Address,
    value: U256,
    call: impl SolInterface,
) -> Multicall3::Call3Value {
    Multicall3::Call3Value {
        target,
        allowFailure: false,
        value,
        callData: call.abi_encode().into(),
    }
}

pub fn create_call_value_only(target: Address, value: U256) -> Multicall3::Call3Value {
    Multicall3::Call3Value {
        target,
        allowFailure: false,
        value,
        callData: Bytes::new(),
    }
}

pub fn decode_result<T: SolCall>(data: &[u8]) -> Result<T::Return, alloy_contract::Error> {
    T::abi_decode_returns(data).map_err(Into::into)
}
