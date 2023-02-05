use crate::common::types::UserOperation as RpcUserOperation;
use ethers::types::{Address, Bytes};
use primitive_types::U256;
use std::mem;

pub mod core {
    tonic::include_proto!("core");

    pub const CORE_FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("core_descriptor");
}

pub mod op_pool {
    tonic::include_proto!("op_pool");

    pub const OP_POOL_FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("op_pool_descriptor");
}

pub mod common {
    use super::*;

    tonic::include_proto!("common");

    impl From<&RpcUserOperation> for UserOperation {
        fn from(op: &RpcUserOperation) -> Self {
            UserOperation {
                sender: op.sender.0.to_vec(),
                nonce: to_le_bytes(op.nonce),
                init_code: op.init_code.to_vec(),
                call_data: op.call_data.to_vec(),
                call_gas_limit: to_le_bytes(op.call_gas_limit),
                verification_gas_limit: to_le_bytes(op.verification_gas_limit),
                max_fee_per_gas: to_le_bytes(op.max_fee_per_gas),
                max_priority_fee_per_gas: to_le_bytes(op.max_priority_fee_per_gas),
                paymaster_and_data: op.paymaster_and_data.to_vec(),
                signature: op.signature.to_vec(),
            }
        }
    }

    impl From<UserOperation> for RpcUserOperation {
        fn from(mut op: UserOperation) -> Self {
            RpcUserOperation {
                // TODO: Address::from_slice panics. Find something better.
                sender: Address::from_slice(&op.sender),
                nonce: U256::from_little_endian(&op.nonce),
                init_code: Bytes::from(mem::take(&mut op.init_code)),
                call_data: Bytes::from(mem::take(&mut op.call_data)),
                call_gas_limit: U256::from_little_endian(&op.call_gas_limit),
                verification_gas_limit: U256::from_little_endian(&op.verification_gas_limit),
                max_fee_per_gas: U256::from_little_endian(&op.max_fee_per_gas),
                max_priority_fee_per_gas: U256::from_little_endian(&op.max_priority_fee_per_gas),
                paymaster_and_data: Bytes::from(mem::take(&mut op.paymaster_and_data)),
                signature: Bytes::from(mem::take(&mut op.signature)),
            }
        }
    }
}

fn to_le_bytes(n: U256) -> Vec<u8> {
    let mut vec = vec![0_u8; 32];
    n.to_little_endian(&mut vec);
    vec
}
