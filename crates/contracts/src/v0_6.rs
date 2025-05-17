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

// Contracts from https://github.com/eth-infinitism/account-abstraction/tree/releases/v0.6/contracts

use alloy_primitives::Bytes;
use alloy_sol_macro::sol;

sol! {
    #[allow(missing_docs)]
    #[derive(Default, Debug, PartialEq, Eq)]
    struct UserOperation {
        address sender;
        uint256 nonce;
        bytes initCode;
        bytes callData;
        uint256 callGasLimit;
        uint256 verificationGasLimit;
        uint256 preVerificationGas;
        uint256 maxFeePerGas;
        uint256 maxPriorityFeePerGas;
        bytes paymasterAndData;
        bytes signature;
    }

    #[allow(missing_docs)]
    #[derive(Default, Debug, PartialEq, Eq)]
    struct UserOpsPerAggregator {
        UserOperation[] userOps;
        address aggregator;
        bytes signature;
    }

    #[allow(missing_docs)]
    #[derive(Default, Debug, PartialEq, Eq)]
    struct ReturnInfo {
        uint256 preOpGas;
        uint256 prefund;
        bool sigFailed;
        uint48 validAfter;
        uint48 validUntil;
        bytes paymasterContext;
    }

    #[allow(missing_docs)]
    #[derive(Default, Debug, PartialEq, Eq)]
    struct StakeInfo {
        uint256 stake;
        uint256 unstakeDelaySec;
    }

    #[allow(missing_docs)]
    #[derive(Default, Debug, PartialEq, Eq)]
    struct AggregatorStakeInfo {
        address aggregator;
        StakeInfo stakeInfo;
    }

    #[allow(missing_docs)]
    #[derive(Default, Debug, PartialEq, Eq)]
    struct DepositInfo {
        uint112 deposit;
        bool staked;
        uint112 stake;
        uint32 unstakeDelaySec;
        uint48 withdrawTime;
    }

    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Default, Debug, PartialEq, Eq)]
    interface IEntryPoint {
        event UserOperationEvent(bytes32 indexed userOpHash, address indexed sender, address indexed paymaster, uint256 nonce, bool success, uint256 actualGasCost, uint256 actualGasUsed);

        event AccountDeployed(bytes32 indexed userOpHash, address indexed sender, address factory, address paymaster);

        event UserOperationRevertReason(bytes32 indexed userOpHash, address indexed sender, uint256 nonce, bytes revertReason);

        event BeforeExecution();

        event SignatureAggregatorChanged(address indexed aggregator);

        error FailedOp(uint256 opIndex, string reason);

        error ValidationResult(ReturnInfo returnInfo,
            StakeInfo senderInfo, StakeInfo factoryInfo, StakeInfo paymasterInfo);

        error ValidationResultWithAggregation(ReturnInfo returnInfo,
                StakeInfo senderInfo, StakeInfo factoryInfo, StakeInfo paymasterInfo,
                AggregatorStakeInfo aggregatorInfo);

        error SignatureValidationFailed(address aggregator);

        error ExecutionResult(uint256 preOpGas, uint256 paid, uint48 validAfter, uint48 validUntil, bool targetSuccess, bytes targetResult);

        function handleOps(UserOperation[] calldata ops, address payable beneficiary);

        function handleAggregatedOps(
            UserOpsPerAggregator[] calldata opsPerAggregator,
            address payable beneficiary
        );

        // From IStakeManager
        event Deposited(
            address indexed account,
            uint256 totalDeposit
        );

        event Withdrawn(
            address indexed account,
            address withdrawAddress,
            uint256 amount
        );

        function getDepositInfo(
            address account
        ) external view returns (DepositInfo memory info);

        function balanceOf(address account) external view returns (uint256);

        function simulateValidation(UserOperation calldata userOp) external;

        function simulateHandleOp(UserOperation calldata op, address target, bytes calldata targetCallData) external;
    }

    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Default, Debug, PartialEq, Eq)]
    interface IAggregator {
        function validateSignatures(UserOperation[] calldata userOps, bytes calldata signature);

        function validateUserOpSignature(UserOperation calldata userOp)
        external view returns (bytes memory sigForUserOp);

        function aggregateSignatures(UserOperation[] calldata userOps) external view returns (bytes memory aggregatedSignature);
    }

    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Default, Debug, PartialEq, Eq)]
    contract VerificationGasEstimationHelper {
        struct EstimateGasArgs {
            address entryPoint;
            UserOperation userOp;
            uint256 minGas;
            uint256 maxGas;
            uint256 rounding;
            bool isContinuation;
            uint256 constantFee;
        }

        struct EstimateGasResult {
            uint256 gasEstimate;
            uint256 numRounds;
        }

        error EstimateGasContinuation(uint256 minGas, uint256 maxGas, uint256 numRounds);

        error EstimateGasRevertAtMax(bytes revertData);

        function estimateVerificationGas(EstimateGasArgs calldata args) external returns (EstimateGasResult memory);
    }
}

sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    CallGasEstimationProxy,
    "contracts/out/v0_6/CallGasEstimationProxy.sol/CallGasEstimationProxy.json"
}

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    GetBalances,
    "contracts/out/v0_6/GetBalances.sol/GetBalances.json"
);

// https://etherscan.io/address/0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789#code
static __ENTRY_POINT_V0_6_DEPLOYED_BYTECODE_HEX: &[u8] = include_bytes!(
    "../contracts/bytecode/entrypoint/0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789_deployed.txt"
);
static __ENTRY_POINT_V0_6_DEPLOYED_BYTECODE: [u8; 23689] = {
    match const_hex::const_decode_to_array(__ENTRY_POINT_V0_6_DEPLOYED_BYTECODE_HEX) {
        Ok(a) => a,
        Err(_) => panic!("Failed to decode entrypoint hex"),
    }
};
pub static ENTRY_POINT_V0_6_DEPLOYED_BYTECODE: Bytes =
    Bytes::from_static(&__ENTRY_POINT_V0_6_DEPLOYED_BYTECODE);

// VerificationGasEstimationHelper deployed bytecode
static __VERIFICATION_GAS_ESTIMATION_HELPER_V0_6_DEPLOYED_BYTECODE_HEX: &[u8] = include_bytes!(
    "../contracts/out/v0_6/VerificationGasEstimationHelper.sol/VerificationGasEstimationHelper_deployedBytecode.txt"
);

static __VERIFICATION_GAS_ESTIMATION_HELPER_V0_6_DEPLOYED_BYTECODE: [u8; 3398] = {
    match const_hex::const_decode_to_array(
        __VERIFICATION_GAS_ESTIMATION_HELPER_V0_6_DEPLOYED_BYTECODE_HEX,
    ) {
        Ok(a) => a,
        Err(_) => panic!("Failed to decode verification gas estimation helper hex"),
    }
};

pub static VERIFICATION_GAS_ESTIMATION_HELPER_V0_6_DEPLOYED_BYTECODE: Bytes =
    Bytes::from_static(&__VERIFICATION_GAS_ESTIMATION_HELPER_V0_6_DEPLOYED_BYTECODE);
