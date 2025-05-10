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

// Contracts from https://github.com/eth-infinitism/account-abstraction/tree/releases/v0.7/contracts

use alloy_primitives::Bytes;
use alloy_sol_macro::sol;

sol!(
    #[allow(missing_docs)]
    #[derive(Default, Debug, PartialEq, Eq)]
    struct PackedUserOperation {
        address sender;
        uint256 nonce;
        bytes initCode;
        bytes callData;
        bytes32 accountGasLimits;
        uint256 preVerificationGas;
        bytes32 gasFees;
        bytes paymasterAndData;
        bytes signature;
    }

    #[allow(missing_docs)]
    #[derive(Default, Debug, PartialEq, Eq)]
    struct UserOpsPerAggregator {
        PackedUserOperation[] userOps;
        address aggregator;
        bytes signature;
    }

    #[allow(missing_docs)]
    #[derive(Default, Debug, PartialEq, Eq)]
    struct ReturnInfo {
        uint256 preOpGas;
        uint256 prefund;
        uint256 accountValidationData;
        uint256 paymasterValidationData;
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
    struct ValidationResult {
        ReturnInfo returnInfo;
        StakeInfo senderInfo;
        StakeInfo factoryInfo;
        StakeInfo paymasterInfo;
        AggregatorStakeInfo aggregatorInfo;
    }

    #[allow(missing_docs)]
    #[derive(Default, Debug, PartialEq, Eq)]
    struct DepositInfo {
        uint256 deposit;
        bool staked;
        uint112 stake;
        uint32 unstakeDelaySec;
        uint48 withdrawTime;
    }

    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Default, Debug, PartialEq, Eq)]
    interface IEntryPoint {
        event UserOperationEvent(
            bytes32 indexed userOpHash,
            address indexed sender,
            address indexed paymaster,
            uint256 nonce,
            bool success,
            uint256 actualGasCost,
            uint256 actualGasUsed
        );

        event AccountDeployed(
            bytes32 indexed userOpHash,
            address indexed sender,
            address factory,
            address paymaster
        );

        event UserOperationRevertReason(
            bytes32 indexed userOpHash,
            address indexed sender,
            uint256 nonce,
            bytes revertReason
        );

        event PostOpRevertReason(
            bytes32 indexed userOpHash,
            address indexed sender,
            uint256 nonce,
            bytes revertReason
        );

        event UserOperationPrefundTooLow(
            bytes32 indexed userOpHash,
            address indexed sender,
            uint256 nonce
        );

        event BeforeExecution();

        event SignatureAggregatorChanged(address indexed aggregator);

        error FailedOp(uint256 opIndex, string reason);

        error FailedOpWithRevert(uint256 opIndex, string reason, bytes inner);

        error SignatureValidationFailed(address aggregator);

        function handleOps(
            PackedUserOperation[] calldata ops,
            address payable beneficiary
        ) external;

        function handleAggregatedOps(
            UserOpsPerAggregator[] calldata opsPerAggregator,
            address payable beneficiary
        ) external;

        // Below from IStakeManager
        event Deposited(address indexed account, uint256 totalDeposit);

        event Withdrawn(
            address indexed account,
            address withdrawAddress,
            uint256 amount
        );

        function getDepositInfo(
            address account
        ) external view returns (DepositInfo memory info);

        function balanceOf(address account) external view returns (uint256);
    }

    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Default, Debug, PartialEq, Eq)]
    interface IAggregator {
        function validateSignatures(
            PackedUserOperation[] calldata userOps,
            bytes calldata signature
        ) external view;

        function validateUserOpSignature(
            PackedUserOperation calldata userOp
        ) external view returns (bytes memory sigForUserOp);

        function aggregateSignatures(
            PackedUserOperation[] calldata userOps
        ) external view returns (bytes memory aggregatedSignature);
    }

    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Default, Debug, PartialEq, Eq)]
    interface IEntryPointSimulations is IEntryPoint {
        struct ExecutionResult {
            uint256 preOpGas;
            uint256 paid;
            uint256 accountValidationData;
            uint256 paymasterValidationData;
            bool targetSuccess;
            bytes targetResult;
        }

        function simulateValidation(
            PackedUserOperation calldata userOp
        )
        external
        returns (
            ValidationResult memory
        );

        function simulateHandleOp(
            PackedUserOperation calldata op,
            address target,
            bytes calldata targetCallData
        )
        external
        returns (
            ExecutionResult memory
        );
    }

    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Default, Debug, PartialEq, Eq)]
    contract CallGasEstimationProxy {
        struct EstimateCallGasArgs {
            PackedUserOperation userOp;
            uint256 minGas;
            uint256 maxGas;
            uint256 rounding;
            bool isContinuation;
        }

        error EstimateCallGasResult(uint256 gasEstimate, uint256 numRounds);

        error EstimateGasContinuation(uint256 minGas, uint256 maxGas, uint256 numRounds);

        error EstimateGasRevertAtMax(bytes revertData);

        error TestCallGasResult(bool success, uint256 gasUsed, bytes revertData);

        function estimateCallGas(EstimateCallGasArgs calldata args) external;

        function testCallGas(PackedUserOperation calldata userOp, uint256 callGasLimit) external;
    }

    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Default, Debug, PartialEq, Eq)]
    contract VerificationGasEstimationHelper {
        struct EstimateGasArgs {
            address entryPointSimulations;
            PackedUserOperation userOp;
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

        function estimatePaymasterVerificationGas(EstimateGasArgs calldata args) external returns (EstimateGasResult memory);
    }
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    GetBalances,
    "contracts/out/v0_7/GetBalances.sol/GetBalances.json"
);

// EntryPointSimulations deployed bytecode
static __ENTRY_POINT_SIMULATIONS_V0_7_DEPLOYED_BYTECODE_HEX: &[u8] = include_bytes!(
    "../contracts/out/v0_7/EntryPointSimulations.sol/EntryPointSimulations_deployedBytecode.txt"
);

static __ENTRY_POINT_SIMULATIONS_V0_7_DEPLOYED_BYTECODE: [u8; 16893] = {
    match const_hex::const_decode_to_array(__ENTRY_POINT_SIMULATIONS_V0_7_DEPLOYED_BYTECODE_HEX) {
        Ok(a) => a,
        Err(_) => panic!("Failed to decode entry point simulations hex"),
    }
};

pub static ENTRY_POINT_SIMULATIONS_V0_7_DEPLOYED_BYTECODE: Bytes =
    Bytes::from_static(&__ENTRY_POINT_SIMULATIONS_V0_7_DEPLOYED_BYTECODE);

// CallGasEstimationProxy deployed bytecode
static __CALL_GAS_ESTIMATION_PROXY_V0_7_DEPLOYED_BYTECODE_HEX: &[u8] = include_bytes!(
    "../contracts/out/v0_7/CallGasEstimationProxy.sol/CallGasEstimationProxy_deployedBytecode.txt"
);

static __CALL_GAS_ESTIMATION_PROXY_V0_7_DEPLOYED_BYTECODE: [u8; 3558] = {
    match const_hex::const_decode_to_array(__CALL_GAS_ESTIMATION_PROXY_V0_7_DEPLOYED_BYTECODE_HEX) {
        Ok(a) => a,
        Err(_) => panic!("Failed to decode call gas estimation proxy hex"),
    }
};

pub static CALL_GAS_ESTIMATION_PROXY_V0_7_DEPLOYED_BYTECODE: Bytes =
    Bytes::from_static(&__CALL_GAS_ESTIMATION_PROXY_V0_7_DEPLOYED_BYTECODE);

// VerificationGasEstimationHelper deployed bytecode
static __VERIFICATION_GAS_ESTIMATION_HELPER_V0_7_DEPLOYED_BYTECODE_HEX: &[u8] = include_bytes!(
    "../contracts/out/v0_7/VerificationGasEstimationHelper.sol/VerificationGasEstimationHelper_deployedBytecode.txt"
);

static __VERIFICATION_GAS_ESTIMATION_HELPER_V0_7_DEPLOYED_BYTECODE: [u8; 4019] = {
    match const_hex::const_decode_to_array(
        __VERIFICATION_GAS_ESTIMATION_HELPER_V0_7_DEPLOYED_BYTECODE_HEX,
    ) {
        Ok(a) => a,
        Err(_) => panic!("Failed to decode verification gas estimation helper hex"),
    }
};

pub static VERIFICATION_GAS_ESTIMATION_HELPER_V0_7_DEPLOYED_BYTECODE: Bytes =
    Bytes::from_static(&__VERIFICATION_GAS_ESTIMATION_HELPER_V0_7_DEPLOYED_BYTECODE);
