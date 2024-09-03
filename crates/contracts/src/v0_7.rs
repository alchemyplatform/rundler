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
    #[sol(rpc)]
    #[derive(Default, Debug, PartialEq, Eq)]
    interface IEntryPoint {
        function handleOps(
            PackedUserOperation[] calldata ops,
            address payable beneficiary
        ) external;
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

        struct ValidationResult {
            ReturnInfo returnInfo;
            StakeInfo senderInfo;
            StakeInfo factoryInfo;
            StakeInfo paymasterInfo;
            AggregatorStakeInfo aggregatorInfo;
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
    contract GetBalances {
        error GetBalancesResult(uint256[] balances);

        constructor(address stakeManager, address[] memory addresses);
    }

    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Default, Debug, PartialEq, Eq)]
    contract CallGasEstimationProxy {
        error EstimateCallGasResult(uint256 gasEstimate, uint256 numRounds);

        error EstimateCallGasContinuation(uint256 minGas, uint256 maxGas, uint256 numRounds);

        error EstimateCallGasRevertAtMax(bytes revertData);

        error TestCallGasResult(bool success, uint256 gasUsed, bytes revertData);

        struct EstimateCallGasArgs {
            PackedUserOperation userOp;
            uint256 minGas;
            uint256 maxGas;
            uint256 rounding;
            bool isContinuation;
        }

        function estimateCallGas(EstimateCallGasArgs calldata args);

        function testCallGas(PackedUserOperation calldata userOp, uint256 callGasLimit);
    }
);
