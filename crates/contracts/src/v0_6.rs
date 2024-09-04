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
    #[sol(rpc)]
    #[derive(Default, Debug, PartialEq, Eq)]
    interface IEntryPoint {
        error FailedOp(uint256 opIndex, string reason);

        error ValidationResult(ReturnInfo returnInfo,
            StakeInfo senderInfo, StakeInfo factoryInfo, StakeInfo paymasterInfo);

        error ValidationResultWithAggregation(ReturnInfo returnInfo,
                StakeInfo senderInfo, StakeInfo factoryInfo, StakeInfo paymasterInfo,
                AggregatorStakeInfo aggregatorInfo);

        function handleOps(UserOperation[] calldata ops, address payable beneficiary);
        function handleAggregatedOps(
            UserOpsPerAggregator[] calldata opsPerAggregator,
            address payable beneficiary
        );
    }

    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Default, Debug, PartialEq, Eq)]
    interface IAggregator {
        function validateSignatures(UserOperation[] calldata userOps, bytes calldata signature);
    }

    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Default, Debug, PartialEq, Eq)]
    contract GetBalances {
        error GetBalancesResult(uint256[] balances);
        constructor(address stakeManager, address[] memory addresses);
    }

    contract CallGasEstimationProxy {
        struct EstimateCallGasArgs {
            address sender;
            bytes callData;
            uint256 minGas;
            uint256 maxGas;
            uint256 rounding;
            bool isContinuation;
        }

        error EstimateCallGasResult(uint256 gasEstimate, uint256 numRounds);

        error EstimateCallGasContinuation(uint256 minGas, uint256 maxGas, uint256 numRounds);

        error EstimateCallGasRevertAtMax(bytes revertData);

        error TestCallGasResult(bool success, uint256 gasUsed, bytes revertData);

        function estimateCallGas(EstimateCallGasArgs calldata args);
    }
}
