// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "openzeppelin-contracts-versions/v5_0/contracts/utils/math/Math.sol";
import "account-abstraction/v0_6/interfaces/IEntryPoint.sol";
import "account-abstraction/v0_6/interfaces/UserOperation.sol";

import "../utils/EstimationTypes.sol";

contract VerificationGasEstimationHelper {
    using Math for uint256;

    constructor() {
        require(block.number < 100, "should not be deployed");
    }

    struct EstimateGasArgs {
        IEntryPoint entryPoint;
        UserOperation userOp;
        uint256 minGas;
        uint256 maxGas;
        uint256 rounding;
        bool isContinuation;
    }

    struct EstimateGasResult {
        uint256 gas;
        uint256 numRounds;
    }

    function estimateVerificationGas(
        EstimateGasArgs calldata args
    ) external returns (EstimateGasResult memory) {
        return _estimateGas(args);
    }

    function _estimateGas(
        EstimateGasArgs calldata args
    ) private returns (EstimateGasResult memory) {
        uint256 scaledMaxFailureGas = args.minGas / args.rounding;
        uint256 scaledMinSuccessGas = args.maxGas.ceilDiv(args.rounding);
        uint256 scaledGasUsedInSuccess = scaledMinSuccessGas;
        uint256 scaledGuess = 0;

        UserOperation memory userOp = args.userOp;

        if (!args.isContinuation) {
            // Make one call at full gas to make sure success is even possible.
            (
                bool success,
                uint256 gasUsed,
                bytes memory revertData
            ) = _innerCall(args.entryPoint, userOp, args.maxGas);
            if (!success) {
                revert EstimateGasRevertAtMax(revertData);
            }
            scaledGuess = (gasUsed * 2) / args.rounding;
        } else {
            scaledGuess = _chooseGuess(
                scaledMaxFailureGas,
                scaledMinSuccessGas,
                scaledGasUsedInSuccess
            );
        }

        uint256 numRounds = 0;
        while (scaledMaxFailureGas + 1 < scaledMinSuccessGas) {
            numRounds++;
            uint256 guess = scaledGuess * args.rounding;
            if (!_isEnoughGasForGuess(guess)) {
                uint256 nextMin = scaledMaxFailureGas * args.rounding;
                uint256 nextMax = scaledMinSuccessGas * args.rounding;
                revert EstimateGasContinuation(nextMin, nextMax, numRounds);
            }

            (bool success, uint256 gasUsed, ) = _innerCall(
                args.entryPoint,
                userOp,
                guess
            );
            if (success) {
                scaledGasUsedInSuccess = scaledGasUsedInSuccess.min(
                    gasUsed.ceilDiv(args.rounding)
                );
                scaledMinSuccessGas = scaledGuess;
            } else {
                scaledMaxFailureGas = scaledGuess;
            }

            scaledGuess = _chooseGuess(
                scaledMaxFailureGas,
                scaledMinSuccessGas,
                scaledGasUsedInSuccess
            );
        }
        return
            EstimateGasResult(
                args.maxGas.min(scaledMinSuccessGas * args.rounding),
                numRounds
            );
    }

    function _chooseGuess(
        uint256 highestFailureGas,
        uint256 lowestSuccessGas,
        uint256 lowestGasUsedInSuccess
    ) private pure returns (uint256) {
        uint256 average = (highestFailureGas + lowestSuccessGas) / 2;
        if (lowestGasUsedInSuccess <= highestFailureGas) {
            // Handle pathological cases where the contract requires a lot of
            // gas but uses very little, which without this branch could cause
            // the guesses to inch up a tiny bit at a time.
            return average;
        } else {
            return average.min(2 * lowestGasUsedInSuccess);
        }
    }

    function _isEnoughGasForGuess(uint256 guess) private view returns (bool) {
        // Because of the 1/64 rule and the fact that we need two levels of
        // calls, we need
        //
        //   guess < (63/64)^2 * (gas - some_overhead)
        //
        // We'll take the overhead to be 50000, which should leave plenty left
        // over for us to hand the result back to the EntryPoint to return.
        return (64 * 64 * guess) / (63 * 63) + 50000 < gasleft();
    }

    function _innerCall(
        IEntryPoint entryPoint,
        UserOperation memory userOp,
        uint256 guess
    ) private returns (bool success, uint256 gasUsed, bytes memory revertData) {
        userOp.verificationGasLimit = guess;
        userOp.callGasLimit = 0;

        uint256 preGas = gasleft();
        try entryPoint.simulateHandleOp(userOp, address(0), "") {} catch (
            bytes memory data
        ) {
            if (
                data.length >= 4 &&
                bytes4(data) == IEntryPoint.ExecutionResult.selector
            ) {
                success = true;
            } else {
                revertData = data;
            }
        }

        gasUsed = preGas - gasleft();
    }
}
