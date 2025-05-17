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
        uint256 constantFee;
    }

    struct EstimateGasResult {
        uint256 gas;
        uint256 numRounds;
    }

    function estimateVerificationGas(
        EstimateGasArgs calldata args
    ) external returns (EstimateGasResult memory) {
        return _estimateGas(args, _setVerificationGas);
    }

    function _estimateGas(
        EstimateGasArgs calldata args,
        function(UserOperation memory, uint256, uint256) internal pure setGas
    ) private returns (EstimateGasResult memory) {
        uint256 scaledMaxFailureGas = args.minGas / args.rounding;
        uint256 scaledMinSuccessGas = args.maxGas.ceilDiv(args.rounding);
        uint256 scaledGasUsedInSuccess = scaledMinSuccessGas;
        uint256 scaledGuess = 0;

        UserOperation memory userOp = args.userOp;
        uint256 gasUsedInSuccess = 0;

        if (!args.isContinuation) {
            // Make one call at full gas to make sure success is even possible.
            setGas(userOp, args.maxGas, args.constantFee);
            (
                bool success,
                uint256 gasUsed,
                bytes memory revertData
            ) = _innerCall(args.entryPoint, userOp);
            if (!success) {
                revert EstimateGasRevertAtMax(revertData);
            }
            gasUsedInSuccess = gasUsed;
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

            setGas(userOp, guess, args.constantFee);
            (bool success, uint256 gasUsed, ) = _innerCall(
                args.entryPoint,
                userOp
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

    error _InnerCallResult(bool success, uint256 gasUsed, bytes revertData);

    function _innerCall(
        IEntryPoint entryPoint,
        UserOperation memory userOp
    ) private returns (bool success, uint256 gasUsed, bytes memory revertData) {
        try this.innerCall(entryPoint, userOp) {
            revert("_innerCallInner should always revert");
        } catch (bytes memory innerCallRevertData) {
            require(bytes4(innerCallRevertData) == _InnerCallResult.selector);
            assembly {
                innerCallRevertData := add(innerCallRevertData, 0x04)
            }
            (success, gasUsed, revertData) = abi.decode(
                innerCallRevertData,
                (bool, uint256, bytes)
            );
        }
    }

    function innerCall(
        IEntryPoint entryPoint,
        UserOperation memory userOp
    )
        external
        returns (bool success, uint256 gasUsed, bytes memory revertData)
    {
        uint256 preGas = gasleft();

        try entryPoint.simulateValidation(userOp) {
            revert("simulateValidation should always revert");
        } catch (bytes memory data) {
            if (bytes4(data) == IEntryPoint.ValidationResult.selector) {
                success = true;
            } else {
                success = false;
                revertData = data;
            }
        }

        gasUsed = preGas - gasleft();

        revert _InnerCallResult(success, gasUsed, revertData);
    }

    function _setVerificationGas(
        UserOperation memory userOp,
        uint256 gas,
        uint256 constantFee
    ) internal pure {
        userOp.verificationGasLimit = gas;
        if (userOp.paymasterAndData.length == 0 || constantFee == 0) {
            userOp.maxFeePerGas = 0;
            userOp.maxPriorityFeePerGas = 0;
            return;
        }

        uint256 totalGasLimit = userOp.verificationGasLimit +
            userOp.preVerificationGas +
            userOp.callGasLimit;
        uint256 gasFees = constantFee.ceilDiv(totalGasLimit);
        userOp.maxFeePerGas = gasFees;
        userOp.maxPriorityFeePerGas = gasFees;
    }
}
