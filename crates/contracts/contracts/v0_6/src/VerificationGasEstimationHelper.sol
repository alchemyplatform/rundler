// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "@openzeppelin/contracts/utils/math/Math.sol";
import "@account-abstraction/interfaces/IEntryPoint.sol";
import "@account-abstraction/interfaces/UserOperation.sol";

import "common/interfaces/EstimationTypes.sol";
import "common/libraries/BinarySearchLib.sol";

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
        uint256 allowedErrorPct;
        bool isContinuation;
        uint256 constantFee;
    }

    struct BinarySearchContext {
        IEntryPoint entryPoint;
        UserOperation userOp;
        uint256 constantFee;
    }

    function estimateVerificationGas(EstimateGasArgs calldata args) external {
        UserOperation memory userOp = args.userOp;
        uint256 initialGuess = 0;

        bytes memory context = abi.encode(
            BinarySearchContext({
                entryPoint: args.entryPoint,
                userOp: userOp,
                constantFee: args.constantFee
            })
        );

        if (!args.isContinuation) {
            // Make one call at full gas to make sure success is even possible.
            _setVerificationGas(userOp, args.maxGas, args.constantFee);
            (
                bool success,
                uint256 gasUsed,
                bytes memory revertData
            ) = BinarySearchLib.runInnerCall(
                    this.innerCall,
                    context,
                    args.maxGas
                );
            if (!success) {
                revert EstimateGasRevertAtMax(revertData);
            }
            initialGuess = gasUsed * 2;
        }

        (uint256 result, uint256 numRounds) = BinarySearchLib.binarySearch(
            BinarySearchLib.BinarySearchArgs({
                innerCall: this.innerCall,
                context: context,
                initialGuess: initialGuess,
                lowestSuccessGas: args.maxGas,
                highestFailureGas: args.minGas,
                allowedErrorPct: args.allowedErrorPct,
                callDepth: 2
            })
        );

        revert EstimateGasResult(result, numRounds);
    }

    function innerCall(uint256 guess, bytes memory context) external {
        BinarySearchContext memory ctx = abi.decode(
            context,
            (BinarySearchContext)
        );
        _setVerificationGas(ctx.userOp, guess, ctx.constantFee);

        bool success;
        bytes memory revertData;

        uint256 preGas = gasleft();
        try ctx.entryPoint.simulateValidation(ctx.userOp) {
            revert("simulateValidation should always revert");
        } catch (bytes memory data) {
            if (bytes4(data) == IEntryPoint.ValidationResult.selector) {
                success = true;
            } else {
                success = false;
                revertData = data;
            }
        }
        uint256 gasUsed = preGas - gasleft();

        revert BinarySearchLib.InnerCallResult(success, gasUsed, revertData);
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
