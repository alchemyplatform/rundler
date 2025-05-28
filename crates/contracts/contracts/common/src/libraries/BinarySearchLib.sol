// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {console} from "forge-std/console.sol";

import {EstimateGasContinuation} from "../interfaces/EstimationTypes.sol";

library BinarySearchLib {
    using Math for uint256;

    error InnerCallResult(bool success, uint256 gasUsed, bytes revertData);

    struct BinarySearchArgs {
        // The function to call to run a guess. Must revert with InnerCallResult(bool, uint256, bytes)
        function(uint256, bytes memory) external innerCall;
        // The context to pass to the runGuess function.
        bytes context;
        // The initial guess to start with.
        uint256 initialGuess;
        // The lowest gas value that was successful.
        uint256 lowestSuccessGas;
        // The highest gas value that was unsuccessful.
        uint256 highestFailureGas;
        // The allowed error percentage.
        uint256 allowedErrorPct;
        // The depth of the runGuess function call prior to the function being estimated.
        uint256 callDepth;
    }

    function binarySearch(
        BinarySearchArgs memory args
    ) internal returns (uint256, uint256) {
        uint256 numRounds = 0;
        uint256 guess = args.initialGuess;
        uint256 lowestSuccessGas = args.lowestSuccessGas;
        uint256 highestFailureGas = args.highestFailureGas;
        uint256 lowestGasUsedInSuccess = 0;

        if (guess == 0) {
            guess = (args.lowestSuccessGas + args.highestFailureGas) / 2;
        }

        while (true) {
            if (lowestSuccessGas < highestFailureGas) {
                revert("lowestSuccessGas is less than highestFailureGas");
            }

            uint256 errorPct = ((lowestSuccessGas - highestFailureGas) * 100)
                .ceilDiv(lowestSuccessGas);

            if (
                errorPct <= args.allowedErrorPct ||
                lowestSuccessGas - highestFailureGas < 2
            ) {
                return (lowestSuccessGas, numRounds);
            }

            if (!_isEnoughGasForGuess(guess, args.callDepth)) {
                revert EstimateGasContinuation(
                    highestFailureGas,
                    lowestSuccessGas,
                    numRounds
                );
            }

            (bool success, uint256 gasUsed, ) = runInnerCall(
                args.innerCall,
                args.context,
                guess
            );

            if (success) {
                lowestSuccessGas = guess;
                lowestGasUsedInSuccess = lowestGasUsedInSuccess.min(gasUsed);
            } else {
                highestFailureGas = guess;
            }

            numRounds++;
            guess = _chooseNextGuess(
                highestFailureGas,
                lowestSuccessGas,
                lowestGasUsedInSuccess
            );
        }

        revert("BinarySearchLib: Unreachable");
    }

    function runInnerCall(
        function(uint256, bytes memory) external innerCall,
        bytes memory context,
        uint256 guess
    )
        internal
        returns (bool success, uint256 gasUsed, bytes memory revertData)
    {
        try innerCall(guess, context) {
            revert("BinarySearchLib: innerCall should always revert");
        } catch (bytes memory innerCallRevertData) {
            require(bytes4(innerCallRevertData) == InnerCallResult.selector);
            assembly {
                innerCallRevertData := add(innerCallRevertData, 0x04)
            }
            (success, gasUsed, revertData) = abi.decode(
                innerCallRevertData,
                (bool, uint256, bytes)
            );
        }
    }

    function _chooseNextGuess(
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

    function _isEnoughGasForGuess(
        uint256 guess,
        uint256 depth
    ) private view returns (bool) {
        // One extra depth level to account for the runGuess call.
        return
            (64 ** (depth + 1) * guess) / (63 ** (depth + 1)) + 50000 <
            gasleft();
    }
}
