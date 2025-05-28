// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";

import {BinarySearchLib} from "../../src/libraries/BinarySearchLib.sol";
import {EstimateGasContinuation} from "../../src/interfaces/EstimationTypes.sol";

contract BinarySearchLibTest is Test {
    struct BinarySearchContext {
        uint256 target;
    }

    function calculate_error_pct(
        uint256 actual,
        uint256 expected
    ) public pure returns (uint256) {
        if (actual < expected) {
            revert("actual is less than expected");
        }

        return ((actual - expected) * 100) / expected;
    }

    function test_binarySearch() public {
        Helper helper = new Helper();

        (uint256 result, ) = helper.run(
            Helper.HelperArgs({
                target: 51111,
                initialGuess: 150101,
                lowestSuccessGas: 5000000,
                highestFailureGas: 0,
                allowedErrorPct: 10,
                callDepth: 1
            })
        );

        assertLt(calculate_error_pct(result, 51111), 10);
    }

    function test_binarySearchMinTarget() public {
        Helper helper = new Helper();

        (uint256 result, ) = helper.run(
            Helper.HelperArgs({
                target: 1,
                initialGuess: 5000000,
                lowestSuccessGas: 5000000,
                highestFailureGas: 0,
                allowedErrorPct: 1,
                callDepth: 1
            })
        );

        assertLt(calculate_error_pct(result, 1), 1);
    }

    function test_binarySearchBadInputs() public {
        Helper helper = new Helper();

        vm.expectRevert();

        helper.run(
            Helper.HelperArgs({
                target: 0,
                initialGuess: 5000000,
                lowestSuccessGas: 0,
                highestFailureGas: 1,
                allowedErrorPct: 1,
                callDepth: 1
            })
        );
    }

    function test_binarySearchOOG() public {
        Helper helper = new Helper();

        vm.expectRevert();

        helper.run{gas: 10000}(
            Helper.HelperArgs({
                target: 500000,
                initialGuess: 1,
                lowestSuccessGas: 5000000,
                highestFailureGas: 0,
                allowedErrorPct: 10,
                callDepth: 1
            })
        );
    }

    function test_binarySearchContinuation() public {
        Helper helper = new Helper();

        uint256 minGas = 0;
        uint256 maxGas = 0;
        uint256 numRounds = 0;

        try
            helper.run{gas: 70100}(
                Helper.HelperArgs({
                    target: 4000,
                    initialGuess: 5000,
                    lowestSuccessGas: 5000000,
                    highestFailureGas: 0,
                    allowedErrorPct: 2,
                    callDepth: 1
                })
            )
        {
            revert("should revert");
        } catch (bytes memory err) {
            // Extract the selector
            bytes4 selector = bytes4(err);
            assembly {
                err := add(err, 0x04)
            }

            if (selector == EstimateGasContinuation.selector) {
                (minGas, maxGas, numRounds) = abi.decode(
                    err,
                    (uint256, uint256, uint256)
                );
            }
        }

        assertGt(minGas, 0);
        assertLt(maxGas, 5000000);
        assertGt(numRounds, 0);

        (uint256 result, ) = helper.run(
            Helper.HelperArgs({
                target: 4000,
                initialGuess: 0,
                lowestSuccessGas: maxGas,
                highestFailureGas: minGas,
                allowedErrorPct: 2,
                callDepth: 1
            })
        );

        assertLt(calculate_error_pct(result, 4000), 2);
    }
}

contract Helper {
    struct BinarySearchContext {
        uint256 target;
    }

    struct HelperArgs {
        uint256 target;
        uint256 initialGuess;
        uint256 lowestSuccessGas;
        uint256 highestFailureGas;
        uint256 allowedErrorPct;
        uint256 callDepth;
    }

    function run(HelperArgs memory args) public returns (uint256, uint256) {
        return
            BinarySearchLib.binarySearch(
                BinarySearchLib.BinarySearchArgs({
                    innerCall: this.innerCall,
                    context: abi.encode(
                        BinarySearchContext({target: args.target})
                    ),
                    initialGuess: args.initialGuess,
                    lowestSuccessGas: args.lowestSuccessGas,
                    highestFailureGas: args.highestFailureGas,
                    allowedErrorPct: args.allowedErrorPct,
                    callDepth: args.callDepth
                })
            );
    }

    function innerCall(uint256 guess, bytes memory context) external pure {
        BinarySearchContext memory ctx = abi.decode(
            context,
            (BinarySearchContext)
        );
        if (guess >= ctx.target) {
            revert BinarySearchLib.InnerCallResult(true, 0, "");
        } else {
            revert BinarySearchLib.InnerCallResult(false, 0, "");
        }
    }
}
