// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "@openzeppelin/contracts/proxy/Proxy.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";

import "common/interfaces/EstimationTypes.sol";
import "common/libraries/BinarySearchLib.sol";

/**
 * Contract used in `eth_call`'s "overrides" parameter in order to estimate the
 * required `callGasLimit` for a user operation.
 *
 * This contract is solving the problem that the entry point's
 * `simulateHandleOp` doesn't return whether the op's call succeeded, thus
 * making it impossible to use directly for trying call gas limits to see if
 * they work. We could call the sender directly with its call data, but that
 * fails because we do need to run the validation step first, as it may cause
 * changes to the sender's state or even deploy the sender in the first place.
 * We can use `simulateHandleOp`s optional `target` and `targetData` parameters
 * to run code after the validation step, but we need to watch out for the
 * restriction that a typical sender will reject calls not coming from the
 * entry point address.
 *
 * The solution is to create a proxy contract which delegates to the entry point
 * but also exposes a method for estimating call gas by binary searching.
 * We then call `simulateHandleOp` on this contract and use `target` and
 * `targetData` to have this contract call itself to run a binary search to
 * discover the call gas estimate. Thus when we call `simulateHandleOp`, we call
 * it on this contract, using `eth_call`s overrides to move the original entry
 * point code to a different address, then putting this contract's code at the
 * original entry point address and having it's proxy target be the address to
 * which we moved the entry point code.
 *
 * Note that this contract is never deployed. It is only used for its compiled
 * bytecode, which is passed as an override in `eth_call`.
 */
contract CallGasEstimationProxy is Proxy {
    using Math for uint256;

    function _implementation()
        internal
        pure
        virtual
        override
        returns (address)
    {
        return IMPLEMENTATION_ADDRESS_MARKER;
    }

    struct EstimateCallGasArgs {
        address sender;
        bytes callData;
        uint256 minGas;
        uint256 maxGas;
        uint256 allowedErrorPct;
        bool isContinuation;
    }

    struct BinarySearchContext {
        address sender;
        bytes callData;
    }

    /**
     * Runs a binary search to find the smallest amount of gas at which the call
     * succeeds.
     *
     * Always reverts with its result, which is one of the following:
     *
     * - The successful gas estimate
     * - That the call fails even with max gas
     * - A new min and max gas to be used in a follow-up call, if we ran out of
     *   gas before completing the binary search.
     */
    function estimateCallGas(EstimateCallGasArgs calldata args) external {
        // Will only be violated if the op is doing shinanigans where it tries
        // to call this method on the entry point to throw off gas estimates.
        require(msg.sender == address(this));

        uint256 initialGuess = 0;

        bytes memory context = abi.encode(
            BinarySearchContext({sender: args.sender, callData: args.callData})
        );

        if (!args.isContinuation) {
            // Make one call at full gas to make sure success is even possible.
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

    /**
     * A helper function for testing execution at a given gas limit.
     */
    function testCallGas(
        address sender,
        bytes calldata callData,
        uint256 callGasLimit
    ) external {
        bytes memory context = abi.encode(
            BinarySearchContext({sender: sender, callData: callData})
        );

        (
            bool success,
            uint256 gasUsed,
            bytes memory revertData
        ) = BinarySearchLib.runInnerCall(this.innerCall, context, callGasLimit);
        revert TestCallGasResult(success, gasUsed, revertData);
    }

    function innerCall(uint256 guess, bytes memory context) external {
        BinarySearchContext memory ctx = abi.decode(
            context,
            (BinarySearchContext)
        );

        uint256 preGas = gasleft();
        (bool success, bytes memory data) = ctx.sender.call{gas: guess}(
            ctx.callData
        );
        uint256 gasUsed = preGas - gasleft();

        bytes memory revertData = success ? bytes("") : data;
        revert BinarySearchLib.InnerCallResult(success, gasUsed, revertData);
    }
}
