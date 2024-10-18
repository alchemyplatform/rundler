// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "openzeppelin-contracts-versions/v5_0/contracts/proxy/Proxy.sol";
import "openzeppelin-contracts-versions/v5_0/contracts/utils/math/Math.sol";
import "account-abstraction/v0_7/interfaces/IAccountExecute.sol";
import "account-abstraction/v0_7/interfaces/PackedUserOperation.sol";
import "account-abstraction/v0_7/interfaces/IEntryPoint.sol";

import "../utils/CallGasEstimationProxyTypes.sol";

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

    function _implementation() internal pure virtual override returns (address) {
        return IMPLEMENTATION_ADDRESS_MARKER;
    }

    struct EstimateCallGasArgs {
        PackedUserOperation userOp;
        uint256 minGas;
        uint256 maxGas;
        uint256 rounding;
        bool isContinuation;
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
     *
     * Takes a `rounding` parameter which rounds all guesses and the final
     * result to a multiple of that parameter.
     *
     * As an optimization, if a round of binary search just completed
     * successfully and used N gas, then the next round will try 2N gas if it's
     * lower than the next (low + high) / 2 guess. This helps us quickly narrow
     * down the common case where the gas needed is much smaller than the
     * initial upper bound.
     */
    function estimateCallGas(EstimateCallGasArgs calldata args) external {
        // Will only be violated if the op is doing shinanigans where it tries
        // to call this method on the entry point to throw off gas estimates.
        require(msg.sender == address(this));
        uint256 scaledMaxFailureGas = args.minGas / args.rounding;
        uint256 scaledMinSuccessGas = args.maxGas.ceilDiv(args.rounding);
        uint256 scaledGasUsedInSuccess = scaledMinSuccessGas;
        uint256 scaledGuess = 0;
        bytes32 userOpHash = _getUserOpHashInternal(args.userOp);
        if (!args.isContinuation) {
            // Make one call at full gas to make sure success is even possible.
            (bool success, uint256 gasUsed, bytes memory revertData) = innerCall(args.userOp, userOpHash, args.maxGas);
            if (!success) {
                revert EstimateCallGasRevertAtMax(revertData);
            }
            scaledGuess = (gasUsed * 2) / args.rounding;
        } else {
            scaledGuess = chooseGuess(scaledMaxFailureGas, scaledMinSuccessGas, scaledGasUsedInSuccess);
        }
        uint256 numRounds = 0;
        while (scaledMaxFailureGas + 1 < scaledMinSuccessGas) {
            numRounds++;
            uint256 guess = scaledGuess * args.rounding;
            if (!isEnoughGasForGuess(guess)) {
                uint256 nextMin = scaledMaxFailureGas * args.rounding;
                uint256 nextMax = scaledMinSuccessGas * args.rounding;
                revert EstimateCallGasContinuation(nextMin, nextMax, numRounds);
            }
            (bool success, uint256 gasUsed,) = innerCall(args.userOp, userOpHash, guess);
            if (success) {
                scaledGasUsedInSuccess = scaledGasUsedInSuccess.min(gasUsed.ceilDiv(args.rounding));
                scaledMinSuccessGas = scaledGuess;
            } else {
                scaledMaxFailureGas = scaledGuess;
            }

            scaledGuess = chooseGuess(scaledMaxFailureGas, scaledMinSuccessGas, scaledGasUsedInSuccess);
        }
        revert EstimateCallGasResult(args.maxGas.min(scaledMinSuccessGas * args.rounding), numRounds);
    }

    /**
     * A helper function for testing execution at a given gas limit.
     */
    function testCallGas(PackedUserOperation calldata userOp, uint256 callGasLimit) external {
        bytes32 userOpHash = _getUserOpHashInternal(userOp);
        (bool success, uint256 gasUsed, bytes memory revertData) = innerCall(userOp, userOpHash, callGasLimit);
        revert TestCallGasResult(success, gasUsed, revertData);
    }

    function chooseGuess(uint256 highestFailureGas, uint256 lowestSuccessGas, uint256 lowestGasUsedInSuccess)
        private
        pure
        returns (uint256)
    {
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

    function isEnoughGasForGuess(uint256 guess) private view returns (bool) {
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

    function innerCall(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 gas)
        private
        returns (bool success, uint256 gasUsed, bytes memory revertData)
    {
        bytes calldata callData = userOp.callData;
        bytes4 methodSig;
        assembly {
            let len := callData.length
            if gt(len, 3) { methodSig := calldataload(callData.offset) }
        }

        bytes memory executeCall;
        if (methodSig == IAccountExecute.executeUserOp.selector) {
            executeCall = abi.encodeCall(IAccountExecute.executeUserOp, (userOp, userOpHash));
        } else {
            executeCall = callData;
        }

        try this._innerCall(userOp.sender, executeCall, gas) {
            // Should never happen. _innerCall should always revert.
            revert();
        } catch (bytes memory innerCallRevertData) {
            require(bytes4(innerCallRevertData) == _InnerCallResult.selector);
            assembly {
                innerCallRevertData := add(innerCallRevertData, 0x04)
            }
            (success, gasUsed, revertData) = abi.decode(innerCallRevertData, (bool, uint256, bytes));
        }
    }

    function _innerCall(address sender, bytes calldata callData, uint256 gas) external {
        uint256 preGas = gasleft();
        (bool success, bytes memory data) = sender.call{gas: gas}(callData);
        uint256 gasUsed = preGas - gasleft();
        bytes memory revertData = success ? bytes("") : data;
        revert _InnerCallResult(success, gasUsed, revertData);
    }

    function _getUserOpHashInternal(PackedUserOperation calldata userOp) internal returns (bytes32) {
        (bool success, bytes memory data) =
            address(this).call(abi.encodeWithSelector(IEntryPoint.getUserOpHash.selector, userOp));
        require(success, "Call to getUserOpHash failed");
        return abi.decode(data, (bytes32));
    }
}
