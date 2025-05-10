// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "openzeppelin-contracts-versions/v5_0/contracts/utils/math/Math.sol";
import "account-abstraction/v0_7/interfaces/PackedUserOperation.sol";
import "account-abstraction/v0_7/interfaces/IEntryPointSimulations.sol";
import "account-abstraction/v0_7/core/UserOperationLib.sol";

import "../utils/EstimationTypes.sol";

contract VerificationGasEstimationHelper {
    using Math for uint256;

    constructor() {
        require(block.number < 100, "should not be deployed");
    }

    struct EstimateGasArgs {
        IEntryPointSimulations entryPointSimulations;
        PackedUserOperation userOp;
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

    function estimatePaymasterVerificationGas(
        EstimateGasArgs calldata args
    ) external returns (EstimateGasResult memory) {
        return _estimateGas(args, _setPaymasterVerificationGas);
    }

    function _estimateGas(
        EstimateGasArgs calldata args,
        function(PackedUserOperation memory, uint256, uint256)
            internal
            pure setGas
    ) private returns (EstimateGasResult memory) {
        uint256 scaledMaxFailureGas = args.minGas / args.rounding;
        uint256 scaledMinSuccessGas = args.maxGas.ceilDiv(args.rounding);
        uint256 scaledGasUsedInSuccess = scaledMinSuccessGas;
        uint256 scaledGuess = 0;

        PackedUserOperation memory userOp = args.userOp;
        uint256 gasUsedInSuccess = 0;

        if (!args.isContinuation) {
            // Make one call at full gas to make sure success is even possible.
            setGas(userOp, args.maxGas, args.constantFee);
            (
                bool success,
                uint256 gasUsed,
                bytes memory revertData
            ) = _innerCall(args.entryPointSimulations, userOp);
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
                args.entryPointSimulations,
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
        IEntryPointSimulations entryPointSimulations,
        PackedUserOperation memory userOp
    ) private returns (bool success, uint256 gasUsed, bytes memory revertData) {
        try this.innerCall(entryPointSimulations, userOp) {
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
        IEntryPointSimulations entryPointSimulations,
        PackedUserOperation memory userOp
    )
        external
        returns (bool success, uint256 gasUsed, bytes memory revertData)
    {
        uint256 preGas = gasleft();

        try entryPointSimulations.simulateValidation(userOp) {
            success = true;
        } catch (bytes memory data) {
            success = false;
            revertData = data;
        }

        gasUsed = preGas - gasleft();

        revert _InnerCallResult(success, gasUsed, revertData);
    }

    function _setVerificationGas(
        PackedUserOperation memory userOp,
        uint256 gas,
        uint256 constantFee
    ) internal pure {
        uint256 gasLimits = uint256(userOp.accountGasLimits);
        gasLimits =
            (gasLimits & 0xffffffffffffffffffffffffffffffff) |
            (gas << 128);
        userOp.accountGasLimits = bytes32(gasLimits);

        _setFeesFields(userOp, constantFee);
    }

    function _setPaymasterVerificationGas(
        PackedUserOperation memory userOp,
        uint256 gas,
        uint256 constantFee
    ) internal pure {
        uint128 value = uint128(gas);
        bytes memory paymasterAndData = userOp.paymasterAndData;
        uint256 offset = UserOperationLib.PAYMASTER_VALIDATION_GAS_OFFSET;
        assembly {
            let ptr := add(add(paymasterAndData, 0x20), offset)
            mstore(ptr, shl(128, value))
        }

        _setFeesFields(userOp, constantFee);
    }

    function _setFeesFields(
        PackedUserOperation memory userOp,
        uint256 constantFee
    ) internal pure {
        if (userOp.paymasterAndData.length == 0 || constantFee == 0) {
            userOp.gasFees = bytes32(uint256(0));
            return;
        }

        require(
            userOp.paymasterAndData.length >=
                UserOperationLib.PAYMASTER_DATA_OFFSET,
            "AA93 invalid paymasterAndData"
        );

        (uint256 vgl, uint256 cgl) = UserOperationLib.unpackUints(
            userOp.accountGasLimits
        );
        (, uint256 pvgl, uint256 ppogl) = _unpackPaymasterFields(
            userOp.paymasterAndData
        );

        uint256 totalGasLimit = vgl +
            cgl +
            pvgl +
            ppogl +
            userOp.preVerificationGas;
        uint256 gasFees = constantFee.ceilDiv(totalGasLimit);

        userOp.gasFees = bytes32((gasFees << 128) | gasFees);
    }

    function _unpackPaymasterFields(
        bytes memory paymasterAndData
    )
        internal
        pure
        returns (
            address paymaster,
            uint256 validationGasLimit,
            uint256 postOpGasLimit
        )
    {
        assembly {
            let ptr := add(paymasterAndData, 0x20)
            paymaster := mload(ptr)
            validationGasLimit := mload(add(ptr, 20)) // 20 bytes for address
            postOpGasLimit := mload(add(ptr, 36)) // 20 + 16 bytes
        }
        return (
            address(paymaster),
            uint128(validationGasLimit),
            uint128(postOpGasLimit)
        );
    }
}
