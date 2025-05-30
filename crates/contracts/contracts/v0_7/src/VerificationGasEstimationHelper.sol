// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "@openzeppelin/contracts/utils/math/Math.sol";
import "@account-abstraction/interfaces/PackedUserOperation.sol";
import "@account-abstraction/interfaces/IEntryPointSimulations.sol";
import "@account-abstraction/core/UserOperationLib.sol";

import "common/interfaces/EstimationTypes.sol";
import "common/libraries/BinarySearchLib.sol";

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
        uint256 allowedErrorPct;
        bool isContinuation;
        uint256 constantFee;
    }

    struct BinarySearchContext {
        IEntryPointSimulations entryPointSimulations;
        PackedUserOperation userOp;
        uint256 constantFee;
        bytes4 setGasSelector;
    }

    function estimateVerificationGas(EstimateGasArgs calldata args) external {
        _estimateGas(args, this._setVerificationGas.selector);
    }

    function estimatePaymasterVerificationGas(
        EstimateGasArgs calldata args
    ) external {
        _estimateGas(args, this._setPaymasterVerificationGas.selector);
    }

    function _estimateGas(
        EstimateGasArgs calldata args,
        bytes4 setGasSelector
    ) private {
        PackedUserOperation memory userOp = args.userOp;
        uint256 initialGuess = 0;

        bytes memory context = abi.encode(
            BinarySearchContext({
                entryPointSimulations: args.entryPointSimulations,
                userOp: userOp,
                constantFee: args.constantFee,
                setGasSelector: setGasSelector
            })
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

    function innerCall(uint256 guess, bytes memory context) external {
        BinarySearchContext memory ctx = abi.decode(
            context,
            (BinarySearchContext)
        );

        if (ctx.setGasSelector == this._setVerificationGas.selector) {
            _setVerificationGas(ctx.userOp, guess, ctx.constantFee);
        } else if (
            ctx.setGasSelector == this._setPaymasterVerificationGas.selector
        ) {
            _setPaymasterVerificationGas(ctx.userOp, guess, ctx.constantFee);
        } else {
            revert("Invalid setGasSelector");
        }

        bool success;
        bytes memory revertData;

        uint256 preGas = gasleft();
        try ctx.entryPointSimulations.simulateValidation(ctx.userOp) {
            success = true;
        } catch (bytes memory data) {
            success = false;
            revertData = data;
        }
        uint256 gasUsed = preGas - gasleft();

        revert BinarySearchLib.InnerCallResult(success, gasUsed, revertData);
    }

    function _setVerificationGas(
        PackedUserOperation memory userOp,
        uint256 gas,
        uint256 constantFee
    ) public pure {
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
    ) public pure {
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
