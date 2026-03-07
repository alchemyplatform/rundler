// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {PackedUserOperation} from "@account-abstraction/interfaces/PackedUserOperation.sol";
import {UserOperationLib} from "@account-abstraction/core/UserOperationLib.sol";

import {VerificationGasEstimationHelper} from "../src/VerificationGasEstimationHelper.sol";

/// @dev Wrapper that exposes the result of _setPaymasterVerificationGas so tests
///      can observe the modified paymasterAndData (memory structs are passed by
///      value across external calls, so changes must be returned explicitly).
contract TestableHelper is VerificationGasEstimationHelper {
    function setPaymasterVerificationGasAndReturn(
        PackedUserOperation memory userOp,
        uint256 gas,
        uint256 constantFee
    ) external pure returns (bytes memory) {
        _setPaymasterVerificationGas(userOp, gas, constantFee);
        return userOp.paymasterAndData;
    }
}

contract VerificationGasEstimationHelperTest is Test {
    TestableHelper helper;

    function setUp() public {
        // Block number must be < 100 to satisfy the constructor guard
        vm.roll(0);
        helper = new TestableHelper();
    }

    // Build paymasterAndData per ERC-4337 v0.7 layout:
    //   bytes 0-19:  paymaster address
    //   bytes 20-35: paymasterVerificationGasLimit (uint128)
    //   bytes 36-51: paymasterPostOpGasLimit (uint128)
    function _makeUserOp(
        address paymaster,
        uint128 verificationGasLimit,
        uint128 postOpGasLimit
    ) internal pure returns (PackedUserOperation memory op) {
        op.paymasterAndData = abi.encodePacked(paymaster, verificationGasLimit, postOpGasLimit);
    }

    function _unpackVerificationGasLimit(bytes memory data) internal pure returns (uint128) {
        uint256 offset = UserOperationLib.PAYMASTER_VALIDATION_GAS_OFFSET; // 20
        uint128 result;
        assembly { result := shr(128, mload(add(add(data, 0x20), offset))) }
        return result;
    }

    function _unpackPostOpGasLimit(bytes memory data) internal pure returns (uint128) {
        uint256 offset = UserOperationLib.PAYMASTER_VALIDATION_GAS_OFFSET + 16; // 36
        uint128 result;
        assembly { result := shr(128, mload(add(add(data, 0x20), offset))) }
        return result;
    }

    /// @notice _setPaymasterVerificationGas must update paymasterVerificationGasLimit
    ///         while leaving paymasterPostOpGasLimit untouched.
    ///         Regression test for issue #1213 (introduced in v0.9.0): mstore wrote
    ///         32 bytes, zeroing the adjacent postOpGasLimit field.
    function test_setPaymasterVerificationGas_preservesPostOpGasLimit() public {
        uint128 originalPostOpGasLimit  = 50_000;
        uint128 newVerificationGasLimit = 200_000;

        PackedUserOperation memory op = _makeUserOp(address(0xdead), 100_000, originalPostOpGasLimit);

        bytes memory result = helper.setPaymasterVerificationGasAndReturn(op, newVerificationGasLimit, 0);

        assertEq(_unpackVerificationGasLimit(result), newVerificationGasLimit, "verificationGasLimit not updated");
        assertEq(_unpackPostOpGasLimit(result), originalPostOpGasLimit, "postOpGasLimit must not be zeroed");
    }

    /// @notice Fuzz: postOpGasLimit must always be preserved regardless of inputs.
    function testFuzz_setPaymasterVerificationGas_preservesPostOpGasLimit(
        uint128 originalVerificationGas,
        uint128 postOpGasLimit,
        uint128 newVerificationGas
    ) public {
        PackedUserOperation memory op = _makeUserOp(address(0xdead), originalVerificationGas, postOpGasLimit);

        bytes memory result = helper.setPaymasterVerificationGasAndReturn(op, newVerificationGas, 0);

        assertEq(_unpackVerificationGasLimit(result), newVerificationGas, "verificationGasLimit not updated");
        assertEq(_unpackPostOpGasLimit(result), postOpGasLimit, "postOpGasLimit must not be zeroed");
    }
}
