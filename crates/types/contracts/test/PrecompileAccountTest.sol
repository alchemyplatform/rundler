// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.14;

import "../src/v0_6/PrecompileAccount.sol";
import "account-abstraction/v0_6/interfaces/UserOperation.sol";
import "forge-std/Test.sol";

contract PrecompileAccountTest is Test {
    PrecompileAccount public account;

    function setUp() public {
        account = new PrecompileAccount(
            0x000000000000000000000000000000000000006D
        );
    }

    function testValidateUserOp() public view {
        UserOperation memory userOp = UserOperation(
            address(0),
            0,
            "",
            "",
            0,
            0,
            0,
            0,
            0,
            "",
            ""
        );
        account.validateUserOp(userOp, 0, 0);
    }
}
