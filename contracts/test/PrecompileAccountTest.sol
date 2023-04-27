// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.14;

import "forge-std/Test.sol";
import "../src/PrecompileAccount.sol";
import "@account-abstraction/interfaces/UserOperation.sol";

contract PrecompileAccountTest is Test {
    PrecompileAccount public account;

    function setUp() public {
        account = new PrecompileAccount(0x000000000000000000000000000000000000006D);
    }

    function testValidateUserOp() view public {
        UserOperation memory userOp = UserOperation(address(0), 0, "", "", 0, 0, 0, 0, 0, "", "");
        account.validateUserOp(userOp, 0, 0);
    }
}
