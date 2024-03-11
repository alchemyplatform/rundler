// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.13;

import "account-abstraction/v0_6/interfaces/IAccount.sol";

contract PrecompileAccount is IAccount {
    address public precompile;

    constructor(address _precompile) {
        precompile = _precompile;
    }

    function validateUserOp(
        UserOperation calldata,
        bytes32,
        uint256
    ) external view override returns (uint256) {
        assembly {
            let addr := sload(precompile.slot)
            let r := staticcall(10000, addr, 0, 0, 0, 0)
        }
        return 0;
    }

    function execute(
        address dest,
        uint256 value,
        bytes calldata func
    ) external {
        (bool success, bytes memory result) = dest.call{value: value}(func);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }

    function getNonce() public view virtual returns (uint256) {
        return 0;
    }
}
