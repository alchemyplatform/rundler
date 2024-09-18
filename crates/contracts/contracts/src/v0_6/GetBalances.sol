// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.12;

import "account-abstraction/v0_6/interfaces/IStakeManager.sol";

contract GetBalances {
    error GetBalancesResult(uint256[] balances);

    constructor(address stakeManager, address[] memory addresses) {
        revert GetBalancesResult(getBalancesHelper(stakeManager, addresses));
    }

    function getBalancesHelper(address stakeManager, address[] memory addresses) public view returns (uint256[] memory) {
        uint256[] memory balances = new uint256[](addresses.length);
        IStakeManager istakeManager = IStakeManager(stakeManager);

        for (uint256 i = 0; i < addresses.length; i++) {
            balances[i] = istakeManager.balanceOf(addresses[i]);
        }

        return balances;
    }
}
