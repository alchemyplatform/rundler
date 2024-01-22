// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.12;

import "account-abstraction/interfaces/IStakeManager.sol";

contract IPaymasterHelper {
    IStakeManager public stakeManager;

    constructor(address _stakeManagerAddress) {
        stakeManager = IStakeManager(_stakeManagerAddress);
    }

    function getBalances(address[] calldata addresses) external view returns (uint256[] memory) {
        uint256[] memory balances = new uint256[](addresses.length);

        for (uint256 i = 0; i < addresses.length; i++) {
            balances[i] = stakeManager.balanceOf(addresses[i]);
        }

        return balances;
    }

    function getDepositInfo(address account) external view returns (IStakeManager.DepositInfo memory info) {
        return stakeManager.getDepositInfo(account);
    }
}
