// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

// Not intended to be deployed on-chain.. Instead, using a call to simulate
// deployment will revert with an error containing the desired result.

contract GetGasUsed {
    error GasUsedResult(uint256 gasUsed, bool success, bytes result);

    constructor(address target, uint256 value, bytes memory data) {
        (uint256 gasUsed, bool success, bytes memory result) = getGas(target, value, data);
        revert GasUsedResult(gasUsed, success, result);
    }

    function getGas(
        address target, 
        uint256 value, 
        bytes memory data
    ) public returns (uint256, bool, bytes memory) {
        uint256 preGas = gasleft();
        (bool success, bytes memory result) = target.call{value : value}(data);
        return (preGas - gasleft(), success, result);
    }
}
