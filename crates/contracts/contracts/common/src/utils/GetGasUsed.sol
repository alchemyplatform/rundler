// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

// Not intended to be deployed on-chain.. Instead use state overrides to deploy the bytecode and call it.

contract GetGasUsed {
    struct GasUsedResult {
        uint256 gasUsed; 
        bool success; 
        bytes result;
    }

    /**
     * Contract should not be deployed
     */
    constructor() {
        require(block.number < 100, "should not be deployed");
    }

    function getGas(
        address target, 
        uint256 value, 
        bytes memory data
    ) public returns (GasUsedResult memory) {
        uint256 preGas = gasleft();
        (bool success, bytes memory result) = target.call{value : value}(data);
        return GasUsedResult({
            gasUsed: preGas - gasleft(),
            success: success,
            result: result
        });
    }
}
