// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.13;

// From eth-infinitism/bundler. A helper contract for hashing together the code
// hashes of multiple contracts at once.
//
// Not intended to be deployed on-chain.. Instead use state overrides to deploy the bytecode and call it.

contract GetCodeHashes {
    /**
     * Contract should not be deployed
     */
    constructor() {
        require(block.number < 100, "should not be deployed");
    }

    function getCodeHashes(
        address[] memory addresses
    ) public view returns (bytes32 hash) {
        bytes32[] memory hashes = new bytes32[](addresses.length);
        for (uint i = 0; i < addresses.length; i++) {
            hashes[i] = addresses[i].codehash;
        }
        bytes memory data = abi.encode(hashes);
        return keccak256(data);
    }
}
