// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.12;

/**
 * Tells whether a call gets an EIP-8037 state-gas reservoir.
 *
 * Clients differ: in some, a call's gas above TX_MAX_GAS_LIMIT goes to the reservoir as in a
 * transaction; in others (reth v2.7), a call gets no reservoir and all state is charged to the
 * frames' gas. Called by state override, in the same `eth_simulateV1` request as reservoir-mode
 * estimation's simulations, which rely on their calls getting a reservoir.
 *
 * `probe` gives `store` less gas than one new slot's state gas. `store` writes a new slot, so it
 * only gets to its revert if the slot's state gas comes from a reservoir; otherwise it runs out of
 * gas. Either way it reverts, which rolls back its state.
 */
contract ReservoirProbe {
    /// Below the state gas of a new slot (97,920), above its execution gas.
    uint256 private constant STORE_GAS = 50_000;

    error Stored();

    uint256 private slot;

    constructor() {
        require(block.number < 100, "should not be deployed");
    }

    /// @return reservoir true if `store` was charged its state gas from a reservoir
    function probe() external returns (bool reservoir) {
        try this.store{gas: STORE_GAS}() {
            // unreachable: store always reverts
            return false;
        } catch (bytes memory reason) {
            return reason.length == 4 && bytes4(reason) == Stored.selector;
        }
    }

    function store() external {
        slot = 1;
        revert Stored();
    }
}
