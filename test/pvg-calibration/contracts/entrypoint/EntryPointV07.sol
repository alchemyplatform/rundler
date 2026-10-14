// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.23;

// EntryPoint v0.7 from rundler's account-abstraction submodule, compiled with the canonical
// deployment settings (see the `entrypoint` profile in foundry.toml). Deployed only on chains
// where the canonical EntryPoint has no code (e.g. anvil); gas-equivalent to the canonical one.
import {EntryPoint} from "@account-abstraction/core/EntryPoint.sol";
