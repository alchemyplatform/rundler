// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

// Simply importing a dependency is enough for Forge to include it in builds.

import "account-abstraction/v0_7/interfaces/IEntryPoint.sol";
import "account-abstraction/v0_7/interfaces/IAccount.sol";
import "account-abstraction/v0_7/interfaces/IPaymaster.sol";
import "account-abstraction/v0_7/interfaces/IAggregator.sol";
import "account-abstraction/v0_7/interfaces/IStakeManager.sol";
import "account-abstraction/v0_7/core/EntryPointSimulations.sol";
import "account-abstraction/v0_7/core/SenderCreator.sol";
