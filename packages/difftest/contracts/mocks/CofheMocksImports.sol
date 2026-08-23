// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.25 <0.9.0;

// Pulls every `@cofhe/mock-contracts` Solidity source into this project's
// compilation unit.
//
// `@cofhe/mock-contracts` >= 0.5 no longer ships pre-built bytecode in its JS
// artifacts (only `contractName`, `abi`, `isFixed` and `fixedAddress`), so the
// mock coprocessor must be compiled by the consuming project. Compiling it here
// also registers the artifacts with Hardhat, which is what lets Hardhat decode
// reverts and traces raised inside MockTaskManager / MockACL.
//
// `@cofhe/hardhat-plugin` does the same thing by generating this file into the
// Hardhat cache directory and injecting it via a
// TASK_COMPILE_SOLIDITY_GET_SOURCE_PATHS subtask override. We keep it as a
// checked-in source file instead: no plugin, no hidden step.

import "@cofhe/mock-contracts/contracts/ACPShareRegistry.sol";
import "@cofhe/mock-contracts/contracts/ACPTimestampRevoker.sol";
import "@cofhe/mock-contracts/contracts/MockACL.sol";
import "@cofhe/mock-contracts/contracts/MockCoFHE.sol";
import "@cofhe/mock-contracts/contracts/MockTaskManager.sol";
import "@cofhe/mock-contracts/contracts/MockThresholdNetwork.sol";
import "@cofhe/mock-contracts/contracts/MockZkVerifier.sol";
import "@cofhe/mock-contracts/contracts/Permissioned.sol";
