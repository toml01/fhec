// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

/**
 * Hand-written reference for `contracts-dialect/EncryptedCounterDialect.fsol`.
 *
 * Written independently from spec §5 (both branches execute; the guarded write
 * merges through `FHE.select`) and §8 (allowThis + allowSender after every
 * encrypted storage write) — NOT copied from fhec output. This is the oracle
 * the transpiled contract must be differentially equivalent to.
 */
contract EncryptedCounterDialectRef {
    address public owner;

    euint32 public count;
    euint32 private cap;

    error OnlyOwnerAllowed(address caller);

    modifier onlyOwner() {
        if (msg.sender != owner) revert OnlyOwnerAllowed(msg.sender);
        _;
    }

    constructor(uint32 initialValue, uint32 capValue) {
        owner = msg.sender;
        count = FHE.asEuint32(initialValue);
        FHE.allowThis(count);
        FHE.allowSender(count);
        cap = FHE.asEuint32(capValue);
        FHE.allowThis(cap);
        FHE.allowSender(cap);
    }

    function getCount() external view returns (euint32) {
        return count;
    }

    function increment(InEuint32 memory amountInput) external onlyOwner {
        euint32 amount = FHE.asEuint32(amountInput);
        euint32 next = FHE.add(count, amount);
        ebool withinCap = FHE.lte(next, cap);
        count = FHE.select(withinCap, next, count);
        FHE.allowThis(count);
        FHE.allowSender(count);
    }

    function incrementByOne() external onlyOwner {
        count = FHE.add(count, FHE.asEuint32(1));
        FHE.allowThis(count);
        FHE.allowSender(count);
    }
}
