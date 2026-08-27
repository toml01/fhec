// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

// Ordinary operator lowering still runs inside a shared return's expression:
// the share call brackets the expression rather than replacing it, so nested
// operators lower normally and exactly one share call is emitted (§2.8).
contract SharedReturnNestedOps {
    euint64 a;
    euint64 b;
    euint64 c;
    ebool flag;

    function total() public returns (sharedEuint64) {
        return FHE.shareEuint64(FHE.add(a, FHE.mul(b, c)), msg.sender);
    }

    function pick() public returns (sharedEuint64) {
        return FHE.shareEuint64(FHE.select(flag, FHE.add(a, b), c), msg.sender);
    }
}
