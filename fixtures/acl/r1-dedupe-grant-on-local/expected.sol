// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

// Compute into a local, grant on the local, then store: the handle the store
// files is the one already granted, so §8.6 suppresses the insertion.
contract GrantOnLocal {
    euint32 total;
    mapping(address => euint32) bal;

    function idiomatic(euint32 amount) public {
        euint32 ptr = amount;
        FHE.allowThis(ptr);
        FHE.allowSender(ptr);
        total = ptr;
    }

    // Reassigned in between: the earlier grant is on a different handle.
    function reassigned(euint32 amount, euint32 other) public {
        euint32 ptr = amount;
        FHE.allowThis(ptr);
        ptr = other;
        total = ptr;
        if (FHE.isInitialized(total)) { FHE.allowThis(total); }
    }

    // Only one of the two grants is present.
    function onlyOne(euint32 amount) public {
        euint32 ptr = amount;
        FHE.allowThis(ptr);
        bal[msg.sender] = ptr;
        if (FHE.isInitialized(bal[msg.sender])) { FHE.allowSender(bal[msg.sender]); }
    }
}
