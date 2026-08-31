// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

// A mapping keyed by something other than an address is not provably
// `msg.sender`-owned either: R1's "unproven" case is not limited to a
// proven-other address (issue #70).
contract NonAddressKey {
    mapping(uint256 => euint32) accounts;

    function set(uint256 id, euint32 v) public {
        accounts[id] = v;
        if (FHE.isInitialized(accounts[id])) { FHE.allowThis(accounts[id]); }
    }
}
