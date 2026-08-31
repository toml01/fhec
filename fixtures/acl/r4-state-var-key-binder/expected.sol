// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

// A reader policy on a mapping state variable (spec §8.8-§8.9): R4 replaces
// R1's ownership decision entirely, granting the named key binder instead
// of guessing `msg.sender` — no FHE4001 withheld-sender-grant warning here.
contract PolicyOnMapping {
    /// @custom:fhe-allow balances: account
    mapping(address account => euint32) balances;

    function set(address to, euint32 v) public {
        balances[to] = v;
        FHE.allowThis(balances[to]);
        if (to != address(0)) FHE.allow(balances[to], to);
    }
}
