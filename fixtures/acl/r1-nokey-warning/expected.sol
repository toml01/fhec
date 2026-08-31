// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

// An array element and a struct field carry no address key either, so R1
// cannot prove either write's owner is `msg.sender` (issue #70, same gap as
// a simple state variable and a non-sender-keyed mapping).
contract NoKeyWrites {
    struct Account {
        euint32 balance;
    }

    euint32[] amounts;
    Account acct;

    function setIndex(uint256 i, euint32 v) public {
        amounts[i] = v;
        if (FHE.isInitialized(amounts[i])) { FHE.allowThis(amounts[i]); }
    }

    function setField(euint32 v) public {
        acct.balance = v;
        if (FHE.isInitialized(acct.balance)) { FHE.allowThis(acct.balance); }
    }
}
