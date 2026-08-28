// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

// A simple state variable has no key at all, so it has no owner distinct
// from the contract. Guessing `allowSender` there is the same confidentiality
// leak §65/FHE4001 already withholds for a non-sender-keyed mapping (issue
// #70): every caller who writes here would gain permanent read access.
contract SimpleVarKey {
    euint32 total;

    function add(euint32 amount) public {
        total = amount;
        FHE.allowThis(total);
    }
}
