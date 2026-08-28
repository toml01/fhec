// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract CoercePlain {
    euint32 a;

    function f(uint32 p) public {
        a = FHE.add(a, FHE.asEuint32(p));
        FHE.allowThis(a);
    }
}
