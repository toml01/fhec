// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract Ternary {
    euint32 a;
    euint32 b;
    ebool eb;

    function f() public {
        a = FHE.select(eb, a, b);
        if (FHE.isInitialized(a)) { FHE.allowThis(a); }
    }
}
