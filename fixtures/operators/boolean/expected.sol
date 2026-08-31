// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract BooleanOps {
    euint32 a;
    euint32 b;
    ebool eb;

    function f() public {
        eb = FHE.and(eb, (FHE.lt(a, b)));
        if (FHE.isInitialized(eb)) { FHE.allowThis(eb); }
        eb = FHE.or(eb, eb);
        if (FHE.isInitialized(eb)) { FHE.allowThis(eb); }
        eb = FHE.not(eb);
        if (FHE.isInitialized(eb)) { FHE.allowThis(eb); }
    }
}
