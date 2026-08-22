// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract BooleanOps {
    euint32 a;
    euint32 b;
    ebool eb;

    function f() public {
        eb = FHE.and(eb, (FHE.lt(a, b)));
        FHE.allowThis(eb);
        FHE.allowSender(eb);
        eb = FHE.or(eb, eb);
        FHE.allowThis(eb);
        FHE.allowSender(eb);
        eb = FHE.not(eb);
        FHE.allowThis(eb);
        FHE.allowSender(eb);
    }
}
