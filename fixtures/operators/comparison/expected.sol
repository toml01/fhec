// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract Comparison {
    euint32 a;
    euint32 b;
    ebool eb;

    function f() public {
        eb = FHE.lt(a, b);
        FHE.allowThis(eb);
        FHE.allowSender(eb);
        eb = FHE.gte(a, b);
        FHE.allowThis(eb);
        FHE.allowSender(eb);
        eb = FHE.eq(a, b);
        FHE.allowThis(eb);
        FHE.allowSender(eb);
        eb = FHE.ne(a, b);
        FHE.allowThis(eb);
        FHE.allowSender(eb);
    }
}
