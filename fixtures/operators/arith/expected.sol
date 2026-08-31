// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract Arith {
    euint32 a;
    euint32 b;

    function f() public {
        a = FHE.add(a, b);
        if (FHE.isInitialized(a)) { FHE.allowThis(a); }
        a = FHE.sub(a, b);
        if (FHE.isInitialized(a)) { FHE.allowThis(a); }
        a = FHE.mul(a, b);
        if (FHE.isInitialized(a)) { FHE.allowThis(a); }
        a = FHE.div(a, b);
        if (FHE.isInitialized(a)) { FHE.allowThis(a); }
        a = FHE.rem(a, b);
        if (FHE.isInitialized(a)) { FHE.allowThis(a); }
    }
}
