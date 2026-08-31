// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract BitwiseShift {
    euint32 a;
    euint32 b;

    function f() public {
        a = FHE.and(a, b);
        if (FHE.isInitialized(a)) { FHE.allowThis(a); }
        a = FHE.or(a, b);
        if (FHE.isInitialized(a)) { FHE.allowThis(a); }
        a = FHE.xor(a, b);
        if (FHE.isInitialized(a)) { FHE.allowThis(a); }
        a = FHE.not(a);
        if (FHE.isInitialized(a)) { FHE.allowThis(a); }
        a = FHE.shl(a, FHE.asEuint32(2));
        if (FHE.isInitialized(a)) { FHE.allowThis(a); }
        a = FHE.shr(a, FHE.asEuint32(1));
        if (FHE.isInitialized(a)) { FHE.allowThis(a); }
    }
}
