// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract BitwiseShift {
    euint32 a;
    euint32 b;

    function f() public {
        a = FHE.and(a, b);
        FHE.allowThis(a);
        FHE.allowSender(a);
        a = FHE.or(a, b);
        FHE.allowThis(a);
        FHE.allowSender(a);
        a = FHE.xor(a, b);
        FHE.allowThis(a);
        FHE.allowSender(a);
        a = FHE.not(a);
        FHE.allowThis(a);
        FHE.allowSender(a);
        a = FHE.shl(a, FHE.asEuint32(2));
        FHE.allowThis(a);
        FHE.allowSender(a);
        a = FHE.shr(a, FHE.asEuint32(1));
        FHE.allowThis(a);
        FHE.allowSender(a);
    }
}
