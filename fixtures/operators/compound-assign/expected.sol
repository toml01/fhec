// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract CompoundAssign {
    euint32 a;
    euint32 b;

    function f() public {
        a = FHE.add(a, b);
        FHE.allowThis(a);
        FHE.allowSender(a);
        a = FHE.mul(a, FHE.asEuint32(2));
        FHE.allowThis(a);
        FHE.allowSender(a);
    }
}
