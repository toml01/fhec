// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract CoerceWiden {
    euint32 a;
    euint8 a8;

    function f() public {
        a = FHE.add(FHE.asEuint32(a8), a);
        FHE.allowThis(a);
        FHE.allowSender(a);
    }
}
