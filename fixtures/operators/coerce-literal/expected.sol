// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract CoerceLiteral {
    euint8 a8;

    function f() public {
        a8 = FHE.add(a8, FHE.asEuint8(250));
        if (FHE.isInitialized(a8)) { FHE.allowThis(a8); }
    }
}
