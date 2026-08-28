// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract IncDec {
    euint32 a;

    function f() public {
        a = FHE.add(a, FHE.asEuint32(1));
        FHE.allowThis(a);
        a = FHE.sub(a, FHE.asEuint32(1));
        FHE.allowThis(a);
    }
}
