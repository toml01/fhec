// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract CastArgNestedOp {
    euint8 x;
    euint8 y;
    ebool flag;

    function check() public {
        flag = FHE.asEbool(FHE.add(x, y));
        FHE.allowThis(flag);
    }
}
