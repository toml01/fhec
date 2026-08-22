// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract Dedupe {
    euint32 a;
    euint32 b;

    function f() public {
        a = FHE.add(a, b);
        FHE.allowThis(a);
        FHE.allowSender(a);
    }
}
