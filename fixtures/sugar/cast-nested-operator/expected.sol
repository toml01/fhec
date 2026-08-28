// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract CastNestedOperator {
    euint32 total;

    function addFive(euint32 a) public {
        total = FHE.add(a, FHE.asEuint32(5));
        FHE.allowThis(total);
        FHE.allowSender(total);
    }
}
