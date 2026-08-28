// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract CastNestedCondition {
    ebool cond;
    euint32 total;

    function pick() public {
        total = FHE.select(cond, FHE.asEuint32(1), FHE.asEuint32(2));
        FHE.allowThis(total);
    }
}
