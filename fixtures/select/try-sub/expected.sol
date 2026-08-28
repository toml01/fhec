// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

contract TrySub {
    function trySub(euint64 a, euint64 b) internal returns (ebool success, euint64 res) {
        if (!FHE.isInitialized(b)) return (FHE.asEbool(true), a);
        euint64 difference = FHE.sub(a, b);
        success = FHE.lte(difference, a);

        res = FHE.select(success, difference, FHE.asEuint64(0));
    }
}
