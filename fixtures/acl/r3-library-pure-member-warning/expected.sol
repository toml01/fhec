// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

// A library's `pure` member is directly, independently callable, like a
// `view` member (issue #91): the `view`/`pure` exception (FHE4002) is
// checked before the `in_library` skip, mirroring #88/#89's `view` fix.
library L {
    function peek(euint32 a) public pure returns (euint32) {
        return a;
    }
}
