// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

// A `pure` function cannot make any call, including `FHE.allowTransient`
// (issue #91): it gets the same warn-only treatment as a `view` function
// (spec §8.3, §8.4), not a guessed grant that would not compile.
contract PureReturn {
    function p(euint64 x) public pure returns (euint64) {
        return x;
    }
}
