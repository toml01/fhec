// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

// Single evaluation holds by construction: the share call wraps the returned
// expression where it stands instead of hoisting and re-reading it, so a
// side-effecting expression runs exactly once (§2.8). `reads` would end at 2
// if the lowering ever duplicated the expression.
contract SharedReturnSingleEval {
    mapping(address => euint64) balances;
    uint256 public reads;

    function fetch(address who) internal returns (euint64 out) {
        reads += 1;
        out = balances[who];
    }

    function take() public returns (sharedEuint64) {
        return FHE.shareEuint64(fetch(msg.sender), msg.sender);
    }
}
