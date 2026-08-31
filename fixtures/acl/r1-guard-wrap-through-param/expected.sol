// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

// Issue #103 follow-up: the `.wrap`-derived zero sentinel arrives one call
// frame away (argument → parameter → write), where the §8.1 FHE4014 static
// withhold cannot see it. The inserted grant must be guarded with
// `FHE.isInitialized` so the zero handle skips it instead of reverting with
// `SenderNotAllowed` (the MockFHESafeMath shape from the reference corpus).
contract GuardWrapThroughParam {
    euint64 spent;

    function reset() external {
        _store(euint64.wrap(bytes32(0)));
    }

    function bump(euint64 v) external {
        _store(FHE.add(spent, v));
    }

    function _store(euint64 sp) private {
        spent = sp;
        if (FHE.isInitialized(spent)) { FHE.allowThis(spent); }
    }
}
