// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";
// The solc gate is off for this case: the base comes from a package the
// fixture harness does not stage, and `couldBeInherited` deliberately exists
// only in that unreadable base.
import { ReentrancyGuardTransient } from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";

library L {
    function pub(euint64 value) internal returns (euint64 out) {
        out = value;
    }
}

contract TClean {
    function libraryCall(euint64 value) external returns (sharedEuint64) {
        return FHE.shareEuint64(L.pub(value), msg.sender);
    }
}

contract TDirty is ReentrancyGuardTransient {
    // An inherited member shadows a file-scope name, so under an unseen base
    // even a resolvable library call stays Unknown: resolving it would also
    // hand the call the §7 branch-legality permission of a builtin. The
    // shared return is still rewritten, because it takes the encrypted type
    // from the declaration and solc checks the assumption (§2.8).
    function libraryCall(euint64 value) external returns (sharedEuint64) {
        return FHE.shareEuint64(L.pub(value), msg.sender);
    }

    // This name genuinely may come from the unseen base and must stay Unknown.
    function unseenBaseCall(euint64 value) external returns (sharedEuint64) {
        return FHE.shareEuint64(couldBeInherited(value), msg.sender);
    }
}

contract HelperBase is ReentrancyGuardTransient {
    function helper(euint64 value) internal returns (euint64) {
        return value;
    }
}

contract Derived is HelperBase {
    // The helper is in the known prefix ahead of HelperBase's opaque ancestor.
    function inheritedHelper(euint64 value) external returns (sharedEuint64) {
        return FHE.shareEuint64(helper(value), msg.sender);
    }
}
