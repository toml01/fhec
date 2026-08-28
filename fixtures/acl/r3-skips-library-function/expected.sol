// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

// A library's public/external members are delegatecall-linked: msg.sender
// and storage are the host's, so R3 must not fire here (issue #88). The
// internal member never states an R3 fact in the first place (it is
// inlined). The host contract's own shared(msg.sender) return is a normal
// contract R3 site and keeps its grant.
library ReturnLib {
    function doubled(euint64 x) public returns (euint64) {
        return FHE.add(x, x);
    }

    function doubledInternal(euint64 x) internal returns (euint64) {
        return FHE.add(x, x);
    }
}

contract LibraryReturn {
    euint64 balance;

    function run() external returns (sharedEuint64) {
        return FHE.shareEuint64(ReturnLib.doubled(balance), msg.sender);
    }
}
